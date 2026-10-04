//! Content-addressed hashing for directives (§3.3.1, §3.3.2).
//!
//! Identity v1: `txid = SHA-256(economic_canonical_serialize(transaction))`,
//! `directiveId` likewise for any other directive.
//!
//! Identity v2 (Format v2, Facet A — M-10): a record whose envelope carries
//! `openledger-format: "2"` is identified by its author as well as its body,
//! `SHA-256("olid-v2" ‖ LP(author) ‖ LP(economic body))`, where `LP(x)` is the
//! 8-byte big-endian length of `x` followed by `x`. Another author's copy of the
//! same body is then another record, so a peer that publishes your body first
//! no longer owns its id. The marker sits outside the hash, but a signature
//! covers the resulting id, so flipping it on a signed record fails
//! verification. A record without the marker is v1 forever.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::model::Directive;
use crate::serialize::economic_canonical_serialize;

/// The envelope key that marks a record as Format v2: identity v2 and
/// signature v4 (`openledger-format`).
pub const FORMAT_KEY: &str = "openledger-format";

/// The one value [`FORMAT_KEY`] may carry.
pub const FORMAT_V2: &str = "2";

/// The envelope key naming a record's author (`openledger-author`).
const AUTHOR_KEY: &str = "openledger-author";

/// Domain string the v2 id preimage opens with: no v2 id is a v1 hash of
/// anything.
const ID_V2_DOMAIN: &[u8] = b"olid-v2";

/// Which identity (and signature) format a record is in (Format v2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordFormat {
    /// Body-only id, signature v3 — every record without the marker.
    V1,
    /// Author-in-the-id, signature v4 — `openledger-format: "2"`.
    V2,
}

impl RecordFormat {
    /// The format an envelope (or a directive's metadata) declares.
    pub fn of_envelope(envelope: &BTreeMap<String, String>) -> Self {
        if envelope.get(FORMAT_KEY).map(String::as_str) == Some(FORMAT_V2) {
            RecordFormat::V2
        } else {
            RecordFormat::V1
        }
    }

    /// The format `directive` is in.
    pub fn of(directive: &Directive) -> Self {
        Self::of_envelope(directive.metadata())
    }
}

/// Compute the content ID for any directive.
///
/// For transactions this is the `txid`; for non-transaction directives
/// it is the `directiveId`. Both are 64-character lowercase hex SHA-256 strings.
/// The identity format is the one the directive's own envelope declares.
pub fn compute_content_id(directive: &Directive) -> String {
    compute_content_id_with_envelope(directive, directive.metadata())
}

/// [`compute_content_id`] for a body whose envelope is held apart from it —
/// the wire's case, where a supply entry's id is checked before its envelope
/// is merged into the parsed body.
pub fn compute_content_id_with_envelope(
    directive: &Directive,
    envelope: &BTreeMap<String, String>,
) -> String {
    let canonical = economic_canonical_serialize(directive);
    let hash = match RecordFormat::of_envelope(envelope) {
        RecordFormat::V1 => Sha256::digest(canonical.as_bytes()),
        RecordFormat::V2 => {
            let author = envelope.get(AUTHOR_KEY).map(String::as_str).unwrap_or("");
            let mut hasher = Sha256::new();
            hasher.update(ID_V2_DOMAIN);
            for field in [author.as_bytes(), canonical.as_bytes()] {
                hasher.update((field.len() as u64).to_be_bytes());
                hasher.update(field);
            }
            hasher.finalize()
        }
    };
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use chrono::NaiveDate;
    use rust_decimal_macros::dec;
    use std::collections::BTreeMap;

    fn make_date(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).unwrap()
    }

    /// CT-3: Worked `txid` fixture from §3.3.3 (normative).
    #[test]
    fn test_ct3_worked_fixture_txid() {
        let txn = Transaction {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: Some("Acme Corp".to_owned()),
            narration: Some("Initial funding".to_owned()),
            tags: Vec::new(),
            links: Vec::new(),
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(1000.00),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening-Balances".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-1000.00),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        };

        let txid = compute_content_id(&Directive::Transaction(txn));
        assert_eq!(
            txid, "dd4a9ec5ec298be6edaa02c4408c0b1cb1b25eb51426599b7eda600cfc5fa88f",
            "CT-3: worked fixture txid must match §3.3.3"
        );
    }

    /// CT-3 extended: envelope metadata must not affect txid.
    #[test]
    fn test_ct3_envelope_does_not_change_txid() {
        let make_txn = |has_envelope: bool| -> Transaction {
            let mut metadata = BTreeMap::new();
            if has_envelope {
                metadata.insert("openledger-author".to_owned(), "peer-42".to_owned());
                metadata.insert("openledger-lamport".to_owned(), "99".to_owned());
                metadata.insert("openledger-parents".to_owned(), "".to_owned());
            }
            Transaction {
                date: make_date(2024, 1, 15),
                flag: Flag::Complete,
                payee: Some("Acme Corp".to_owned()),
                narration: Some("Initial funding".to_owned()),
                tags: Vec::new(),
                links: Vec::new(),
                postings: vec![
                    Posting {
                        account: "Assets:Cash".to_owned(),
                        amount: Some(Amount {
                            number: dec!(1000.00),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                        metadata: BTreeMap::new(),
                    },
                    Posting {
                        account: "Equity:Opening-Balances".to_owned(),
                        amount: Some(Amount {
                            number: dec!(-1000.00),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                        metadata: BTreeMap::new(),
                    },
                ],
                metadata,
            }
        };

        let txid_bare = compute_content_id(&Directive::Transaction(make_txn(false)));
        let txid_envelope = compute_content_id(&Directive::Transaction(make_txn(true)));

        assert_eq!(
            txid_bare, txid_envelope,
            "envelope metadata must not change txid"
        );
        assert_eq!(
            txid_bare,
            "dd4a9ec5ec298be6edaa02c4408c0b1cb1b25eb51426599b7eda600cfc5fa88f"
        );
    }

    #[test]
    fn test_content_id_is_64_char_hex() {
        let open = Open {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            currencies: vec!["USD".to_owned()],
            metadata: BTreeMap::new(),
        };
        let id = compute_content_id(&Directive::Open(open));
        assert_eq!(id.len(), 64, "content ID must be 64 hex characters");
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            "content ID must be lowercase hex"
        );
    }

    #[test]
    fn test_different_directives_different_ids() {
        let open_a = Directive::Open(Open {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            currencies: vec!["USD".to_owned()],
            metadata: BTreeMap::new(),
        });
        let open_b = Directive::Open(Open {
            date: make_date(2024, 1, 1),
            account: "Assets:Bank".to_owned(),
            currencies: vec!["USD".to_owned()],
            metadata: BTreeMap::new(),
        });
        assert_ne!(
            compute_content_id(&open_a),
            compute_content_id(&open_b),
            "different economic bodies must produce different content IDs"
        );
    }

    #[test]
    fn test_content_id_stable_across_calls() {
        let open = Open {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            currencies: Vec::new(),
            metadata: BTreeMap::new(),
        };
        let id1 = compute_content_id(&Directive::Open(open.clone()));
        let id2 = compute_content_id(&Directive::Open(open));
        assert_eq!(id1, id2, "content ID must be deterministic");
    }

    // ── Identity v2 (Format v2, Facet A) ─────────────────────────────────

    fn open_by(author: Option<&str>, format: Option<&str>) -> Directive {
        let mut metadata = BTreeMap::new();
        if let Some(author) = author {
            metadata.insert("openledger-author".to_owned(), author.to_owned());
        }
        if let Some(format) = format {
            metadata.insert(FORMAT_KEY.to_owned(), format.to_owned());
        }
        metadata.insert("openledger-lamport".to_owned(), "7".to_owned());
        Directive::Open(Open {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            currencies: vec!["USD".to_owned()],
            metadata,
        })
    }

    /// Identity v1 is unchanged for every record without the marker — the
    /// envelope (author included) stays outside the id — while a v2 record's
    /// id is the length-prefixed hash of its author and body: two authors'
    /// copies of one body are two ids, and neither is the v1 id. Pinned
    /// against the preimage built by hand.
    #[test]
    fn identity_v2_binds_the_author_and_v1_does_not() {
        let v1_a = compute_content_id(&open_by(Some("aa"), None));
        let v1_b = compute_content_id(&open_by(Some("bb"), None));
        assert_eq!(v1_a, v1_b, "v1: the author is envelope, outside the id");
        assert_eq!(
            v1_a,
            compute_content_id(&open_by(None, Some("3"))),
            "only \"2\" is v2"
        );
        let v2_a = compute_content_id(&open_by(Some("aa"), Some(FORMAT_V2)));
        let v2_b = compute_content_id(&open_by(Some("bb"), Some(FORMAT_V2)));
        assert_ne!(v2_a, v2_b, "v2: another author's copy is another record");
        assert_ne!(v2_a, v1_a);
        let body = economic_canonical_serialize(&open_by(None, None));
        let mut preimage = b"olid-v2".to_vec();
        preimage.extend_from_slice(&2u64.to_be_bytes());
        preimage.extend_from_slice(b"aa");
        preimage.extend_from_slice(&(body.len() as u64).to_be_bytes());
        preimage.extend_from_slice(body.as_bytes());
        let expected: String = Sha256::digest(&preimage)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(v2_a, expected);
        assert_eq!(
            RecordFormat::of(&open_by(Some("aa"), Some(FORMAT_V2))),
            RecordFormat::V2
        );
        assert_eq!(
            RecordFormat::of(&open_by(Some("aa"), Some("3"))),
            RecordFormat::V1
        );
    }

    /// The length prefixes make the preimage injective: moving bytes between
    /// the author and the body changes the id (with a `|` separator, an author
    /// ending in the body's first bytes could collide).
    #[test]
    fn identity_v2_is_injective_across_the_author_boundary() {
        let body = Directive::Open(Open {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            currencies: Vec::new(),
            metadata: BTreeMap::new(),
        });
        let with = |author: &str| {
            let envelope = BTreeMap::from([
                ("openledger-author".to_owned(), author.to_owned()),
                (FORMAT_KEY.to_owned(), FORMAT_V2.to_owned()),
            ]);
            compute_content_id_with_envelope(&body, &envelope)
        };
        let canonical = economic_canonical_serialize(&body);
        let first = &canonical[..4];
        assert_ne!(with("ab"), with(&format!("ab{first}")));
        assert_ne!(with(""), with("a"));
        assert_eq!(
            with("ab"),
            compute_content_id(&{
                let Directive::Open(mut open) = body.clone() else {
                    unreachable!()
                };
                open.metadata
                    .insert("openledger-author".to_owned(), "ab".to_owned());
                open.metadata
                    .insert(FORMAT_KEY.to_owned(), FORMAT_V2.to_owned());
                Directive::Open(open)
            })
        );
    }
}
