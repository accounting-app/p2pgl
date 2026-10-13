//! The access list: who may use this node's API, and with which role
//! (`docs/build-log/002-users-and-roles`).
//!
//! It is folded from the ledger's access records ([`ledger::access_record`]) —
//! `event "openledger-access"` records that replicate like every other — in the
//! order every node computes the same way: lamport, then content id. A `grant`
//! sets a person's name, role, key hash and expiry (a later grant replaces
//! their key: rotation); a `rename` changes the name and nothing else; a
//! `revoke` ends them **for good** — a grant of that user id anywhere in the
//! order, before or after, counts for nothing once it is revoked, so a key
//! rotated on one node while another revoked the person never brings them
//! back (step 3 review). Every node folds the same records in the same order,
//! so every node of the mesh reaches the same list, and a concurrent grant and
//! revoke resolve the same way everywhere: the revoke wins.
//!
//! The DAG keeps an index of access records and bumps a generation when one
//! arrives, so the fold runs only when the records change
//! (`crate::auth::AccessSource`). A record that is malformed, or written by a
//! node outside `auth.adminNodes`, is skipped.

use std::collections::{BTreeMap, HashSet};

use chrono::NaiveDate;
use ledger::model::Directive;
use sha2::{Digest, Sha256};

use crate::access_control::{Caller, CallerId, Role};

/// One person's current access.
#[derive(Clone, PartialEq, Eq)]
pub struct AccessEntry {
    /// The person's name, as the admin typed it (decision 2, revised
    /// 2026-10-12: names live in the access records).
    pub name: String,
    pub role: Role,
    /// SHA-256 of the person's key, lowercase hex.
    pub key_sha256: String,
    /// The last day the key is accepted, if it expires.
    pub expires: Option<NaiveDate>,
}

/// Hand-written so the key hash never reaches `Debug` output (the intent: no
/// key, and no hash of one, in a log or `Debug`).
impl std::fmt::Debug for AccessEntry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AccessEntry")
            .field("name", &self.name)
            .field("role", &self.role)
            .field("key_sha256", &"<redacted>")
            .field("expires", &self.expires)
            .finish()
    }
}

/// The folded access list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccessList {
    /// By user id (`u_` and 16 hex digits).
    pub users: BTreeMap<String, AccessEntry>,
    /// Every person's name, by user id — set by each grant, changed by a
    /// rename of someone already granted earlier in the order, and kept after
    /// a revoke, so the journal can still say who entered a record (step 4).
    /// A rename of an id no grant came before names no one.
    pub names: BTreeMap<String, String>,
}

/// What one access record says, once parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Change {
    Grant { user: String, entry: AccessEntry },
    Rename { user: String, name: String },
    Revoke { user: String },
}

impl AccessList {
    /// Fold `records` (content id, record) into the list; see the module doc.
    /// `admin_nodes`, when given, is the only set of node ids whose records
    /// count.
    pub fn fold<'a>(
        records: impl IntoIterator<Item = (&'a str, &'a Directive)>,
        admin_nodes: Option<&HashSet<String>>,
    ) -> AccessList {
        let mut ordered: Vec<(u64, &str, Change)> = records
            .into_iter()
            .filter_map(|(id, directive)| {
                let Directive::Event(event) = directive else {
                    return None;
                };
                let author = event.metadata.get("openledger-author")?;
                if admin_nodes.is_some_and(|nodes| !nodes.contains(author)) {
                    return None;
                }
                let lamport = event.metadata.get("openledger-lamport")?.parse().ok()?;
                Some((
                    lamport,
                    id,
                    parse_change(&event.description, &event.metadata)?,
                ))
            })
            .collect();
        ordered.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
        // A revoked user id is never granted again: the API only ever revokes
        // someone on the list and gives a new person a new id, so a grant of a
        // revoked id is a rotation that raced the revoke — and the revoke wins.
        let revoked: HashSet<String> = ordered
            .iter()
            .filter_map(|(_, _, change)| match change {
                Change::Revoke { user } => Some(user.clone()),
                _ => None,
            })
            .collect();

        let mut list = AccessList::default();
        for (_, _, change) in ordered {
            match &change {
                Change::Grant { user, entry } => {
                    list.names.insert(user.clone(), entry.name.clone());
                }
                Change::Rename { user, name } => {
                    if let Some(known) = list.names.get_mut(user) {
                        *known = name.clone();
                    }
                }
                Change::Revoke { .. } => {}
            }
            match change {
                Change::Grant { user, entry } => {
                    if !revoked.contains(&user) {
                        list.users.insert(user, entry);
                    }
                }
                // A rename of someone not on the list (never granted, or
                // revoked first in the order) changes nothing.
                Change::Rename { user, name } => {
                    if let Some(entry) = list.users.get_mut(&user) {
                        entry.name = name;
                    }
                }
                // Applied above: a revoked id's grants are skipped, so it is
                // never on the list.
                Change::Revoke { .. } => {}
            }
        }
        list
    }

    /// The caller a key belongs to, if any, on `today`: found by the key's
    /// SHA-256, compared in constant time with every stored hash, and refused
    /// after its expiry day. A hash two people share (only an admin who reused
    /// a key could cause it) belongs to neither — fail closed.
    pub fn authenticate(&self, key: &str, today: NaiveDate) -> Option<Caller> {
        use subtle::ConstantTimeEq;
        let hash = sha256_hex(key);
        let mut matched = None;
        let mut matches = 0usize;
        for (user, entry) in &self.users {
            if bool::from(entry.key_sha256.as_bytes().ct_eq(hash.as_bytes())) {
                matches += 1;
                matched = Some((user, entry));
            }
        }
        let (user, entry) = matched.filter(|_| matches == 1)?;
        if entry.expires.is_some_and(|last| today > last) {
            return None;
        }
        Some(Caller {
            who: CallerId::User(user.clone()),
            role: entry.role,
        })
    }
}

/// SHA-256 of `key`, lowercase hex — what an access record stores.
pub fn sha256_hex(key: &str) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

/// 32 bytes from the OS CSPRNG: the draw that makes the node's identity key
/// and its operator key, so no second random source is needed.
fn random_bytes() -> zeroize::Zeroizing<[u8; 32]> {
    zeroize::Zeroizing::new(iroh::SecretKey::generate().to_bytes())
}

/// A new person's key: 32 random bytes, hex — as strong as the operator key.
pub fn new_key() -> String {
    hex::encode(random_bytes().as_slice())
}

/// A new user id: `u_` and 64 random bits, hex.
pub fn new_user_id() -> String {
    format!("u_{}", hex::encode(&random_bytes()[..8]))
}

/// A new access record nonce: 128 random bits, hex
/// ([`ledger::access_record::ACCESS_RECORD_NONCE`]).
pub fn new_record_nonce() -> String {
    hex::encode(&random_bytes()[..16])
}

/// The longest name an access record may carry, in characters.
pub const MAX_NAME_CHARS: usize = 100;

/// A person's name as an access record may carry it: not blank, no longer than
/// [`MAX_NAME_CHARS`], no space at either end, and no control or invisible
/// formatting character — a bidi override or a zero-width character would let
/// a name read as someone else's in `user list` and the journal.
pub fn is_valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.trim() == name
        && name.chars().count() <= MAX_NAME_CHARS
        && !name
            .chars()
            .any(|c| c.is_control() || is_invisible_format(c))
}

/// The Unicode format characters that change how text around them reads
/// without showing: bidi marks, embeddings, overrides and isolates;
/// zero-width spaces and joiners; the byte-order mark.
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{061C}' | '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}'
    )
}

/// A user id: `u_` and 16 lowercase hex digits.
pub fn is_user_id(text: &str) -> bool {
    text.strip_prefix("u_").is_some_and(|hex| {
        hex.len() == 16
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn parse_change(action: &str, fields: &BTreeMap<String, String>) -> Option<Change> {
    // Unique bodies only (review I-1): a record without a well-formed nonce
    // could share its id with another, so it counts for nothing.
    if !fields
        .get(ledger::access_record::ACCESS_RECORD_NONCE)
        .is_some_and(|nonce| ledger::access_record::is_access_record_nonce(nonce))
    {
        return None;
    }
    let user = fields.get("user").filter(|user| is_user_id(user))?.clone();
    let by = fields.get("by")?;
    if by != "operator" && !is_user_id(by) {
        return None;
    }
    let name = || {
        fields
            .get("name")
            .filter(|name| is_valid_name(name))
            .cloned()
    };
    match action {
        "grant" => {
            let name = name()?;
            let role = match fields.get("role")?.as_str() {
                "read" => Role::Read,
                "write" => Role::Write,
                "admin" => Role::Admin,
                _ => return None,
            };
            let key_sha256 = fields.get("key-sha256")?;
            if key_sha256.len() != 64
                || !key_sha256
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return None;
            }
            let expires = match fields.get("expires") {
                Some(text) => Some(NaiveDate::parse_from_str(text, "%Y-%m-%d").ok()?),
                None => None,
            };
            Some(Change::Grant {
                user,
                entry: AccessEntry {
                    name,
                    role,
                    key_sha256: key_sha256.clone(),
                    expires,
                },
            })
        }
        "rename" => Some(Change::Rename {
            user,
            name: name()?,
        }),
        "revoke" => Some(Change::Revoke { user }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger::model::Event;

    const USER: &str = "u_0123456789abcdef";

    fn record(lamport: u64, author: &str, action: &str, fields: &[(&str, &str)]) -> Directive {
        let mut metadata: BTreeMap<String, String> = fields
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        metadata.entry("record".to_owned()).or_insert_with(|| {
            format!(
                "{:032x}",
                NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            )
        });
        metadata.insert("openledger-author".to_owned(), author.to_owned());
        metadata.insert("openledger-lamport".to_owned(), lamport.to_string());
        Directive::Event(Event {
            date: NaiveDate::from_ymd_opt(2026, 10, 1).unwrap(),
            event_type: ledger::access_record::ACCESS_EVENT_TYPE.to_owned(),
            description: action.to_owned(),
            metadata,
        })
    }

    fn grant(lamport: u64, key: &str, role: &str, expires: Option<&str>) -> Directive {
        let hash = sha256_hex(key);
        let mut fields = vec![
            ("user", USER),
            ("name", "Ana Ruiz"),
            ("role", role),
            ("key-sha256", hash.as_str()),
            ("by", "operator"),
        ];
        if let Some(expires) = expires {
            fields.push(("expires", expires));
        }
        record(lamport, "node-a", "grant", &fields)
    }

    fn revoke(lamport: u64) -> Directive {
        record(
            lamport,
            "node-a",
            "revoke",
            &[("user", USER), ("by", "operator")],
        )
    }

    fn fold(records: &[(&str, &Directive)]) -> AccessList {
        AccessList::fold(records.iter().copied(), None)
    }

    fn day(day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 11, day).unwrap()
    }

    /// The fold (002-users-and-roles): records count in lamport order whatever
    /// order they arrive in — a revoke ends the user id for good, whether the
    /// grant is before or after it (a rotation that raced a revoke loses); a
    /// later grant replaces the key (rotation); a key is
    /// accepted through its expiry day and refused after; equal lamports are
    /// settled by content id, the same way everywhere.
    ///
    /// Bug-catch: fold in arrival order and two nodes that received the same
    /// records in different orders disagree on who may write; let a grant
    /// revive a revoked id and a rotation that raced a revoke undoes it.
    #[test]
    fn the_access_list_is_the_same_whatever_order_records_arrive_in() {
        let (granted, revoked) = (grant(5, "key-one", "write", None), revoke(7));
        for records in [
            [("g", &granted), ("r", &revoked)],
            [("r", &revoked), ("g", &granted)],
        ] {
            assert!(fold(&records).users.is_empty(), "the revoke is later");
        }
        let earlier_revoke = revoke(3);
        assert!(
            fold(&[("g", &granted), ("r", &earlier_revoke)])
                .users
                .is_empty(),
            "a revoke is final: a grant of the id, even a later one, does not bring them back"
        );

        let rotated = grant(6, "key-two", "read", None);
        let list = fold(&[("b", &rotated), ("a", &granted)]);
        assert_eq!(
            list.authenticate("key-one", day(1)),
            None,
            "the old key is gone"
        );
        assert_eq!(
            list.authenticate("key-two", day(1)).map(|c| c.role),
            Some(Role::Read)
        );

        let expiring = grant(5, "key-one", "write", Some("2026-11-09"));
        let list = fold(&[("g", &expiring)]);
        assert!(
            list.authenticate("key-one", day(9)).is_some(),
            "the last day counts"
        );
        assert_eq!(
            list.authenticate("key-one", day(10)),
            None,
            "refused after it"
        );

        let (first, second) = (
            grant(5, "key-one", "read", None),
            grant(5, "key-two", "admin", None),
        );
        for records in [
            [("id-1", &first), ("id-2", &second)],
            [("id-2", &second), ("id-1", &first)],
        ] {
            assert_eq!(
                fold(&records).users[USER].role,
                Role::Admin,
                "the higher content id wins a tie"
            );
        }
    }

    /// Names (decision 2, revised): a grant carries the person's name and a
    /// `rename` changes it, keeping role, key and expiry. A rename counts only
    /// for someone on the list at that point in the order — not before their
    /// grant, not after their revoke — and a grant or rename whose name is
    /// blank, padded, too long or holds a control or invisible formatting
    /// character (a bidi override) counts for nothing.
    ///
    /// Bug-catch: let a rename replace the whole entry and it drops the
    /// person's key; apply it to anyone and a rename revives a revoked person.
    #[test]
    fn a_rename_changes_the_name_and_nothing_else() {
        let rename = |lamport: u64, name: &str| {
            record(
                lamport,
                "node-a",
                "rename",
                &[("user", USER), ("name", name), ("by", "operator")],
            )
        };
        let granted = grant(5, "key-one", "write", Some("2026-11-30"));
        let renamed = rename(6, "Ana Ruiz-Soto");
        let list = fold(&[("r", &renamed), ("g", &granted)]);
        let entry = &list.users[USER];
        assert_eq!(entry.name, "Ana Ruiz-Soto");
        assert_eq!(entry.role, Role::Write);
        assert_eq!(
            entry.expires,
            NaiveDate::from_ymd_opt(2026, 11, 30),
            "the expiry is kept"
        );
        assert!(
            list.authenticate("key-one", day(1)).is_some(),
            "the key is kept"
        );

        // The names the journal uses: a grant names, a revoke keeps the name,
        // a rename of an id never granted before it names no one.
        let revoked_now = revoke(7);
        assert_eq!(
            fold(&[("g", &granted), ("v", &revoked_now)]).names[USER],
            "Ana Ruiz",
            "kept after the revoke"
        );
        let stray = rename(4, "Never Granted");
        assert!(fold(&[("s", &stray)]).names.is_empty());

        let early = rename(4, "Before The Grant");
        assert_eq!(
            fold(&[("g", &granted), ("e", &early)]).users[USER].name,
            "Ana Ruiz",
            "a rename before the grant changes nothing"
        );
        let revoked = revoke(7);
        let late = rename(8, "After The Revoke");
        assert!(
            fold(&[("g", &granted), ("v", &revoked), ("l", &late)])
                .users
                .is_empty(),
            "a rename after the revoke brings no one back"
        );

        let too_long = "x".repeat(MAX_NAME_CHARS + 1);
        for bad in [
            "",
            " Ana",
            "Ana ",
            "Ana\nRuiz",
            "Ana\u{202E}ziuR",
            "An\u{200B}a",
            too_long.as_str(),
        ] {
            let bad_rename = rename(6, bad);
            assert_eq!(
                fold(&[("g", &granted), ("r", &bad_rename)]).users[USER].name,
                "Ana Ruiz",
                "{bad:?}"
            );
            let hash = sha256_hex("key");
            let bad_grant = record(
                1,
                "node-a",
                "grant",
                &[
                    ("user", USER),
                    ("name", bad),
                    ("role", "write"),
                    ("key-sha256", &hash),
                    ("by", "operator"),
                ],
            );
            assert!(fold(&[("x", &bad_grant)]).users.is_empty(), "{bad:?}");
        }
        let longest = "x".repeat(MAX_NAME_CHARS);
        let fits = rename(6, &longest);
        assert_eq!(
            fold(&[("g", &granted), ("r", &fits)]).users[USER].name,
            longest,
            "exactly the limit is allowed"
        );
    }

    /// A malformed access record — a bad user id, role, key hash or `by`, an
    /// unknown action, no lamport — changes nothing; and with
    /// `auth.adminNodes` set, records from any other node are ignored; a
    /// record with no well-formed `record` nonce counts for nothing; and a key
    /// hash two people hold belongs to neither.
    ///
    /// Bug-catch: accept a record without its checks and a typo grants an
    /// unknown role; ignore `adminNodes` and any node can grant access.
    #[test]
    fn malformed_records_and_other_nodes_records_change_nothing() {
        let hash = sha256_hex("key");
        let bad = [
            record(
                1,
                "node-a",
                "grant",
                &[
                    ("user", "alice"),
                    ("name", "Ana Ruiz"),
                    ("role", "write"),
                    ("key-sha256", &hash),
                    ("by", "operator"),
                ],
            ),
            record(
                1,
                "node-a",
                "grant",
                &[
                    ("user", USER),
                    ("name", "Ana Ruiz"),
                    ("role", "owner"),
                    ("key-sha256", &hash),
                    ("by", "operator"),
                ],
            ),
            // Uppercase (the hex check) and lowercase but short (the length
            // check): each check has a case only it refuses.
            record(
                1,
                "node-a",
                "grant",
                &[
                    ("user", USER),
                    ("name", "Ana Ruiz"),
                    ("role", "write"),
                    ("key-sha256", &"A".repeat(64)),
                    ("by", "operator"),
                ],
            ),
            record(
                1,
                "node-a",
                "grant",
                &[
                    ("user", USER),
                    ("name", "Ana Ruiz"),
                    ("role", "write"),
                    ("key-sha256", "abc"),
                    ("by", "operator"),
                ],
            ),
            record(
                1,
                "node-a",
                "grant",
                &[
                    ("user", USER),
                    ("name", "Ana Ruiz"),
                    ("role", "write"),
                    ("key-sha256", &hash),
                    ("by", "root"),
                ],
            ),
            record(
                1,
                "node-a",
                "promote",
                &[("user", USER), ("by", "operator")],
            ),
        ];
        for directive in &bad {
            assert!(fold(&[("x", directive)]).users.is_empty(), "{directive:?}");
        }
        let mut no_lamport = grant(1, "key", "write", None);
        if let Directive::Event(event) = &mut no_lamport {
            event.metadata.remove("openledger-lamport");
        }
        assert!(fold(&[("x", &no_lamport)]).users.is_empty());

        // A record without a well-formed `record` nonce counts for nothing.
        for bad_nonce in [None, Some("XYZ")] {
            let mut directive = grant(1, "key", "write", None);
            if let Directive::Event(event) = &mut directive {
                match bad_nonce {
                    None => event.metadata.remove("record"),
                    Some(value) => event.metadata.insert("record".to_owned(), value.to_owned()),
                };
            }
            assert!(fold(&[("x", &directive)]).users.is_empty(), "{bad_nonce:?}");
        }

        // One key hash held by two people belongs to neither (fail closed).
        let hash = sha256_hex("shared");
        let (first, second) = (
            record(
                1,
                "node-a",
                "grant",
                &[
                    ("user", "u_000000000000000a"),
                    ("name", "Ana Ruiz"),
                    ("role", "read"),
                    ("key-sha256", &hash),
                    ("by", "operator"),
                ],
            ),
            record(
                2,
                "node-a",
                "grant",
                &[
                    ("user", "u_000000000000000b"),
                    ("name", "Ana Ruiz"),
                    ("role", "admin"),
                    ("key-sha256", &hash),
                    ("by", "operator"),
                ],
            ),
        );
        assert_eq!(
            fold(&[("1", &first), ("2", &second)]).authenticate("shared", day(1)),
            None
        );

        let granted = grant(1, "key", "write", None);
        let only_b: HashSet<String> = ["node-b".to_owned()].into();
        assert!(
            AccessList::fold([("x", &granted)], Some(&only_b))
                .users
                .is_empty(),
            "node-a is not an admin node"
        );
        let only_a: HashSet<String> = ["node-a".to_owned()].into();
        assert_eq!(
            AccessList::fold([("x", &granted)], Some(&only_a))
                .users
                .len(),
            1
        );
    }

    /// Two nodes converge on one access list (decision 5): one grants a
    /// person write access while the other, concurrently, revokes them; once
    /// each has the other's record — through the real peer path,
    /// `stage_remote_directive` — both fold to the same list.
    ///
    /// Bug-catch: index access records only on the authoring path and the
    /// peer's records never reach its access list.
    #[test]
    fn two_nodes_converge_on_the_same_access_list() {
        let dir = tempfile::tempdir().expect("tempdir");
        let boot = |name: &str| {
            ledger::service::LedgerService::boot(
                dir.path().join(format!("{name}.bean")),
                name.to_owned(),
            )
            .expect("boot")
        };
        let (mut node_a, mut node_b) = (boot("node-a"), boot("node-b"));
        let date = NaiveDate::from_ymd_opt(2026, 10, 1).unwrap();
        let fields = |pairs: &[(&str, &str)]| -> BTreeMap<String, String> {
            static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1000);
            let mut fields: BTreeMap<String, String> = pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect();
            fields.insert(
                "record".to_owned(),
                format!(
                    "{:032x}",
                    NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                ),
            );
            fields
        };
        let hash = sha256_hex("person-key");
        let grant_id = node_a
            .record_access_event_staged(
                date,
                "grant",
                fields(&[
                    ("user", USER),
                    ("name", "Ana Ruiz"),
                    ("role", "write"),
                    ("key-sha256", &hash),
                    ("by", "operator"),
                ]),
                |_, _, _| None,
            )
            .expect("grant");
        let revoke_id = node_b
            .record_access_event_staged(
                date,
                "revoke",
                fields(&[("user", USER), ("by", "operator")]),
                |_, _, _| None,
            )
            .expect("revoke");
        let grant_record = node_a.dag().get(&grant_id).expect("granted").clone();
        let revoke_record = node_b.dag().get(&revoke_id).expect("revoked").clone();
        node_b
            .stage_remote_directive(grant_record)
            .expect("b takes a's grant");
        node_a
            .stage_remote_directive(revoke_record)
            .expect("a takes b's revoke");

        let list_a = AccessList::fold(node_a.dag().access_records(), None);
        let list_b = AccessList::fold(node_b.dag().access_records(), None);
        assert_eq!(node_a.dag().access_records().count(), 2);
        assert_eq!(
            list_a, list_b,
            "the same records fold to the same list on both nodes"
        );
    }
}
