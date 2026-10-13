//! Access records: who may use the node's API, kept in the ledger itself
//! (`docs/build-log/002-users-and-roles`).
//!
//! A grant or a revocation is an `event` directive of type
//! [`ACCESS_EVENT_TYPE`], so it is signed, replicated, quarantined and verified
//! exactly like every other record, and changes no balance. This crate stores
//! and indexes them ([`crate::dag::LedgerDag::access_records`]) and refuses one
//! typed into the ledger file by hand; what they mean — the access list — is the
//! node's (`gl-node`'s `access_list`).

use crate::model::Directive;

/// The `event` type of an access record: `YYYY-MM-DD event "openledger-access" "grant"`.
pub const ACCESS_EVENT_TYPE: &str = "openledger-access";

/// The field that makes every access record's body unique: 32 random lowercase
/// hex digits. A record's id is a hash of its body, and two revocations of the
/// same person on the same day would otherwise be one record — the second
/// silently dropped, or, on a Format v1 mesh where the author is not in the
/// id, two nodes keeping different copies under one id.
pub const ACCESS_RECORD_NONCE: &str = "record";

/// The metadata key naming the person who entered a record through the API:
/// `entered-by: "u_…"` (`docs/build-log/002-users-and-roles`, step 4). An
/// ordinary body key, not the `openledger-` envelope: it is part of the
/// record's id and covered by its signature, so it cannot be changed without
/// the change showing. The node writes it for a person's writes only; a
/// record without it was entered with the node's operator key, by hand in
/// the `.bean`, or before people had keys. An entry typed into the `.bean`
/// with it is refused (`reconcile`): the node would sign it as theirs.
pub const ENTERED_BY: &str = "entered-by";

/// Whether `value` is a well-formed [`ACCESS_RECORD_NONCE`].
pub fn is_access_record_nonce(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether `directive` is an access record.
pub fn is_access_record(directive: &Directive) -> bool {
    matches!(directive, Directive::Event(event) if event.event_type == ACCESS_EVENT_TYPE)
}
