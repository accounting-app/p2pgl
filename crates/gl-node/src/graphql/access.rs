//! The admin API for people and keys (`docs/build-log/002-users-and-roles`,
//! step 3): `grantAccess`, `revokeAccess`, `renameUser` and `accessList`.
//!
//! All four are in [`crate::access_control::ADMIN_FIELDS`], so the role check
//! has refused anyone but an admin before a resolver here runs. A change is an
//! access record (`ledger::access_record`) this node writes, signs and
//! replicates like any other record; the access list every node folds from
//! those records is what the auth middleware consults, so a grant works on
//! every node of the mesh as soon as the record reaches it. A person's key is
//! 32 random bytes, returned once by `grantAccess` and never stored: the record
//! keeps only its SHA-256.

use std::sync::Arc;

use async_graphql::{Context, Enum, ErrorExtensions, Result, SimpleObject};
use chrono::NaiveDate;
use ledger::model::Metadata;
use ledger::service::ServiceError;
use security::signing::{SignableMessage, SignatureProvider};

use super::mutation::{gossip_after_unlock, service_error_to_graphql};
use super::scalars::DateScalar;
use super::SharedLedger;
use crate::access_control::{Caller, CallerId, Role};
use crate::access_list::{self, AccessList};
use crate::auth::AccessSource;
use crate::ledger_commit::{
    acquire_write_permit, commit_pending, prepare_or_recover, refuse_if_local_write_cannot_fit,
    LocalWrite,
};

/// A role, as the admin API names it.
#[derive(Enum, Copy, Clone, Debug, PartialEq, Eq)]
pub enum AccessRole {
    /// Reports, balances, the journal: nothing that changes anything.
    Read,
    /// Read, and enter transactions and manage accounts.
    Write,
    /// Everything, including managing people and keys.
    Admin,
}

impl From<Role> for AccessRole {
    fn from(role: Role) -> Self {
        match role {
            Role::Read => AccessRole::Read,
            Role::Write => AccessRole::Write,
            Role::Admin => AccessRole::Admin,
        }
    }
}

impl AccessRole {
    /// The `role` field of an access record.
    fn as_record(self) -> &'static str {
        match self {
            AccessRole::Read => "read",
            AccessRole::Write => "write",
            AccessRole::Admin => "admin",
        }
    }
}

/// What `grantAccess` returns: the person and, this once, their key.
#[derive(SimpleObject)]
pub struct GrantedAccess {
    pub user_id: String,
    pub name: String,
    pub role: AccessRole,
    /// The last day the key is accepted; none, it does not expire.
    pub expires: Option<DateScalar>,
    /// The person's key, to send as `X-Api-Key`. Shown this once: the node
    /// keeps only its SHA-256, so a lost key is replaced by a new grant.
    pub key: String,
}

/// One person on the access list.
#[derive(SimpleObject)]
pub struct PersonAccess {
    pub user_id: String,
    pub name: String,
    pub role: AccessRole,
    pub expires: Option<DateScalar>,
    /// Past its expiry day: the key is refused until a new grant.
    pub expired: bool,
}

/// What an admin asked for.
pub(super) enum AccessChange {
    /// A new person (`user_id` none) or a new role, expiry and key for one on
    /// the list.
    Grant {
        user_id: Option<String>,
        name: Option<String>,
        role: AccessRole,
        expires: Option<NaiveDate>,
    },
    Rename {
        user_id: String,
        name: String,
    },
    Revoke {
        user_id: String,
    },
}

/// The access record a change becomes: its action, its own fields (without
/// `by` and the nonce), and for a grant what to hand back.
struct PlannedRecord {
    action: &'static str,
    fields: Metadata,
    granted: Option<GrantedAccess>,
}

fn refusal(code: &'static str, message: String) -> async_graphql::Error {
    async_graphql::Error::new(message).extend_with(|_, ext| ext.set("code", code))
}

fn invalid(message: String) -> ServiceError {
    ServiceError::InvalidInput { message }
}

/// This node's access list source, or the refusal a node without one gives.
fn access_source<'a>(ctx: &Context<'a>) -> Result<&'a AccessSource> {
    ctx.data_opt::<AccessSource>().ok_or_else(|| {
        refusal(
            "NO_ACCESS_LIST",
            "this node keeps no access list, so it cannot manage people: that needs \
             signing.enabled (nothing else proves who wrote an access record) and auth on (with \
             auth off anything on this machine is the operator, and its grants would count on \
             every node of the mesh)"
                .to_owned(),
        )
    })
}

/// A name as the admin typed it, with the spaces at either end dropped, or why
/// an access record cannot carry it.
fn checked_name(name: &str) -> Result<String, ServiceError> {
    let name = name.trim();
    if access_list::is_valid_name(name) {
        Ok(name.to_owned())
    } else {
        Err(invalid(format!(
            "a name must be 1 to {} characters with no control characters",
            access_list::MAX_NAME_CHARS
        )))
    }
}

/// Judge `change` against `list` as it stands on `today`, and build the record.
fn plan(
    list: &AccessList,
    change: AccessChange,
    today: NaiveDate,
) -> Result<PlannedRecord, ServiceError> {
    let on_the_list = |user_id: &str| {
        list.users.get(user_id).ok_or_else(|| {
            invalid(format!(
                "no one with user id {user_id:?} is on the access list"
            ))
        })
    };
    let mut fields = Metadata::new();
    match change {
        AccessChange::Grant {
            user_id,
            name,
            role,
            expires,
        } => {
            if let Some(last) = expires.filter(|last| *last < today) {
                return Err(invalid(format!(
                    "expires {last} is in the past; a key is accepted through its expiry day"
                )));
            }
            let (user_id, name) = match user_id {
                Some(user_id) => {
                    let current = on_the_list(&user_id)?;
                    let name = match name {
                        Some(name) => checked_name(&name)?,
                        None => current.name.clone(),
                    };
                    (user_id, name)
                }
                None => {
                    let name = checked_name(
                        &name.ok_or_else(|| invalid("a new person needs a name".to_owned()))?,
                    )?;
                    // 64 random bits; drawn again on the (never seen)
                    // chance it is taken.
                    let user_id = std::iter::repeat_with(access_list::new_user_id)
                        .find(|id| !list.users.contains_key(id))
                        .expect("an unbounded iterator");
                    (user_id, name)
                }
            };
            let key = access_list::new_key();
            fields.insert("user".to_owned(), user_id.clone());
            fields.insert("name".to_owned(), name.clone());
            fields.insert("role".to_owned(), role.as_record().to_owned());
            fields.insert("key-sha256".to_owned(), access_list::sha256_hex(&key));
            if let Some(last) = expires {
                fields.insert("expires".to_owned(), last.format("%Y-%m-%d").to_string());
            }
            Ok(PlannedRecord {
                action: "grant",
                fields,
                granted: Some(GrantedAccess {
                    user_id,
                    name,
                    role,
                    expires: expires.map(DateScalar),
                    key,
                }),
            })
        }
        AccessChange::Rename { user_id, name } => {
            on_the_list(&user_id)?;
            fields.insert("user".to_owned(), user_id);
            fields.insert("name".to_owned(), checked_name(&name)?);
            Ok(PlannedRecord {
                action: "rename",
                fields,
                granted: None,
            })
        }
        AccessChange::Revoke { user_id } => {
            on_the_list(&user_id)?;
            fields.insert("user".to_owned(), user_id);
            Ok(PlannedRecord {
                action: "revoke",
                fields,
                granted: None,
            })
        }
    }
}

/// Write the access record `change` asks for, as every mutation writes: the
/// single-writer permit and the write lock while it is judged and staged, the
/// durable write off the lock, then gossip (`super::mutation`). It is judged
/// under the lock against the list as it stands — the caller, still an admin,
/// and the change — so two admins revoking the same person at once get one
/// record and one refusal.
pub(super) async fn change_access(
    ctx: &Context<'_>,
    change: AccessChange,
) -> Result<Option<GrantedAccess>> {
    let ledger = ctx
        .data::<SharedLedger>()
        .map_err(|_| refusal("INTERNAL", "Ledger service not initialized".to_owned()))?;
    let source = access_source(ctx)?;
    let by = match ctx.data::<Caller>().map(|caller| &caller.who) {
        Ok(CallerId::Operator) => "operator".to_owned(),
        Ok(CallerId::User(user_id)) => user_id.clone(),
        Err(_) => {
            return Err(refusal(
                "FORBIDDEN",
                "no authenticated caller for this request".to_owned(),
            ))
        }
    };
    let today = chrono::Utc::now().date_naive();
    let signer = ctx.data::<Arc<dyn SignatureProvider>>().ok().cloned();

    let permit = acquire_write_permit(ledger).await;
    let mut svc = ledger.write().await;
    // A record from a node outside `auth.adminNodes` counts on no node, this
    // one included: say so rather than write it.
    if source
        .admin_nodes
        .as_ref()
        .is_some_and(|nodes| !nodes.contains(svc.author_id()))
    {
        return Err(refusal(
            "NOT_AN_ADMIN_NODE",
            "this node is not in auth.adminNodes, so no node would count an access record it \
             wrote; manage people on one of the admin nodes"
                .to_owned(),
        ));
    }
    let list = AccessList::fold(svc.dag().access_records(), source.admin_nodes.as_deref());
    // The role check judged the caller when the request was parsed; a person
    // revoked, demoted or expired while it waited for the permit is judged
    // again here, against the same list as the change (step 3 review).
    if by != "operator"
        && !list.users.get(&by).is_some_and(|entry| {
            entry.role == Role::Admin && !entry.expires.is_some_and(|last| today > last)
        })
    {
        return Err(refusal(
            "FORBIDDEN",
            "this key is no longer an admin's: its access changed while the request waited"
                .to_owned(),
        ));
    }
    let PlannedRecord {
        action,
        mut fields,
        granted,
    } = plan(&list, change, today).map_err(service_error_to_graphql)?;
    fields.insert("by".to_owned(), by);
    fields.insert(
        ledger::access_record::ACCESS_RECORD_NONCE.to_owned(),
        access_list::new_record_nonce(),
    );
    // T77 / L-71: see `append_transaction`.
    refuse_if_local_write_cannot_fit(
        &svc,
        LocalWrite::Access {
            date: today,
            action,
            fields: &fields,
        },
        None,
        signer.as_deref(),
    )
    .map_err(service_error_to_graphql)?;
    let content_id = svc
        .record_access_event_staged(today, action, fields, |id, parents, lamport| {
            signer.as_ref().and_then(|provider| {
                provider.sign(&SignableMessage {
                    content_id: id,
                    is_transaction: false,
                    parents,
                    lamport,
                })
            })
        })
        .map_err(service_error_to_graphql)?;
    // M-39: see `append_transaction`.
    let (svc, pending, permit) = prepare_or_recover(ledger, svc, false, permit)
        .await
        .map_err(service_error_to_graphql)?;
    // L-18: gossip after the lock is dropped, as every mutation does.
    let to_gossip = svc.get_directive(&content_id).cloned();
    drop(svc);
    commit_pending(ledger, pending, permit)
        .await
        .map_err(service_error_to_graphql)?;
    gossip_after_unlock(ctx, to_gossip).await;
    Ok(granted)
}

/// Everyone on the access list, by user id.
pub(super) async fn access_list(ctx: &Context<'_>) -> Result<Vec<PersonAccess>> {
    let list = access_source(ctx)?.current().await;
    let today = chrono::Utc::now().date_naive();
    Ok(list
        .users
        .iter()
        .map(|(user_id, entry)| PersonAccess {
            user_id: user_id.clone(),
            name: entry.name.clone(),
            role: entry.role.into(),
            expires: entry.expires.map(DateScalar),
            expired: entry.expires.is_some_and(|last| today > last),
        })
        .collect())
}

/// A node with auth, an access list and the operator key [`test_node::OPERATOR`],
/// behind the real router — for these tests and `crate::user_cli`'s.
#[cfg(test)]
pub(crate) mod test_node {
    use std::collections::HashSet;
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::Router;
    use http_body_util::BodyExt;
    use serde_json::Value;
    use tokio::sync::RwLock;
    use tower::ServiceExt;
    use tower_http::cors::CorsLayer;

    use crate::auth::{AccessSource, AuthState};
    use crate::graphql::broadcast::TransactionBroadcast;
    use crate::graphql::{build_schema_with_access, SharedLedger};
    use crate::health::HealthState;
    use crate::request_guard::RequestGuardState;

    pub(crate) const OPERATOR: &str = "operator-key-for-the-access-tests-0123456789abcdef";

    pub(crate) struct TestNode {
        pub dir: tempfile::TempDir,
        pub ledger: SharedLedger,
        pub schema: crate::graphql::AppSchema,
        pub app: Router,
    }

    /// `signing`: whether the node keeps an access list at all; `admin_nodes`:
    /// `auth.adminNodes` (the node's own id is `test-node`).
    pub(crate) fn node(signing: bool, admin_nodes: Option<&[&str]>) -> TestNode {
        let dir = tempfile::tempdir().expect("tempdir");
        let bean_path = dir.path().join("access.bean");
        let service =
            ledger::service::LedgerService::boot(&bean_path, "test-node".to_owned()).expect("boot");
        let ledger: SharedLedger = Arc::new(RwLock::new(service));
        let admin_nodes = admin_nodes.map(|nodes| {
            Arc::new(
                nodes
                    .iter()
                    .map(|node| (*node).to_owned())
                    .collect::<HashSet<_>>(),
            )
        });
        let access = signing.then(|| AccessSource::new(ledger.clone(), admin_nodes));
        let peer_registry = p2p::node::PeerRegistry::new();
        let schema = build_schema_with_access(
            ledger.clone(),
            TransactionBroadcast::new(),
            peer_registry.clone(),
            Arc::new(security::signing::NoopSignatureProvider),
            true,
            None,
            access.clone(),
        );
        let auth = AuthState {
            enabled: true,
            api_key: OPERATOR.to_owned(),
            access,
        };
        let app = crate::build_application(
            schema.clone(),
            auth.clone(),
            HealthState {
                ledger: ledger.clone(),
                peer_registry,
                public_bind: false,
                auth,
            },
            RequestGuardState {
                allowed_hosts: Arc::new(["127.0.0.1".to_owned()].into()),
                allowed_origins: Arc::new(HashSet::new()),
                tls_terminated: false,
            },
            CorsLayer::new(),
            true,
        );
        TestNode {
            dir,
            ledger,
            schema,
            app,
        }
    }

    impl TestNode {
        /// `POST /graphql` with `key`: the status and the JSON body.
        pub(crate) async fn post(&self, key: &str, body: Value) -> (StatusCode, Value) {
            let request = Request::post("/graphql")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .header("x-api-key", key)
                .body(Body::from(body.to_string()))
                .expect("request");
            let response = self.app.clone().oneshot(request).await.expect("response");
            let status = response.status();
            let bytes = response
                .into_body()
                .collect()
                .await
                .expect("body")
                .to_bytes();
            (
                status,
                serde_json::from_slice(&bytes).unwrap_or(Value::Null),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use serde_json::{json, Value};

    use super::test_node::{node, TestNode, OPERATOR};
    use crate::access_list::{is_user_id, AccessList};

    const GRANT: &str =
        "mutation($name: String, $role: AccessRole!, $expires: Date, $user: String) \
        { grantAccess(name: $name, role: $role, expires: $expires, userId: $user) \
        { userId name role expires key } }";

    fn grant(name: Option<&str>, role: &str, user: Option<&str>) -> Value {
        json!({ "query": GRANT, "variables": { "name": name, "role": role, "user": user } })
    }

    fn query(text: &str) -> Value {
        json!({ "query": text })
    }

    fn code(body: &Value) -> Option<&str> {
        body["errors"][0]["extensions"]["code"].as_str()
    }

    /// Grant as `key`, returning (user id, key).
    async fn granted(node: &TestNode, key: &str, request: Value) -> (String, String) {
        let (status, body) = node.post(key, request).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["errors"].is_null(), "{body}");
        let granted = &body["data"]["grantAccess"];
        (
            granted["userId"].as_str().expect("user id").to_owned(),
            granted["key"].as_str().expect("key").to_owned(),
        )
    }

    const OPEN: &str = r#"mutation { openAccount(name: "Assets:Bank", date: "2026-01-02") }"#;
    const READ: &str = "{ verify { ok } }";

    /// The admin API end to end (002 step 3), through the real router and
    /// auth middleware: the operator grants a person write access and the key
    /// it returns works at once — writes, but not the admin API; `accessList`
    /// shows name and role and never a key or its hash; a rename keeps the
    /// key; a new grant to the same person replaces role and key (the old key
    /// gets 401); an admin person's grant names them in `by`; a revoke ends
    /// the key.
    ///
    /// Bug-catch: drop `grantAccess` from `ADMIN_FIELDS` and a write key can
    /// grant itself admin; store the key instead of its hash and the key no
    /// longer authenticates.
    #[tokio::test]
    async fn an_admin_grants_renames_regrants_and_revokes() {
        let node = node(true, None);
        let (ana, ana_key) =
            granted(&node, OPERATOR, grant(Some("  Ana Ruiz "), "WRITE", None)).await;
        assert!(is_user_id(&ana), "{ana}");
        assert_eq!(ana_key.len(), 64);

        let (status, body) = node.post(&ana_key, query(OPEN)).await;
        assert_eq!(
            (status, body["errors"].is_null()),
            (StatusCode::OK, true),
            "{body}"
        );
        for admin_only in [
            query("{ accessList { userId } }"),
            grant(Some("Mallory"), "ADMIN", None),
            json!({ "query": format!(r#"mutation {{ revokeAccess(userId: "{ana}") }}"#) }),
            json!({ "query": format!(r#"mutation {{ renameUser(userId: "{ana}", name: "M") }}"#) }),
        ] {
            let (_, body) = node.post(&ana_key, admin_only.clone()).await;
            assert_eq!(code(&body), Some("FORBIDDEN"), "{admin_only}: {body}");
            // The role check's refusal, before any resolver runs — not the
            // under-the-lock caller check, which would also refuse a write key.
            let message = body["errors"][0]["message"].as_str().unwrap_or("");
            assert!(message.contains("the request needs admin"), "{message}");
        }

        let (_, listed) = node
            .post(
                OPERATOR,
                query("{ accessList { userId name role expires expired } }"),
            )
            .await;
        assert_eq!(
            listed["data"]["accessList"],
            json!([{ "userId": ana, "name": "Ana Ruiz", "role": "WRITE", "expires": null, "expired": false }])
        );
        let text = listed.to_string();
        assert!(!text.contains(&ana_key), "no key in the list");
        assert!(
            !text.contains(&crate::access_list::sha256_hex(&ana_key)),
            "no key hash in the list"
        );

        let rename =
            format!(r#"mutation {{ renameUser(userId: "{ana}", name: "Ana Ruiz-Soto") }}"#);
        let (_, body) = node.post(OPERATOR, query(&rename)).await;
        assert_eq!(body["data"]["renameUser"], true, "{body}");
        let (status, _) = node.post(&ana_key, query(READ)).await;
        assert_eq!(status, StatusCode::OK, "a rename keeps the key");

        let (same, new_key) = granted(&node, OPERATOR, grant(None, "READ", Some(&ana))).await;
        assert_eq!(same, ana);
        let (status, _) = node.post(&ana_key, query(READ)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "the old key is gone");
        let (_, body) = node.post(&new_key, query(OPEN)).await;
        assert_eq!(code(&body), Some("FORBIDDEN"), "read now: {body}");
        let (_, listed) = node
            .post(OPERATOR, query("{ accessList { name role } }"))
            .await;
        assert_eq!(
            listed["data"]["accessList"],
            json!([{ "name": "Ana Ruiz-Soto", "role": "READ" }]),
            "a grant without a name keeps theirs"
        );

        let (bea, bea_key) = granted(&node, OPERATOR, grant(Some("Bea"), "ADMIN", None)).await;
        let (cy, _) = granted(&node, &bea_key, grant(Some("Cy"), "READ", None)).await;
        let by_of = |user: &str| {
            let user = user.to_owned();
            let ledger = node.ledger.clone();
            async move {
                let svc = ledger.read().await;
                let by: Vec<String> = svc
                    .dag()
                    .access_records()
                    .filter_map(|(_, record)| match record {
                        ledger::model::Directive::Event(event)
                            if event.metadata.get("user") == Some(&user) =>
                        {
                            event.metadata.get("by").cloned()
                        }
                        _ => None,
                    })
                    .collect();
                by
            }
        };
        assert_eq!(
            by_of(&cy).await,
            vec![bea.clone()],
            "an admin person is named"
        );
        assert_eq!(by_of(&bea).await, vec!["operator".to_owned()]);

        let revoke = format!(r#"mutation {{ revokeAccess(userId: "{ana}") }}"#);
        let (_, body) = node.post(OPERATOR, query(&revoke)).await;
        assert_eq!(body["data"]["revokeAccess"], true, "{body}");
        let (status, _) = node.post(&new_key, query(READ)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "revoked");
        assert_eq!(node.ledger.read().await.dag().access_records().count(), 6);
    }

    /// What the admin API refuses, writing nothing: a change for someone not
    /// on the list, a new person with no name or a blank one, an expiry
    /// already past; on a node that does not sign, everything
    /// (`NO_ACCESS_LIST`); on a node outside `auth.adminNodes`, every change
    /// (`NOT_AN_ADMIN_NODE`) — and on one inside it, the grant goes through.
    ///
    /// Bug-catch: skip the list check and a revoke for a mistyped id writes a
    /// record that ends no one; drop the adminNodes check and a change every
    /// node ignores is reported as made.
    #[tokio::test]
    async fn the_admin_api_refuses_what_would_not_count() {
        let node = node(true, None);
        let nobody = "u_0123456789abcdef";
        let yesterday = (chrono::Utc::now().date_naive() - chrono::Duration::days(1)).to_string();
        for (request, why) in [
            (
                query(&format!(
                    r#"mutation {{ revokeAccess(userId: "{nobody}") }}"#
                )),
                "revoke someone not on the list",
            ),
            (
                query(&format!(
                    r#"mutation {{ renameUser(userId: "{nobody}", name: "X") }}"#
                )),
                "rename someone not on the list",
            ),
            (
                grant(None, "READ", Some(nobody)),
                "regrant someone not on the list",
            ),
            (grant(None, "READ", None), "a new person with no name"),
            (grant(Some("   "), "READ", None), "a blank name"),
            (
                json!({ "query": GRANT, "variables": { "name": "Ana", "role": "READ", "expires": yesterday } }),
                "an expiry in the past",
            ),
        ] {
            let (_, body) = node.post(OPERATOR, request).await;
            assert_eq!(code(&body), Some("INVALID_INPUT"), "{why}: {body}");
        }
        assert_eq!(node.ledger.read().await.dag().access_records().count(), 0);

        let today = chrono::Utc::now().date_naive().to_string();
        let (_, body) = node
            .post(
                OPERATOR,
                json!({ "query": GRANT, "variables": { "name": "Ana", "role": "READ", "expires": today } }),
            )
            .await;
        assert!(body["errors"].is_null(), "today is not past: {body}");

        let unsigned = super::test_node::node(false, None);
        for request in [
            grant(Some("Ana"), "READ", None),
            query("{ accessList { userId } }"),
        ] {
            let (_, body) = unsigned.post(OPERATOR, request).await;
            assert_eq!(code(&body), Some("NO_ACCESS_LIST"), "{body}");
        }

        let outside = super::test_node::node(true, Some(&["some-other-node"]));
        let (_, body) = outside
            .post(OPERATOR, grant(Some("Ana"), "READ", None))
            .await;
        assert_eq!(code(&body), Some("NOT_AN_ADMIN_NODE"), "{body}");
        assert_eq!(
            outside.ledger.read().await.dag().access_records().count(),
            0
        );
        let inside = super::test_node::node(true, Some(&["test-node"]));
        let (_, body) = inside
            .post(OPERATOR, grant(Some("Ana"), "READ", None))
            .await;
        assert!(body["errors"].is_null(), "an admin node grants: {body}");
    }

    /// T77 / L-71 for access records: on a ledger too near its size cap for
    /// the record, a grant is refused before anything is staged — no clock
    /// movement, no stage, no reload under the permit — in both record
    /// formats (v2 is gl-node's default).
    ///
    /// Bug-catch: leave access records out of the fit check, in either
    /// format, and the grant is staged, refused at the prepare, and paid for
    /// with a full reload.
    #[tokio::test]
    async fn a_grant_that_cannot_fit_is_refused_before_staging() {
        for format in [
            ledger::hash::RecordFormat::V1,
            ledger::hash::RecordFormat::V2,
        ] {
            grant_near_the_cap(format).await;
        }
    }

    async fn grant_near_the_cap(format: ledger::hash::RecordFormat) {
        use crate::graphql::ExecuteAsOperator;
        let dir = tempfile::tempdir().expect("tempdir");
        let ledger = crate::ledger_commit::near_cap::near_cap_ledger_emitting(
            &dir.path().join("cap.bean"),
            200,
            format,
        );
        let schema = crate::graphql::build_schema_with_access(
            ledger.clone(),
            crate::graphql::broadcast::TransactionBroadcast::new(),
            p2p::node::PeerRegistry::new(),
            std::sync::Arc::new(security::signing::NoopSignatureProvider),
            true,
            None,
            Some(crate::auth::AccessSource::new(ledger.clone(), None)),
        );
        let lamport = ledger.read().await.lamport_clock();
        let response = schema
            .execute_as_operator(async_graphql::Request::new(GRANT).variables(
                async_graphql::Variables::from_json(json!({ "name": "Ana", "role": "READ" })),
            ))
            .await;
        let message = response
            .errors
            .first()
            .map(|error| error.message.clone())
            .unwrap_or_default();
        assert!(
            message.contains("refused before staging"),
            "{format:?}: {message}"
        );
        let service = ledger.read().await;
        assert_eq!(service.uncommitted_count(), 0, "nothing staged");
        assert_eq!(service.lamport_clock(), lamport, "the clock did not move");
    }

    /// The caller is judged again under the write lock (step 3 review): an
    /// admin person whose access changed while the request waited — here, one
    /// the list no longer holds — is refused, and nothing is written.
    ///
    /// Bug-catch: trust the role the request was parsed with and a revoked
    /// admin's queued grant is written in their name.
    #[tokio::test]
    async fn a_caller_no_longer_an_admin_is_refused_under_the_lock() {
        use crate::access_control::{Caller, CallerId, Role};
        let node = node(true, None);
        let (reader, _) = granted(&node, OPERATOR, grant(Some("Rita"), "READ", None)).await;
        for who in ["u_0123456789abcdef".to_owned(), reader] {
            let request = async_graphql::Request::new(GRANT)
                .variables(async_graphql::Variables::from_json(
                    json!({ "name": "Mallory", "role": "ADMIN" }),
                ))
                .data(Caller {
                    who: CallerId::User(who.clone()),
                    role: Role::Admin,
                });
            let response = node.schema.execute(request).await;
            let codes: Vec<String> = response
                .errors
                .iter()
                .filter_map(|error| {
                    error
                        .extensions
                        .as_ref()?
                        .get("code")
                        .map(|c| c.to_string())
                })
                .collect();
            assert_eq!(codes, vec!["\"FORBIDDEN\"".to_owned()], "{who}");
        }
        assert_eq!(
            node.ledger.read().await.dag().access_records().count(),
            1,
            "only Rita's grant"
        );
    }

    /// A key granted through one node's API works on another node once the
    /// record reaches it through the peer path (`stage_remote_directive`), and
    /// a revoke made on the first ends it on the second (intent: issued on one
    /// admin node, accepted on all).
    ///
    /// Bug-catch: index access records only on the authoring path and the
    /// peer never learns of the person.
    #[tokio::test]
    async fn a_key_granted_on_one_node_works_on_another() {
        let (first, second) = (node(true, None), node(true, None));
        let copy_new_records = |from: &TestNode, to: &TestNode| {
            let (from, to) = (from.ledger.clone(), to.ledger.clone());
            async move {
                let records: Vec<_> = from
                    .read()
                    .await
                    .dag()
                    .access_records()
                    .map(|(id, record)| (id.to_owned(), record.clone()))
                    .collect();
                let mut to = to.write().await;
                for (id, record) in records {
                    if !to.contains_directive(&id) {
                        to.stage_remote_directive(record).expect("a peer's record");
                    }
                }
            }
        };
        let (user, key) = granted(&first, OPERATOR, grant(Some("Ana"), "READ", None)).await;
        let (status, _) = second.post(&key, query(READ)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "not there yet");
        copy_new_records(&first, &second).await;
        let (status, body) = second.post(&key, query(READ)).await;
        assert_eq!(status, StatusCode::OK, "the peer honours it: {body}");

        let revoke = format!(r#"mutation {{ revokeAccess(userId: "{user}") }}"#);
        let (_, body) = first.post(OPERATOR, query(&revoke)).await;
        assert_eq!(body["data"]["revokeAccess"], true, "{body}");
        copy_new_records(&first, &second).await;
        let (status, _) = second.post(&key, query(READ)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "revoked there too");
    }

    /// Who entered it (step 4): a person's writes carry their user id
    /// (`entered-by`) and the journal shows it with their name — the latest
    /// one, and still after their access is revoked; the operator's writes
    /// carry none.
    ///
    /// Bug-catch: stamp the operator's id on every write and the journal
    /// cannot tell people apart; look names up in the current list only and
    /// a revoked clerk's entries lose their name.
    #[tokio::test]
    async fn the_journal_shows_who_entered_each_write() {
        let node = node(true, None);
        for account in ["Assets:Cash", "Income:Salary"] {
            let open =
                format!(r#"mutation {{ openAccount(name: "{account}", date: "2026-01-01") }}"#);
            let (_, body) = node.post(OPERATOR, query(&open)).await;
            assert!(body["errors"].is_null(), "{body}");
        }
        let (ana, ana_key) = granted(&node, OPERATOR, grant(Some("Ana Ruiz"), "WRITE", None)).await;
        let post = |narration: &str| {
            query(&format!(
                r#"mutation {{ appendTransaction(input: {{ date: "2026-01-02", narration: "{narration}", postings: [
                    {{ account: "Assets:Cash", amount: {{ number: "5", currency: "USD" }} }},
                    {{ account: "Income:Salary" }}] }}) {{ txid enteredBy enteredByName }} }}"#
            ))
        };
        let (_, body) = node.post(&ana_key, post("by Ana")).await;
        let appended = &body["data"]["appendTransaction"];
        assert_eq!(appended["enteredBy"], json!(ana), "{body}");
        assert_eq!(appended["enteredByName"], "Ana Ruiz");
        let (_, body) = node.post(OPERATOR, post("by the operator")).await;
        assert_eq!(
            body["data"]["appendTransaction"]["enteredBy"],
            Value::Null,
            "{body}"
        );
        let (_, body) = node.post(&ana_key, query(OPEN)).await;
        assert!(body["errors"].is_null(), "{body}");
        let close = r#"mutation { closeAccount(name: "Assets:Bank", date: "2026-01-03") }"#;
        let (_, body) = node.post(&ana_key, query(close)).await;
        assert!(body["errors"].is_null(), "{body}");
        let closed_by: Vec<String> = node
            .ledger
            .read()
            .await
            .dag()
            .directives()
            .into_iter()
            .filter_map(|directive| match directive {
                ledger::model::Directive::Close(close) => close
                    .metadata
                    .get(ledger::access_record::ENTERED_BY)
                    .cloned(),
                _ => None,
            })
            .collect();
        assert_eq!(closed_by, vec![ana.clone()], "the close names Ana too");
        let opened_by: Vec<String> = node
            .ledger
            .read()
            .await
            .dag()
            .directives()
            .into_iter()
            .filter_map(|directive| match directive {
                ledger::model::Directive::Open(open) if open.account == "Assets:Bank" => open
                    .metadata
                    .get(ledger::access_record::ENTERED_BY)
                    .cloned(),
                _ => None,
            })
            .collect();
        assert_eq!(opened_by, vec![ana.clone()], "the open names Ana too");

        let journal = || async {
            let (_, body) = node
                .post(
                    OPERATOR,
                    query("{ journal { narration enteredBy enteredByName } }"),
                )
                .await;
            body["data"]["journal"].clone()
        };
        let rename =
            format!(r#"mutation {{ renameUser(userId: "{ana}", name: "Ana Ruiz-Soto") }}"#);
        node.post(OPERATOR, query(&rename)).await;
        let revoke = format!(r#"mutation {{ revokeAccess(userId: "{ana}") }}"#);
        node.post(OPERATOR, query(&revoke)).await;
        let rows = journal().await;
        let row = |narration: &str| {
            rows.as_array()
                .and_then(|rows| rows.iter().find(|row| row["narration"] == narration))
                .cloned()
                .unwrap_or_else(|| panic!("{narration} in {rows}"))
        };
        assert_eq!(
            row("by Ana"),
            json!({ "narration": "by Ana", "enteredBy": ana, "enteredByName": "Ana Ruiz-Soto" }),
            "the latest name, after the revoke"
        );
        assert_eq!(
            row("by the operator"),
            json!({ "narration": "by the operator", "enteredBy": null, "enteredByName": null })
        );
    }

    /// A grant is durable and its name survives the `.bean`: a name with
    /// quotes, an apostrophe, a backslash and non-ASCII letters folds to the
    /// same list after the node reboots from its file.
    ///
    /// The `.bean` holds the key's hash, never the key.
    ///
    /// Bug-catch: write the record unescaped and the reboot loses the person,
    /// or names them wrongly; store the key instead of its hash and anyone
    /// given the books holds every key.
    #[tokio::test]
    async fn a_grant_and_its_name_survive_a_reboot() {
        let node = node(true, None);
        let name = r#"José "JJ" O'Brien \ Núñez"#;
        let (user, key) = granted(&node, OPERATOR, grant(Some(name), "WRITE", None)).await;
        let before = AccessList::fold(node.ledger.read().await.dag().access_records(), None);
        assert_eq!(before.users[&user].name, name);

        let rebooted = ledger::service::LedgerService::boot(
            node.dir.path().join("access.bean"),
            "test-node".to_owned(),
        )
        .expect("reboot");
        let bean = std::fs::read_to_string(node.dir.path().join("access.bean")).expect("bean");
        assert!(bean.contains(&crate::access_list::sha256_hex(&key)));
        assert!(!bean.contains(&key), "the key itself is never in the books");
        let after = AccessList::fold(rebooted.dag().access_records(), None);
        assert_eq!(after, before);
        assert!(after
            .authenticate(&key, chrono::Utc::now().date_naive())
            .is_some());
    }
}
