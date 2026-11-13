//! The Plaid fields (`docs/build-log/007-plaid-commitments`, step 5):
//! `createPlaidLinkToken`, `connectBank` and `disconnectBank` (admin only:
//! [`crate::access_control::ADMIN_FIELDS`]) and `connectedBanks` (read). None
//! of them ever returns an access token.

use std::sync::Arc;

use async_graphql::{Context, ErrorExtensions, Result, SimpleObject};

use crate::access_control::{Caller, CallerId};
use crate::plaid::{BankConnection, PlaidError, PlaidService};

/// What the client app opens Plaid Link with. Short-lived (Plaid: 4 hours).
#[derive(SimpleObject, Debug, Clone)]
pub struct PlaidLinkToken {
    pub link_token: String,
    /// When Plaid stops accepting it (RFC 3339, from Plaid).
    pub expiration: String,
}

/// A bank connected through Plaid: its accounts as Plaid names them, with
/// only the last digits Plaid shows. Never a token or a full number.
#[derive(SimpleObject, Debug, Clone)]
pub struct ConnectedBank {
    /// Plaid's id for the connection; `disconnectBank` takes it.
    pub item_id: String,
    pub institution_name: Option<String>,
    /// The UTC date it was connected (`YYYY-MM-DD`); null when its
    /// description could not be stored or read.
    pub connected_on: Option<String>,
    pub accounts: Vec<BankAccount>,
}

#[derive(SimpleObject, Debug, Clone)]
pub struct BankAccount {
    pub account_id: String,
    pub name: String,
    pub mask: Option<String>,
    /// Plaid's account type (`depository`, `credit`, `loan`, …).
    #[graphql(name = "type")]
    pub kind: String,
    pub subtype: Option<String>,
}

impl From<BankConnection> for ConnectedBank {
    fn from(connection: BankConnection) -> Self {
        Self {
            item_id: connection.item_id,
            institution_name: connection.institution_name,
            connected_on: connection.connected_on,
            accounts: connection
                .accounts
                .into_iter()
                .map(|account| BankAccount {
                    account_id: account.account_id,
                    name: account.name,
                    mask: account.mask,
                    kind: account.kind,
                    subtype: account.subtype,
                })
                .collect(),
        }
    }
}

/// This ledger's Plaid service on this node, or the refusal every other node
/// gives.
fn service<'a>(ctx: &Context<'a>) -> Result<&'a Arc<PlaidService>> {
    ctx.data_opt::<Arc<PlaidService>>().ok_or_else(|| {
        async_graphql::Error::new(
            "Plaid is not enabled for this ledger on this node: one node per company holds its \
             bank connections (plaid.enabled in that ledger's config)",
        )
        .extend_with(|_, ext| ext.set("code", "PLAID_NOT_ENABLED"))
    })
}

fn failed(error: PlaidError) -> async_graphql::Error {
    let code = error.code();
    let plaid_code = error.plaid_code().map(str::to_owned);
    // A store failure names files on the node: logged here, not handed to a
    // caller who may hold only a read key.
    let message = match &error {
        PlaidError::Store(detail) => {
            tracing::warn!(error = %detail, "the secret store failed a Plaid request");
            "the node's secret store failed; its log says why".to_owned()
        }
        _ => error.to_string(),
    };
    async_graphql::Error::new(message).extend_with(|_, ext| {
        ext.set("code", code);
        if let Some(plaid_code) = &plaid_code {
            ext.set("plaidCode", plaid_code.as_str());
        }
    })
}

/// Plaid's `client_user_id` for the caller: their user id, or `operator`.
fn client_user_id(ctx: &Context<'_>) -> String {
    match ctx.data_opt::<Caller>().map(|caller| &caller.who) {
        Some(CallerId::User(id)) => id.clone(),
        _ => "operator".to_owned(),
    }
}

pub(super) async fn create_link_token(ctx: &Context<'_>) -> Result<PlaidLinkToken> {
    let token = service(ctx)?
        .create_link_token(&client_user_id(ctx))
        .await
        .map_err(failed)?;
    Ok(PlaidLinkToken {
        link_token: token.link_token,
        expiration: token.expiration,
    })
}

pub(super) async fn connect_bank(ctx: &Context<'_>, public_token: String) -> Result<ConnectedBank> {
    let connection = service(ctx)?.connect(public_token).await.map_err(failed)?;
    Ok(connection.into())
}

pub(super) async fn disconnect_bank(ctx: &Context<'_>, item_id: String) -> Result<bool> {
    service(ctx)?.disconnect(item_id).await.map_err(failed)
}

pub(super) async fn connected_banks(ctx: &Context<'_>) -> Result<Vec<ConnectedBank>> {
    let connections = service(ctx)?.connections().await.map_err(failed)?;
    Ok(connections.into_iter().map(ConnectedBank::from).collect())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use serde_json::Value;
    use tokio::sync::RwLock;

    use crate::access_control::{Caller, CallerId, Role};
    use crate::graphql::broadcast::TransactionBroadcast;
    use crate::graphql::{build_schema_with_access, AppSchema, SharedLedger};
    use crate::plaid::tests::{
        self as mock, MockPlaid, ACCESS_TOKEN, ERROR_MESSAGE_MARKER, ITEM_ID,
    };
    use crate::plaid::PlaidService;

    struct Fixture {
        _dir: tempfile::TempDir,
        schema: AppSchema,
        mock: MockPlaid,
    }

    /// A ledger's schema, with Plaid on (against a mock) or off.
    async fn fixture(plaid_on: bool) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let service = ledger::service::LedgerService::boot(
            dir.path().join("ledger.bean"),
            "test-node".to_owned(),
        )
        .unwrap();
        let ledger: SharedLedger = Arc::new(RwLock::new(service));
        let mock = MockPlaid::default();
        let plaid = if plaid_on {
            let url = mock.serve().await;
            let service =
                PlaidService::start_at("acme", dir.path(), &mock::enabled(), &mock::env(), &url)
                    .unwrap();
            Some(Arc::new(service))
        } else {
            None
        };
        let schema = build_schema_with_access(
            ledger,
            TransactionBroadcast::new(),
            p2p::node::PeerRegistry::new(),
            Arc::new(security::signing::NoopSignatureProvider),
            false,
            None,
            None,
            plaid,
        );
        Fixture {
            _dir: dir,
            schema,
            mock,
        }
    }

    async fn run(schema: &AppSchema, role: Role, query: &str) -> Value {
        let caller = Caller {
            who: CallerId::User("u_0123456789abcdef".to_owned()),
            role,
        };
        let response = schema
            .execute(async_graphql::Request::new(query).data(caller))
            .await;
        serde_json::to_value(&response).unwrap()
    }

    fn code(body: &Value) -> Option<&str> {
        body["errors"][0]["extensions"]["code"].as_str()
    }

    const CONNECT: &str = r#"mutation { connectBank(publicToken: "public-sandbox-xyz") { itemId institutionName accounts { accountId name mask type subtype } } }"#;
    const LINK: &str = "mutation { createPlaidLinkToken { linkToken expiration } }";
    const BANKS: &str =
        "{ connectedBanks { itemId institutionName connectedOn accounts { name mask } } }";

    /// Opening Link, connecting and disconnecting need an admin key; listing
    /// the banks needs only read.
    ///
    /// Bug-catch: leaving `connectBank` out of `ADMIN_FIELDS` lets any write
    /// key connect a bank to the company.
    #[tokio::test]
    async fn plaid_mutations_need_an_admin_key() {
        let fixture = fixture(true).await;
        let disconnect = format!(r#"mutation {{ disconnectBank(itemId: "{ITEM_ID}") }}"#);
        for query in [LINK, CONNECT, disconnect.as_str()] {
            let body = run(&fixture.schema, Role::Write, query).await;
            assert_eq!(code(&body), Some("FORBIDDEN"), "{query}: {body}");
        }
        assert!(
            fixture.mock.paths().is_empty(),
            "{:?}",
            fixture.mock.paths()
        );

        let body = run(&fixture.schema, Role::Read, BANKS).await;
        assert!(body["errors"].is_null(), "{body}");
        let body = run(&fixture.schema, Role::Admin, CONNECT).await;
        assert!(body["errors"].is_null(), "{body}");
    }

    /// On a node without Plaid for the ledger every Plaid field is refused,
    /// naming the rule.
    ///
    /// Bug-catch: a node without the service answering as if it held none.
    #[tokio::test]
    async fn plaid_fields_are_refused_where_plaid_is_off() {
        let fixture = fixture(false).await;
        let disconnect = format!(r#"mutation {{ disconnectBank(itemId: "{ITEM_ID}") }}"#);
        for query in [LINK, CONNECT, BANKS, disconnect.as_str()] {
            let body = run(&fixture.schema, Role::Admin, query).await;
            assert_eq!(code(&body), Some("PLAID_NOT_ENABLED"), "{query}: {body}");
        }
    }

    /// The whole flow — link token, connect, list, disconnect — never puts the
    /// access token in a response. What it logs, at every level, is scanned
    /// too; that half is best effort: tracing's interest cache is global, so
    /// tests running beside this one can hide some lines from its subscriber.
    /// (`Secret`'s redaction and Plaid errors carrying only codes are pinned
    /// on their own: `secret_store`, `crate::plaid`.)
    ///
    /// Bug-catch: a token written into the bank's stored description reaches
    /// every `connectedBanks` caller, read keys included.
    #[tokio::test]
    async fn no_response_carries_the_access_token() {
        use tracing_subscriber::layer::SubscriberExt;
        #[derive(Clone, Default)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        impl std::io::Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let logs = Buffer::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new("trace"))
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(move || writer.clone())
                    .with_ansi(false),
            );
        let _guard = tracing::subscriber::set_default(subscriber);
        // Call sites other tests reached first, with no subscriber on their
        // thread, are cached as uninteresting; judge them again under this one.
        tracing::callsite::rebuild_interest_cache();

        let fixture = fixture(true).await;
        let disconnect = format!(r#"mutation {{ disconnectBank(itemId: "{ITEM_ID}") }}"#);
        let mut bodies = Vec::new();
        for query in [LINK, CONNECT, BANKS, disconnect.as_str(), BANKS] {
            let body = run(&fixture.schema, Role::Admin, query).await;
            assert!(body["errors"].is_null(), "{query}: {body}");
            bodies.push(body);
        }
        assert_eq!(
            bodies[1]["data"]["connectBank"]["institutionName"],
            "First Platypus Bank"
        );
        assert_eq!(
            bodies[2]["data"]["connectedBanks"][0]["accounts"][1]["mask"],
            "1111"
        );
        assert_eq!(bodies[3]["data"]["disconnectBank"], true);
        assert_eq!(bodies[4]["data"]["connectedBanks"], serde_json::json!([]));

        for body in &bodies {
            assert!(!body.to_string().contains(ACCESS_TOKEN), "{body}");
        }
        let text = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        assert!(!text.contains(ACCESS_TOKEN), "token logged");
        assert!(!text.contains(mock::CLIENT_SECRET), "secret logged");
    }

    /// A Plaid refusal reaches the caller as Plaid's code, never its message.
    ///
    /// Bug-catch: passing Plaid's `error_message` through to the client.
    #[tokio::test]
    async fn a_plaid_refusal_reaches_the_caller_as_its_code() {
        let fixture = fixture(true).await;
        fixture
            .mock
            .fail("/item/public_token/exchange", 400, "INVALID_PUBLIC_TOKEN");
        let body = run(&fixture.schema, Role::Admin, CONNECT).await;
        assert_eq!(code(&body), Some("PLAID_ERROR"), "{body}");
        assert_eq!(
            body["errors"][0]["extensions"]["plaidCode"],
            "INVALID_PUBLIC_TOKEN"
        );
        assert!(!body.to_string().contains(ERROR_MESSAGE_MARKER), "{body}");
    }
}
