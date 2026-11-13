//! Bank connections through Plaid (`docs/build-log/007-plaid-commitments`,
//! step 5): open Link, connect a bank, list connected banks, disconnect one.
//!
//! One node per company holds them (`plaid.enabled` in that ledger's config;
//! [`crate::config::PlaidConfig`]). The access token Plaid issues for each
//! bank never leaves that node: it lives in the ledger's secret store
//! ([`crate::secret_store`]), is sent only to Plaid, and is never in a record,
//! a GraphQL response or a log line. Plaid's responses are read in memory,
//! capped, and dropped; only what [`connected_banks`](PlaidService::connections)
//! shows is kept, encrypted beside the token.
//!
//! **No bank is left live at Plaid with nothing holding it:**
//!
//! - a bank is removed at Plaid **before** its token is deleted here, and only
//!   "the item is not found" counts as already removed;
//! - a connect or disconnect runs on a task of its own, so a request cut short
//!   (`http.requestTimeoutSeconds`, a client that hangs up) never drops a
//!   token Plaid has just issued;
//! - the store lock is held for store work only, never across a call to Plaid;
//! - [`PlaidService::close`] waits for every connect and disconnect under way
//!   and refuses new ones: a ledger stops, restarts or is removed only after it,
//!   so a second store instance never opens beside a live one and a removal
//!   judges the store when nothing more can be added to it.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{info, warn, Instrument};
use zeroize::Zeroizing;

use crate::config::{PlaidConfig, PlaidEnvironment};
use crate::secret_store::{Secret, SecretStore, SecretStoreError, StoreKey};

/// Plaid's client id for the Company's Plaid account.
pub(crate) const CLIENT_ID_ENV_VAR: &str = "GL_NODE_PLAID_CLIENT_ID";
/// The Plaid secret that goes with it (sandbox or production, matching
/// `plaid.environment`).
pub(crate) const SECRET_ENV_VAR: &str = "GL_NODE_PLAID_SECRET";

/// Where every stored name starts: `plaid/items/<item id>/<what>`.
const ITEM_PREFIX: &str = "plaid/items/";

/// Plaid answers within seconds; a stalled connection must not hold up a
/// ledger's stop for long.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Plaid's answers are a few KB; anything past this is not one.
const MAX_ANSWER_BYTES: usize = 1024 * 1024;

/// The node's Plaid credentials, from the environment.
pub(crate) struct PlaidCredentials {
    client_id: String,
    secret: Secret,
}

impl fmt::Debug for PlaidCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlaidCredentials")
            .field("client_id", &self.client_id)
            .field("secret", &self.secret)
            .finish()
    }
}

impl PlaidCredentials {
    pub(crate) fn new(client_id: impl Into<String>, secret: Secret) -> Self {
        Self {
            client_id: client_id.into(),
            secret,
        }
    }
}

/// What the node brings to every Plaid-enabled ledger: the credentials and
/// the secret-store key, each from the environment, each optional until a
/// ledger turns Plaid on.
#[derive(Debug, Default)]
pub(crate) struct PlaidEnv {
    pub credentials: Option<Arc<PlaidCredentials>>,
    pub store_key: Option<Arc<StoreKey>>,
    /// Where Plaid is, for tests' loopback mock; [`Self::from_env`] never sets
    /// it, so a running node only ever calls `plaid.environment`'s host.
    pub base_url: Option<String>,
}

impl PlaidEnv {
    /// Read [`CLIENT_ID_ENV_VAR`], [`SECRET_ENV_VAR`] and the store key; an
    /// empty variable is an unset one. Both credentials or neither; a
    /// malformed key is refused here, at boot.
    pub(crate) fn from_env() -> Result<Self, String> {
        let read = |name: &str| match std::env::var(name) {
            Ok(value) => {
                let value = Zeroizing::new(value);
                Ok((!value.trim().is_empty()).then(|| Zeroizing::new(value.trim().to_owned())))
            }
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(format!("{name} is not valid text")),
        };
        let credentials = match (read(CLIENT_ID_ENV_VAR)?, read(SECRET_ENV_VAR)?) {
            (Some(client_id), Some(secret)) => Some(Arc::new(PlaidCredentials::new(
                client_id.as_str(),
                Secret::new(secret.as_str()),
            ))),
            (None, None) => None,
            _ => {
                return Err(format!(
                    "set both {CLIENT_ID_ENV_VAR} and {SECRET_ENV_VAR}, or neither"
                ))
            }
        };
        let store_key = match read(crate::secret_store::SECRETS_KEY_ENV_VAR)? {
            Some(text) => Some(Arc::new(
                StoreKey::from_hex(&text).map_err(|error| error.to_string())?,
            )),
            None => None,
        };
        Ok(Self {
            credentials,
            store_key,
            base_url: None,
        })
    }
}

/// A Plaid call or bank operation that did not succeed. Never carries Plaid's
/// message text, a request body or a token: only Plaid's error code, type and
/// request id.
#[derive(Debug)]
pub(crate) enum PlaidError {
    /// Plaid answered with an error.
    Api {
        status: u16,
        error_type: String,
        error_code: String,
        request_id: String,
    },
    /// No usable answer: connection, timeout, or a body that is not Plaid's.
    Transport(String),
    Store(SecretStoreError),
    /// Something Plaid sent that this node will not store.
    Unexpected(String),
    /// A token of another Plaid environment than `plaid.environment`: sent
    /// there, Plaid would call it invalid while the bank stays live where it
    /// was connected.
    WrongEnvironment {
        configured: PlaidEnvironment,
    },
    /// The ledger is stopping, restarting or being removed.
    Closing,
}

impl fmt::Display for PlaidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Api {
                status,
                error_type,
                error_code,
                request_id,
            } => write!(
                f,
                "Plaid refused the request: {error_code} ({error_type}, HTTP {status}, request id {request_id})"
            ),
            Self::Transport(detail) => write!(f, "Plaid could not be reached: {detail}"),
            Self::Store(error) => write!(f, "{error}"),
            Self::Unexpected(detail) => write!(f, "unexpected answer from Plaid: {detail}"),
            Self::WrongEnvironment { configured } => write!(
                f,
                "this bank's token is not from Plaid's {configured:?} environment (plaid.environment): \
                 set the environment it was connected in, or remove it from the Plaid Dashboard; \
                 nothing was changed"
            ),
            Self::Closing => f.write_str(
                "this ledger is stopping, restarting or being removed; try again once it is served",
            ),
        }
    }
}

impl std::error::Error for PlaidError {}

impl From<SecretStoreError> for PlaidError {
    fn from(error: SecretStoreError) -> Self {
        Self::Store(error)
    }
}

impl PlaidError {
    /// The GraphQL error code a client branches on.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Api { .. } => "PLAID_ERROR",
            Self::Transport(_) => "PLAID_UNREACHABLE",
            Self::Unexpected(_) => "PLAID_UNEXPECTED",
            Self::Store(_) => "SECRET_STORE",
            Self::WrongEnvironment { .. } => "PLAID_ENVIRONMENT",
            Self::Closing => "LEDGER_BUSY",
        }
    }

    /// Plaid's own error code, when Plaid gave one.
    pub(crate) fn plaid_code(&self) -> Option<&str> {
        match self {
            Self::Api { error_code, .. } => Some(error_code),
            _ => None,
        }
    }

    /// The item is already gone at Plaid: removing it again cannot succeed,
    /// and there is nothing left at Plaid to orphan. Only `ITEM_NOT_FOUND`:
    /// `INVALID_ACCESS_TOKEN` also answers a token of another environment or
    /// client id, whose bank can still be live.
    fn item_is_gone(&self) -> bool {
        self.plaid_code() == Some("ITEM_NOT_FOUND")
    }
}

#[derive(Deserialize)]
struct PlaidErrorBody {
    #[serde(default)]
    error_type: String,
    #[serde(default)]
    error_code: String,
    #[serde(default)]
    request_id: String,
}

/// reqwest's error and every cause under it (DNS, refused, TLS), without the
/// URL. No request body ever reaches an error.
fn transport(error: reqwest::Error) -> PlaidError {
    let error = error.without_url();
    let mut text = error.to_string();
    let mut cause = std::error::Error::source(&error);
    while let Some(next) = cause {
        text.push_str(": ");
        text.push_str(&next.to_string());
        cause = next.source();
    }
    PlaidError::Transport(text)
}

/// Plaid's HTTP API, for one environment.
pub(crate) struct PlaidClient {
    http: reqwest::Client,
    base_url: String,
    credentials: Arc<PlaidCredentials>,
}

impl PlaidClient {
    /// No proxy and no redirect: every call carries the secret, and goes to
    /// `base_url` or nowhere. HTTPS only, unless `base_url` is a test's
    /// loopback mock.
    pub(crate) fn new(base_url: &str, credentials: Arc<PlaidCredentials>) -> Result<Self, String> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|error| format!("TLS setup for Plaid: {error}"))?
            .with_root_certificates(rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
            .with_no_client_auth();
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(base_url.starts_with("https://"))
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .build()
            .map_err(|error| format!("HTTP client for Plaid: {error}"))?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_owned(),
            credentials,
        })
    }

    /// POST `body` plus the credentials to `path`, and read the answer as `T`.
    /// Neither the body nor the answer is ever logged.
    async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        mut body: Value,
    ) -> Result<T, PlaidError> {
        if let Value::Object(fields) = &mut body {
            fields.insert("client_id".to_owned(), json!(self.credentials.client_id));
            fields.insert("secret".to_owned(), json!(self.credentials.secret.expose()));
        }
        let mut response = self
            .http
            .post(format!("{}{path}", self.base_url))
            .json(&body)
            .send()
            .await
            .map_err(transport)?;
        drop(body);
        let status = response.status();
        let too_large =
            || PlaidError::Transport(format!("{path}: an answer over {MAX_ANSWER_BYTES} bytes"));
        if response
            .content_length()
            .is_some_and(|length| length > MAX_ANSWER_BYTES as u64)
        {
            return Err(too_large());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(transport)? {
            if bytes.len() + chunk.len() > MAX_ANSWER_BYTES {
                return Err(too_large());
            }
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            let error: PlaidErrorBody = serde_json::from_slice(&bytes).map_err(|_| {
                PlaidError::Transport(format!(
                    "HTTP {} with a body that is not Plaid's",
                    status.as_u16()
                ))
            })?;
            return Err(PlaidError::Api {
                status: status.as_u16(),
                error_type: error.error_type,
                error_code: error.error_code,
                request_id: error.request_id,
            });
        }
        serde_json::from_slice(&bytes)
            .map_err(|_| PlaidError::Transport(format!("{path}: an answer that is not Plaid's")))
    }
}

#[derive(Deserialize)]
struct LinkTokenCreated {
    link_token: String,
    expiration: String,
}

#[derive(Deserialize)]
struct TokenExchanged {
    access_token: String,
    item_id: String,
}

#[derive(Deserialize)]
struct AccountsGot {
    accounts: Vec<PlaidAccount>,
    item: PlaidItem,
}

#[derive(Deserialize)]
struct PlaidAccount {
    account_id: String,
    name: String,
    #[serde(default)]
    mask: Option<String>,
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    subtype: Option<String>,
}

#[derive(Deserialize)]
struct PlaidItem {
    #[serde(default)]
    institution_id: Option<String>,
}

#[derive(Deserialize)]
struct InstitutionGot {
    institution: Institution,
}

#[derive(Deserialize)]
struct Institution {
    name: String,
}

#[derive(Deserialize)]
struct Removed {}

/// A link token for the client app to open Plaid Link with.
#[derive(Debug, Clone)]
pub(crate) struct LinkToken {
    pub link_token: String,
    pub expiration: String,
}

/// One connected bank, as `connectedBanks` shows it: never a token. Unknown
/// fields are ignored, so a description a newer build wrote still reads after
/// a rollback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BankConnection {
    pub item_id: String,
    pub institution_name: Option<String>,
    /// The UTC date it was connected, `YYYY-MM-DD`; `None` when its
    /// description could not be stored or read.
    pub connected_on: Option<String>,
    pub accounts: Vec<BankAccount>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BankAccount {
    pub account_id: String,
    pub name: String,
    /// The last digits Plaid shows (2–4), never the full number.
    pub mask: Option<String>,
    pub kind: String,
    pub subtype: Option<String>,
}

impl BankConnection {
    /// What is known of an item whose description is missing or unreadable.
    fn bare(item_id: String) -> Self {
        Self {
            item_id,
            institution_name: None,
            connected_on: None,
            accounts: Vec::new(),
        }
    }
}

fn token_name(item_id: &str) -> String {
    format!("{ITEM_PREFIX}{item_id}/access_token")
}

fn info_name(item_id: &str) -> String {
    format!("{ITEM_PREFIX}{item_id}/info")
}

/// The item ids among a store's names (sorted, as a store lists them).
fn item_ids<'a>(names: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut ids: Vec<String> = names
        .filter_map(|name| name.strip_prefix(ITEM_PREFIX))
        .filter_map(|rest| rest.split_once('/'))
        .map(|(id, _)| id.to_owned())
        .collect();
    ids.dedup();
    ids
}

/// Plaid item and account ids are short alphanumeric strings; anything else is
/// refused before it becomes part of a stored name or a request.
fn check_id(what: &str, id: &str) -> Result<(), PlaidError> {
    let fine = (1..=128).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if fine {
        Ok(())
    } else {
        Err(PlaidError::Unexpected(format!(
            "{what} is not an id Plaid issues"
        )))
    }
}

/// How many banks the ledger folder holds, read without the key (company
/// removal refuses then: removing the folder would strand the items at Plaid).
pub(crate) fn connected_item_count(folder: &std::path::Path) -> Result<usize, SecretStoreError> {
    let names = SecretStore::stored_names(folder)?;
    Ok(item_ids(names.iter().map(String::as_str)).len())
}

/// The start of an access token Plaid issues in `environment`.
fn token_prefix(environment: PlaidEnvironment) -> &'static str {
    match environment {
        PlaidEnvironment::Sandbox => "access-sandbox-",
        PlaidEnvironment::Production => "access-production-",
    }
}

/// One ledger's bank connections on this node.
pub(crate) struct PlaidService {
    client: PlaidClient,
    client_name: String,
    environment: PlaidEnvironment,
    /// The ledger's one store instance (`crate::secret_store`): every read and
    /// write goes through this lock, held for store work only.
    store: tokio::sync::Mutex<SecretStore>,
    /// `true` once [`Self::close`] ran. Every connect and disconnect holds a
    /// read guard from start to end; `close` takes the write side.
    closed: tokio::sync::RwLock<bool>,
}

impl PlaidService {
    /// Start the service for ledger `ledger` in `folder`, or say why it cannot
    /// (the ledger is then not served: `plaid.enabled` promised connections it
    /// could not keep).
    pub(crate) fn start(
        ledger: &str,
        folder: &std::path::Path,
        config: &PlaidConfig,
        env: &PlaidEnv,
    ) -> Result<Self, String> {
        let base_url = env
            .base_url
            .as_deref()
            .unwrap_or(config.environment.base_url());
        Self::start_at(ledger, folder, config, env, base_url)
    }

    /// [`Self::start`] against `base_url`: Plaid's host, or a test's mock.
    pub(crate) fn start_at(
        ledger: &str,
        folder: &std::path::Path,
        config: &PlaidConfig,
        env: &PlaidEnv,
        base_url: &str,
    ) -> Result<Self, String> {
        let (Some(credentials), Some(key)) = (&env.credentials, &env.store_key) else {
            return Err(format!(
                "plaid.enabled needs {CLIENT_ID_ENV_VAR}, {SECRET_ENV_VAR} and {} in the node's environment",
                crate::secret_store::SECRETS_KEY_ENV_VAR
            ));
        };
        let store = SecretStore::open(folder, ledger, key).map_err(|error| error.to_string())?;
        let client = PlaidClient::new(base_url, Arc::clone(credentials))?;
        Ok(Self {
            client,
            client_name: config.client_name.clone(),
            environment: config.environment,
            store: tokio::sync::Mutex::new(store),
            closed: tokio::sync::RwLock::new(false),
        })
    }

    /// Wait for every connect and disconnect under way, then refuse new ones
    /// ([`PlaidError::Closing`]). Bounded by Plaid's timeouts: a connect
    /// makes at most three calls of [`REQUEST_TIMEOUT`] each, about 90 s.
    pub(crate) async fn close(&self) {
        *self.closed.write().await = true;
    }

    /// Whether [`Self::close`] ran and no [`Self::reopen`] since (tests).
    #[cfg(test)]
    pub(crate) async fn is_closed(&self) -> bool {
        *self.closed.read().await
    }

    /// Undo [`Self::close`]: a removal that was refused leaves the ledger
    /// serving as before.
    pub(crate) async fn reopen(&self) {
        *self.closed.write().await = false;
    }

    /// A link token for `client_user_id` (Plaid's stable, non-personal id for
    /// the person opening Link).
    pub(crate) async fn create_link_token(
        &self,
        client_user_id: &str,
    ) -> Result<LinkToken, PlaidError> {
        let created: LinkTokenCreated = self
            .client
            .call(
                "/link/token/create",
                json!({
                    "client_name": self.client_name,
                    "user": { "client_user_id": client_user_id },
                    "products": ["transactions"],
                    "country_codes": ["US"],
                    "language": "en",
                }),
            )
            .await?;
        Ok(LinkToken {
            link_token: created.link_token,
            expiration: created.expiration,
        })
    }

    /// Connect the bank Link returned `public_token` for, on a task of its
    /// own: the caller going away does not stop it.
    pub(crate) async fn connect(
        self: &Arc<Self>,
        public_token: String,
    ) -> Result<BankConnection, PlaidError> {
        let service = Arc::clone(self);
        let task = tokio::spawn(
            async move { service.connect_to_the_end(&public_token).await }.in_current_span(),
        );
        task.await
            .map_err(|error| PlaidError::Unexpected(format!("the connect task ended: {error}")))?
    }

    /// Exchange the public token for an access token, keep it, and describe
    /// the bank. The token is stored before anything else is asked of Plaid,
    /// so no later failure can leave an item nobody holds; a token that cannot
    /// be stored (or is not of this environment) is removed at Plaid again.
    async fn connect_to_the_end(&self, public_token: &str) -> Result<BankConnection, PlaidError> {
        let closed = self.closed.read().await;
        if *closed {
            return Err(PlaidError::Closing);
        }
        let exchanged: TokenExchanged = self
            .client
            .call(
                "/item/public_token/exchange",
                json!({ "public_token": public_token }),
            )
            .await?;
        let access_token = Secret::new(exchanged.access_token);
        let item_id = exchanged.item_id;
        let refused = if let Err(error) = check_id("item_id", &item_id) {
            Some(error)
        } else if !access_token
            .expose()
            .starts_with(token_prefix(self.environment))
        {
            Some(PlaidError::WrongEnvironment {
                configured: self.environment,
            })
        } else {
            self.store
                .lock()
                .await
                .put(&token_name(&item_id), &access_token)
                .err()
                .map(PlaidError::from)
        };
        if let Some(error) = refused {
            self.remove_at_plaid_after_failure(&access_token, &item_id)
                .await;
            return Err(error);
        }

        let mut connection = BankConnection {
            connected_on: Some(chrono::Utc::now().date_naive().to_string()),
            ..BankConnection::bare(item_id.clone())
        };
        match self.describe(&access_token).await {
            Ok((institution_name, accounts)) => {
                connection.institution_name = institution_name;
                connection.accounts = accounts;
            }
            Err(error) => {
                warn!(
                    item_id = %item_id,
                    code = error.plaid_code().unwrap_or("-"),
                    "connected a bank, but Plaid did not describe its accounts"
                );
            }
        }
        // The token is kept: a description that cannot be stored is logged,
        // not reported as a failed connect (the caller would link it again).
        if let Err(error) = self.store_info(&connection).await {
            warn!(item_id = %item_id, %error, "connected a bank, but its description was not stored");
        }
        drop(closed);
        info!(
            item_id = %item_id,
            accounts = connection.accounts.len(),
            "bank connected through Plaid"
        );
        Ok(connection)
    }

    /// The bank's name and accounts, for `connectedBanks`.
    async fn describe(
        &self,
        access_token: &Secret,
    ) -> Result<(Option<String>, Vec<BankAccount>), PlaidError> {
        let got: AccountsGot = self
            .client
            .call(
                "/accounts/get",
                json!({ "access_token": access_token.expose() }),
            )
            .await?;
        let mut accounts = Vec::with_capacity(got.accounts.len());
        for account in got.accounts {
            check_id("account_id", &account.account_id)?;
            accounts.push(BankAccount {
                account_id: account.account_id,
                name: account.name,
                mask: account.mask,
                kind: account.kind,
                subtype: account.subtype,
            });
        }
        let institution_name = match got.item.institution_id {
            Some(institution_id) => {
                let got: InstitutionGot = self
                    .client
                    .call(
                        "/institutions/get_by_id",
                        json!({ "institution_id": institution_id, "country_codes": ["US"] }),
                    )
                    .await?;
                Some(got.institution.name)
            }
            None => None,
        };
        Ok((institution_name, accounts))
    }

    async fn store_info(&self, connection: &BankConnection) -> Result<(), PlaidError> {
        let text = serde_json::to_string(connection)
            .map_err(|error| PlaidError::Unexpected(error.to_string()))?;
        self.store
            .lock()
            .await
            .put(&info_name(&connection.item_id), &Secret::new(text))?;
        Ok(())
    }

    /// Best effort, after a connect that cannot keep the token: remove the
    /// item at Plaid so it is not left live with no holder.
    async fn remove_at_plaid_after_failure(&self, access_token: &Secret, item_id: &str) {
        if let Err(error) = self.remove_at_plaid(access_token).await {
            warn!(item_id = %item_id, %error, "a bank connection could not be kept, and removing it at Plaid failed too: remove it from the Plaid Dashboard");
        }
    }

    async fn remove_at_plaid(&self, access_token: &Secret) -> Result<Removed, PlaidError> {
        self.client
            .call(
                "/item/remove",
                json!({ "access_token": access_token.expose() }),
            )
            .await
    }

    /// Every connected bank, by item id. A description that cannot be read is
    /// logged and the bank listed bare, so one bad entry hides no other bank.
    pub(crate) async fn connections(&self) -> Result<Vec<BankConnection>, PlaidError> {
        let store = self.store.lock().await;
        let mut connections = Vec::new();
        for item_id in item_ids(store.names()) {
            let described = store
                .get(&info_name(&item_id))
                .map(|text| text.map(|text| serde_json::from_str::<BankConnection>(text.expose())));
            let connection = match described {
                Ok(Some(Ok(connection))) => connection,
                Ok(None) => BankConnection::bare(item_id),
                Ok(Some(Err(error))) => {
                    warn!(item_id = %item_id, %error, "a stored bank description does not read");
                    BankConnection::bare(item_id)
                }
                Err(error) => {
                    warn!(item_id = %item_id, %error, "a stored bank description does not open");
                    BankConnection::bare(item_id)
                }
            };
            connections.push(connection);
        }
        Ok(connections)
    }

    /// Disconnect `item_id` on a task of its own: removed at Plaid, then its
    /// description and token deleted here. `Ok(false)` when this ledger has
    /// no such bank.
    pub(crate) async fn disconnect(self: &Arc<Self>, item_id: String) -> Result<bool, PlaidError> {
        let service = Arc::clone(self);
        let task = tokio::spawn(
            async move { service.disconnect_to_the_end(&item_id).await }.in_current_span(),
        );
        task.await.map_err(|error| {
            PlaidError::Unexpected(format!("the disconnect task ended: {error}"))
        })?
    }

    /// When Plaid refuses (other than "not found"), or the token is of another
    /// environment, nothing is deleted, so the call can be repeated.
    async fn disconnect_to_the_end(&self, item_id: &str) -> Result<bool, PlaidError> {
        let closed = self.closed.read().await;
        if *closed {
            return Err(PlaidError::Closing);
        }
        if check_id("item_id", item_id).is_err() {
            return Ok(false);
        }
        let Some(access_token) = self.store.lock().await.get(&token_name(item_id))? else {
            return Ok(false);
        };
        if !access_token
            .expose()
            .starts_with(token_prefix(self.environment))
        {
            return Err(PlaidError::WrongEnvironment {
                configured: self.environment,
            });
        }
        let removed: Result<Removed, PlaidError> = self.remove_at_plaid(&access_token).await;
        match removed {
            Ok(_) => {}
            Err(error) if error.item_is_gone() => {
                info!(item_id = %item_id, "Plaid no longer has this bank; deleting it here");
            }
            Err(error) => return Err(error),
        }
        // The description first: a failure between the two leaves the token,
        // which a repeated call finds and finishes.
        let mut store = self.store.lock().await;
        store.remove(&info_name(item_id))?;
        store.remove(&token_name(item_id))?;
        drop(store);
        drop(closed);
        info!(item_id = %item_id, "bank disconnected");
        Ok(true)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    use axum::extract::State;
    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::{Json, Router};

    pub(crate) const ACCESS_TOKEN: &str = "access-sandbox-11111111-2222-3333-4444-555555555555";
    pub(crate) const ITEM_ID: &str = "eVBnVMp7zdTJLkRNr33Rs6zr7KNJqBFL9DrE6";
    pub(crate) const CLIENT_SECRET: &str = "plaid-test-secret-0123456789abcdef";
    /// Text a Plaid error body carries that must never reach a caller or a log.
    pub(crate) const ERROR_MESSAGE_MARKER: &str =
        "the provided access token is confidential-marker";

    /// A loopback stand-in for Plaid's API: records every call, and answers as
    /// [`MockPlaid::fail`], [`MockPlaid::delay`] and [`MockPlaid::pad`] say.
    #[derive(Clone, Default)]
    pub(crate) struct MockPlaid {
        pub calls: Arc<Mutex<Vec<(String, Value)>>>,
        /// Path → (HTTP status, Plaid error code) to answer with instead.
        pub fail: Arc<Mutex<HashMap<String, (u16, String)>>>,
        /// Path → how long to wait before answering.
        pub delay: Arc<Mutex<HashMap<String, Duration>>>,
        /// Paths whose answer is padded past the client's cap.
        pub pad: Arc<Mutex<HashSet<String>>>,
    }

    impl MockPlaid {
        pub(crate) fn fail(&self, path: &str, status: u16, code: &str) {
            self.fail
                .lock()
                .unwrap()
                .insert(path.to_owned(), (status, code.to_owned()));
        }

        pub(crate) fn delay(&self, path: &str, wait: Duration) {
            self.delay.lock().unwrap().insert(path.to_owned(), wait);
        }

        pub(crate) fn pad(&self, path: &str) {
            self.pad.lock().unwrap().insert(path.to_owned());
        }

        pub(crate) fn paths(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .map(|(path, _)| path.clone())
                .collect()
        }

        pub(crate) fn body_of(&self, path: &str) -> Option<Value> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|(called, _)| called == path)
                .map(|(_, body)| body.clone())
        }

        /// Serve on 127.0.0.1 and return the base URL.
        pub(crate) async fn serve(&self) -> String {
            async fn answer(
                State((mock, path)): State<(MockPlaid, &'static str)>,
                Json(body): Json<Value>,
            ) -> (StatusCode, Json<Value>) {
                mock.calls.lock().unwrap().push((path.to_owned(), body));
                let wait = mock.delay.lock().unwrap().get(path).copied();
                if let Some(wait) = wait {
                    tokio::time::sleep(wait).await;
                }
                let failure = mock.fail.lock().unwrap().get(path).cloned();
                if let Some((status, code)) = failure {
                    return (
                        StatusCode::from_u16(status).unwrap(),
                        Json(json!({
                            "error_type": "ITEM_ERROR",
                            "error_code": code,
                            "error_message": ERROR_MESSAGE_MARKER,
                            "display_message": null,
                            "request_id": "req-mock",
                        })),
                    );
                }
                let mut answer = match path {
                    "/link/token/create" => json!({
                        "link_token": "link-sandbox-abc",
                        "expiration": "2026-11-13T18:00:00Z",
                        "request_id": "req-1",
                    }),
                    "/item/public_token/exchange" => json!({
                        "access_token": ACCESS_TOKEN,
                        "item_id": ITEM_ID,
                        "request_id": "req-2",
                    }),
                    "/accounts/get" => json!({
                        "accounts": [
                            { "account_id": "acc1", "name": "Plaid Checking", "mask": "0000",
                              "type": "depository", "subtype": "checking", "balances": {} },
                            { "account_id": "acc2", "name": "Plaid Saving", "mask": "1111",
                              "type": "depository", "subtype": "savings", "balances": {} },
                        ],
                        "item": { "item_id": ITEM_ID, "institution_id": "ins_109508" },
                        "request_id": "req-3",
                    }),
                    "/institutions/get_by_id" => json!({
                        "institution": { "institution_id": "ins_109508", "name": "First Platypus Bank" },
                        "request_id": "req-4",
                    }),
                    "/item/remove" => json!({ "request_id": "req-5" }),
                    _ => json!({}),
                };
                if mock.pad.lock().unwrap().contains(path) {
                    answer["padding"] = json!("x".repeat(2 * 1024 * 1024));
                }
                (StatusCode::OK, Json(answer))
            }
            let mut app = Router::new();
            for path in [
                "/link/token/create",
                "/item/public_token/exchange",
                "/accounts/get",
                "/institutions/get_by_id",
                "/item/remove",
            ] {
                app = app.route(path, post(answer).with_state((self.clone(), path)));
            }
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            tokio::spawn(async move {
                axum::serve(listener, app).await.unwrap();
            });
            format!("http://{address}")
        }
    }

    pub(crate) fn env() -> PlaidEnv {
        PlaidEnv {
            credentials: Some(Arc::new(PlaidCredentials::new(
                "client-id-test",
                Secret::new(CLIENT_SECRET),
            ))),
            store_key: Some(Arc::new(StoreKey::generate())),
            base_url: None,
        }
    }

    pub(crate) fn enabled() -> PlaidConfig {
        PlaidConfig {
            enabled: true,
            ..PlaidConfig::default()
        }
    }

    async fn service(
        mock: &MockPlaid,
        folder: &std::path::Path,
        env: &PlaidEnv,
    ) -> Arc<PlaidService> {
        service_in(mock, folder, env, enabled()).await
    }

    async fn service_in(
        mock: &MockPlaid,
        folder: &std::path::Path,
        env: &PlaidEnv,
        config: PlaidConfig,
    ) -> Arc<PlaidService> {
        let url = mock.serve().await;
        Arc::new(
            PlaidService::start_at("acme", folder, &config, env, &url).expect("start the service"),
        )
    }

    fn connect_token() -> String {
        "public-sandbox-xyz".to_owned()
    }

    /// Connecting a bank exchanges the public token, keeps the access token in
    /// the store, and describes the bank's accounts — without the token.
    ///
    /// Bug-catch: a connect that does not store the token loses the bank at
    /// the next restart.
    #[tokio::test]
    async fn connect_keeps_the_token_and_describes_the_bank() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let env = env();
        let plaid = service(&mock, dir.path(), &env).await;

        let connection = plaid.connect(connect_token()).await.unwrap();
        assert_eq!(connection.item_id, ITEM_ID);
        assert_eq!(
            connection.institution_name.as_deref(),
            Some("First Platypus Bank")
        );
        assert_eq!(connection.accounts.len(), 2);
        assert_eq!(connection.accounts[0].mask.as_deref(), Some("0000"));
        assert_eq!(
            mock.body_of("/item/public_token/exchange").unwrap()["public_token"],
            "public-sandbox-xyz"
        );

        drop(plaid);
        let key = env.store_key.as_ref().unwrap();
        let store = SecretStore::open(dir.path(), "acme", key).unwrap();
        assert_eq!(
            store.get(&token_name(ITEM_ID)).unwrap().unwrap().expose(),
            ACCESS_TOKEN
        );
        let info = store.get(&info_name(ITEM_ID)).unwrap().unwrap();
        assert!(!info.expose().contains(ACCESS_TOKEN));
    }

    /// A connect whose caller goes away mid-exchange still keeps the token.
    ///
    /// Bug-catch: running the connect in the request's own task drops the
    /// token Plaid has just issued when the request is cut short, leaving the
    /// item live at Plaid with nobody holding it.
    #[tokio::test]
    async fn a_connect_cut_short_still_keeps_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        mock.delay("/item/public_token/exchange", Duration::from_millis(300));
        let plaid = service(&mock, dir.path(), &env()).await;

        let cut =
            tokio::time::timeout(Duration::from_millis(50), plaid.connect(connect_token())).await;
        assert!(cut.is_err(), "the caller gave up first");
        for _ in 0..50 {
            if connected_item_count(dir.path()).unwrap() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(connected_item_count(dir.path()).unwrap(), 1);
    }

    /// A disconnect whose caller goes away mid-removal still finishes: the
    /// bank is removed at Plaid and its token deleted here.
    ///
    /// Bug-catch: running the disconnect in the request's own task leaves the
    /// token behind for a bank Plaid has already removed.
    #[tokio::test]
    async fn a_disconnect_cut_short_still_finishes() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        plaid.connect(connect_token()).await.unwrap();
        mock.delay("/item/remove", Duration::from_millis(300));

        let cut = tokio::time::timeout(
            Duration::from_millis(50),
            plaid.disconnect(ITEM_ID.to_owned()),
        )
        .await;
        assert!(cut.is_err(), "the caller gave up first");
        for _ in 0..50 {
            if connected_item_count(dir.path()).unwrap() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(connected_item_count(dir.path()).unwrap(), 0);
    }

    /// Every call carries the credentials, and the link token asks for
    /// transactions under the configured client name.
    ///
    /// Bug-catch: a call without `client_id`/`secret` is refused by Plaid.
    #[tokio::test]
    async fn calls_carry_the_credentials_and_the_link_settings() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;

        let token = plaid.create_link_token("u_0123456789abcdef").await.unwrap();
        assert_eq!(token.link_token, "link-sandbox-abc");
        let body = mock.body_of("/link/token/create").unwrap();
        assert_eq!(body["client_id"], "client-id-test");
        assert_eq!(body["secret"], CLIENT_SECRET);
        assert_eq!(body["client_name"], "NewGL");
        assert_eq!(body["products"], json!(["transactions"]));
        assert_eq!(body["user"]["client_user_id"], "u_0123456789abcdef");
    }

    /// Disconnecting removes the item at Plaid, then deletes token and
    /// description here.
    ///
    /// Bug-catch: deleting the token without `/item/remove` leaves the item
    /// live at Plaid with nothing able to remove it.
    #[tokio::test]
    async fn disconnect_removes_at_plaid_then_here() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        plaid.connect(connect_token()).await.unwrap();

        assert!(plaid.disconnect(ITEM_ID.to_owned()).await.unwrap());
        assert_eq!(
            mock.body_of("/item/remove").unwrap()["access_token"],
            ACCESS_TOKEN
        );
        assert!(plaid.connections().await.unwrap().is_empty());
        assert_eq!(connected_item_count(dir.path()).unwrap(), 0);
        assert!(!plaid.disconnect(ITEM_ID.to_owned()).await.unwrap());
    }

    /// When Plaid refuses the removal, the token stays, so it can be retried.
    ///
    /// Bug-catch: deleting the token whatever Plaid answered strands the item.
    #[tokio::test]
    async fn disconnect_keeps_the_token_when_plaid_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        plaid.connect(connect_token()).await.unwrap();
        mock.fail("/item/remove", 500, "INTERNAL_SERVER_ERROR");

        let error = plaid.disconnect(ITEM_ID.to_owned()).await.unwrap_err();
        assert_eq!(error.plaid_code(), Some("INTERNAL_SERVER_ERROR"));
        assert_eq!(plaid.connections().await.unwrap().len(), 1);
        assert_eq!(connected_item_count(dir.path()).unwrap(), 1);
    }

    /// An item Plaid does not find is deleted here too; an "invalid token"
    /// answer is not taken for that.
    ///
    /// Bug-catch: treating `INVALID_ACCESS_TOKEN` as gone deletes the token of
    /// a bank still live at Plaid (another environment, another client id).
    #[tokio::test]
    async fn only_item_not_found_counts_as_already_removed() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        plaid.connect(connect_token()).await.unwrap();

        mock.fail("/item/remove", 400, "INVALID_ACCESS_TOKEN");
        assert!(plaid.disconnect(ITEM_ID.to_owned()).await.is_err());
        assert_eq!(connected_item_count(dir.path()).unwrap(), 1);

        mock.fail("/item/remove", 400, "ITEM_NOT_FOUND");
        assert!(plaid.disconnect(ITEM_ID.to_owned()).await.unwrap());
        assert!(plaid.connections().await.unwrap().is_empty());
    }

    /// A token of another environment is never sent there: a connect that
    /// gets one removes it at Plaid, and a disconnect refuses it untouched.
    ///
    /// Bug-catch: without the check, `plaid.environment` changed after a bank
    /// was connected makes `disconnectBank` ask the wrong Plaid, which cannot
    /// remove the bank.
    #[tokio::test]
    async fn a_token_of_another_environment_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let env = env();
        let production = PlaidConfig {
            environment: PlaidEnvironment::Production,
            ..enabled()
        };

        let plaid = service_in(&mock, dir.path(), &env, production.clone()).await;
        let error = plaid.connect(connect_token()).await.unwrap_err();
        assert!(
            matches!(error, PlaidError::WrongEnvironment { .. }),
            "{error}"
        );
        assert_eq!(
            mock.body_of("/item/remove").unwrap()["access_token"],
            ACCESS_TOKEN
        );
        assert_eq!(connected_item_count(dir.path()).unwrap(), 0);
        drop(plaid);

        let sandbox = service(&mock, dir.path(), &env).await;
        sandbox.connect(connect_token()).await.unwrap();
        sandbox.close().await;
        drop(sandbox);
        let calls = mock.paths().len();
        let plaid = service_in(&mock, dir.path(), &env, production).await;
        let error = plaid.disconnect(ITEM_ID.to_owned()).await.unwrap_err();
        assert!(
            matches!(error, PlaidError::WrongEnvironment { .. }),
            "{error}"
        );
        assert_eq!(mock.paths().len(), calls, "nothing sent to Plaid");
        assert_eq!(connected_item_count(dir.path()).unwrap(), 1);
    }

    /// `close` waits for a connect under way, then refuses new ones until
    /// `reopen`.
    ///
    /// Bug-catch: a close that does not wait lets a removal judge the store
    /// while a connect is about to add a token to it.
    #[tokio::test]
    async fn close_waits_for_the_connect_under_way() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        mock.delay("/item/public_token/exchange", Duration::from_millis(200));
        let plaid = service(&mock, dir.path(), &env()).await;

        let connecting = tokio::spawn({
            let plaid = Arc::clone(&plaid);
            async move { plaid.connect(connect_token()).await }
        });
        while mock.paths().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        plaid.close().await;
        assert_eq!(connected_item_count(dir.path()).unwrap(), 1, "close waited");
        assert!(connecting.await.unwrap().is_ok());

        let error = plaid.disconnect(ITEM_ID.to_owned()).await.unwrap_err();
        assert!(matches!(error, PlaidError::Closing), "{error}");
        plaid.reopen().await;
        assert!(plaid.disconnect(ITEM_ID.to_owned()).await.unwrap());
    }

    /// A Plaid error reports Plaid's code and request id, never its message.
    ///
    /// Bug-catch: echoing Plaid's `error_message` passes whatever it quotes on
    /// to callers and logs.
    #[tokio::test]
    async fn plaid_errors_name_the_code_not_the_message() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        mock.fail("/item/public_token/exchange", 400, "INVALID_PUBLIC_TOKEN");

        let error = plaid.connect(connect_token()).await.unwrap_err();
        let text = error.to_string();
        assert!(text.contains("INVALID_PUBLIC_TOKEN"), "{text}");
        assert!(text.contains("req-mock"), "{text}");
        assert!(!text.contains(ERROR_MESSAGE_MARKER), "{text}");
        assert!(!format!("{error:?}").contains(ERROR_MESSAGE_MARKER));
        assert_eq!(connected_item_count(dir.path()).unwrap(), 0);
    }

    /// A bank Plaid cannot describe is still kept: the token is the part that
    /// must not be lost. An answer past the size cap is one Plaid did not give.
    ///
    /// Bug-catch: failing the connect after the exchange leaves a live item
    /// at Plaid this node no longer lists; reading an answer without a cap
    /// buffers whatever arrives.
    #[tokio::test]
    async fn a_bank_plaid_cannot_describe_is_still_kept() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        mock.fail("/accounts/get", 400, "PRODUCT_NOT_READY");

        let connection = plaid.connect(connect_token()).await.unwrap();
        assert!(connection.accounts.is_empty());
        assert_eq!(plaid.connections().await.unwrap(), vec![connection]);

        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        mock.pad("/accounts/get");
        let plaid = service(&mock, dir.path(), &env()).await;
        let connection = plaid.connect(connect_token()).await.unwrap();
        assert!(
            connection.accounts.is_empty(),
            "the padded answer was refused"
        );
    }

    /// A ledger with Plaid on, on a node without the credentials or the key,
    /// is refused, naming all three variables.
    ///
    /// Bug-catch: a refusal that does not name what is missing leaves the
    /// operator guessing which of three variables to set.
    #[test]
    fn start_needs_the_credentials_and_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let full = env();
        for env in [
            PlaidEnv::default(),
            PlaidEnv {
                credentials: full.credentials.clone(),
                store_key: None,
                base_url: None,
            },
            PlaidEnv {
                credentials: None,
                store_key: full.store_key.clone(),
                base_url: None,
            },
        ] {
            let error =
                PlaidService::start_at("acme", dir.path(), &enabled(), &env, "http://127.0.0.1:9")
                    .err()
                    .expect("refused");
            for name in [
                CLIENT_ID_ENV_VAR,
                SECRET_ENV_VAR,
                crate::secret_store::SECRETS_KEY_ENV_VAR,
            ] {
                assert!(error.contains(name), "{error}");
            }
        }
    }

    /// The credentials print without the secret.
    ///
    /// Bug-catch: a derived `Debug` holding the secret as a `String`.
    #[test]
    fn credentials_print_without_the_secret() {
        let env = env();
        assert!(!format!("{env:?}").contains(CLIENT_SECRET));
    }

    /// Ids that are not Plaid's are refused before they name anything stored.
    ///
    /// Bug-catch: an item id with `/` reaching another item's stored names.
    #[test]
    fn ids_are_checked() {
        assert!(check_id("item_id", ITEM_ID).is_ok());
        for bad in ["", "a/b", "../x", &"a".repeat(129), "a b"] {
            assert!(check_id("item_id", bad).is_err(), "{bad:?}");
        }
    }
}
