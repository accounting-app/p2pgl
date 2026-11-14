//! Bank connections through Plaid (`docs/build-log/007-plaid-commitments`,
//! steps 5 to 6c): open Link (a new bank, or logging in again to one), connect
//! a bank, list connected banks and their health, disconnect one, read its
//! accounts again, map and unmap them, page its transactions in, and — in
//! Plaid's sandbox — connect a test bank or reset its login for demos.
//!
//! One node per company holds them (`plaid.enabled` in that ledger's config;
//! [`crate::config::PlaidConfig`]). The access token Plaid issues for each
//! bank never leaves that node: it lives in the ledger's secret store
//! ([`crate::secret_store`]), is sent only to Plaid, and is never in a record,
//! a GraphQL response or a log line. Plaid's responses are read in memory,
//! capped, and dropped; only what [`connected_banks`](PlaidService::connections)
//! shows (with each account's mapping) and each bank's sync cursor are kept,
//! encrypted beside the token. The import itself (one entry per posted
//! transaction) is `crate::graphql::plaid`'s; this module fetches the pages
//! ([`PlaidService::next_page`]) and stores where a sync stands
//! ([`PlaidService::commit_page`]).
//!
//! **No bank is left live at Plaid with nothing holding it:**
//!
//! - a bank is removed at Plaid **before** its token is deleted here, and only
//!   "the item is not found" counts as already removed;
//! - a connect or disconnect runs on a task of its own, so a request cut short
//!   (`http.requestTimeoutSeconds`, a client that hangs up) never drops a
//!   token Plaid has just issued;
//! - the store lock is held for store work only, never across a call to Plaid;
//! - [`PlaidService::close`] waits for every bank operation under way (a
//!   connect, a disconnect, a mapping or unmapping, an accounts refresh, a
//!   page fetched or stored, a health note) and refuses
//!   new ones: a ledger stops, restarts or is removed only after it,
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
    /// Plaid's webhook keys, one set for every ledger on the node in each
    /// Plaid environment (step 6e).
    pub webhook_keys: NodeWebhookKeys,
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
            webhook_keys: NodeWebhookKeys::default(),
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
    /// The bank Link just connected is one this ledger holds already (same
    /// institution, same accounts): the new connection was removed at Plaid,
    /// so its transactions are not imported twice.
    AlreadyConnected {
        item_id: String,
    },
    /// No such bank, or no such account of it, on this ledger.
    NoSuchBank(String),
    /// The bank is being synced: a mapping changed under a sync would be lost.
    SyncInProgress,
    /// A helper of Plaid's sandbox, asked of a ledger on another environment.
    SandboxOnly,
    /// A webhook mutation on a ledger with no `plaid.webhookUrl`.
    NoWebhookUrl,
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
            Self::AlreadyConnected { item_id } => write!(
                f,
                "this bank is connected already (item {item_id}); the new connection was \
                 removed at Plaid"
            ),
            Self::NoSuchBank(what) => write!(f, "{what}"),
            Self::SyncInProgress => f.write_str(
                "this bank is being synced; try again once the sync ends",
            ),
            Self::SandboxOnly => f.write_str(
                "this is a helper of Plaid's sandbox, and this ledger is not on it (plaid.environment)",
            ),
            Self::NoWebhookUrl => f.write_str(
                "this ledger has no plaid.webhookUrl: set it in its config and restart it",
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
            Self::AlreadyConnected { .. } => "BANK_ALREADY_CONNECTED",
            Self::NoSuchBank(_) => "NO_SUCH_BANK",
            Self::SyncInProgress => "SYNC_IN_PROGRESS",
            Self::SandboxOnly => "PLAID_SANDBOX_ONLY",
            Self::NoWebhookUrl => "PLAID_NO_WEBHOOK_URL",
        }
    }

    /// Plaid's own error code, when Plaid gave one.
    pub(crate) fn plaid_code(&self) -> Option<&str> {
        match self {
            Self::Api { error_code, .. } => Some(error_code),
            _ => None,
        }
    }

    /// Plaid refused for good (a 4xx other than 429), or answered with
    /// something unusable: not worth asking again soon.
    fn is_definite_refusal(&self) -> bool {
        match self {
            Self::Api { status, .. } => (400..500).contains(status) && *status != 429,
            Self::Unexpected(_) => true,
            _ => false,
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

#[derive(Deserialize)]
struct SandboxPublicToken {
    public_token: String,
}

#[derive(Deserialize)]
struct VerificationKeyGot {
    key: VerificationKey,
}

/// A JWK as Plaid gives its webhook verification keys.
#[derive(Deserialize)]
struct VerificationKey {
    alg: String,
    kid: String,
    crv: String,
    kty: String,
    x: String,
    y: String,
    #[serde(default)]
    expired_at: Option<i64>,
}

/// The most `/transactions/sync` pages one sync reads: years of a
/// busy account's history fit; a loop that never ends does not.
const MAX_SYNC_PAGES: usize = 1000;

/// Transactions per `/transactions/sync` page: Plaid's default. A full
/// transaction is 1.5–2 KB of JSON, so 100 stay well under
/// [`MAX_ANSWER_BYTES`]; 500 (Plaid's most) may not.
const SYNC_PAGE_SIZE: usize = 100;

/// One `/transactions/sync` page. Its transactions are read one by one
/// ([`SyncTransaction`]), so one Plaid sends malformed is noted, not a page
/// that fails — every later sync would stop on it.
#[derive(Deserialize)]
struct SyncPage {
    #[serde(default)]
    added: Vec<Value>,
    #[serde(default)]
    modified: Vec<Value>,
    #[serde(default)]
    removed: Vec<Value>,
    next_cursor: String,
    has_more: bool,
}

#[derive(Deserialize)]
struct SyncTransaction {
    transaction_id: String,
    account_id: String,
    /// Plaid's sign: positive is money out of the account.
    amount: serde_json::Number,
    #[serde(default)]
    iso_currency_code: Option<String>,
    #[serde(default)]
    unofficial_currency_code: Option<String>,
    /// The date the bank posted it.
    date: chrono::NaiveDate,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    merchant_name: Option<String>,
    #[serde(default)]
    pending: bool,
}

#[derive(Deserialize)]
struct SyncRemoved {
    transaction_id: String,
}

/// What a change needs read: which transaction, and whether it is pending.
#[derive(Deserialize)]
struct SyncChanged {
    transaction_id: String,
    #[serde(default)]
    pending: bool,
}

/// The ledger's limits on a payee and a narration (`ledger`'s resource
/// limits): longer text is cut at a character boundary rather than refused,
/// which would stop every later sync of the bank at that entry.
const MAX_PAYEE_BYTES: usize = ledger::service::MAX_PAYEE_LENGTH;
const MAX_NARRATION_BYTES: usize = ledger::service::MAX_NARRATION_LENGTH;

fn cut(text: Option<String>, max: usize) -> Option<String> {
    text.map(|mut text| {
        if text.len() > max {
            let mut end = max;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        }
        text
    })
}

impl SyncTransaction {
    fn posted(self) -> Result<PostedTransaction, PlaidError> {
        check_id("transaction_id", &self.transaction_id)?;
        check_id("account_id", &self.account_id)?;
        let amount: rust_decimal::Decimal = self.amount.to_string().parse().map_err(|_| {
            PlaidError::Unexpected(format!(
                "transaction {}: an amount that is not a decimal",
                self.transaction_id
            ))
        })?;
        Ok(PostedTransaction {
            transaction_id: self.transaction_id,
            account_id: self.account_id,
            amount,
            currency: self.iso_currency_code.or(self.unofficial_currency_code),
            date: self.date,
            name: cut(self.name, MAX_NARRATION_BYTES),
            merchant_name: cut(self.merchant_name, MAX_PAYEE_BYTES),
        })
    }
}

/// A posted bank transaction, as Plaid gave it (in memory only).
#[derive(Debug, Clone)]
pub(crate) struct PostedTransaction {
    pub transaction_id: String,
    pub account_id: String,
    /// Plaid's sign: positive is money out of the account.
    pub amount: rust_decimal::Decimal,
    pub currency: Option<String>,
    pub date: chrono::NaiveDate,
    pub name: Option<String>,
    pub merchant_name: Option<String>,
}

/// One page of a bank's transactions ([`PlaidService::next_page`]).
#[derive(Debug, Default)]
pub(crate) struct Page {
    /// Posted transactions Plaid added, in Plaid's order.
    pub added: Vec<PostedTransaction>,
    /// Pending ones, skipped (decision 8).
    pub pending: usize,
    /// Posted transactions Plaid changed or removed since: for review, never
    /// reversed here. One id may come twice (changed, then removed); the
    /// sync notes each once.
    pub changed: Vec<String>,
    /// Transactions Plaid sent that this node cannot read (a field missing or
    /// of the wrong kind, an id or amount it will not store): Plaid's id when
    /// it is one this node can repeat, and what is wrong. Noted, not imported.
    pub unreadable: Vec<(Option<String>, String)>,
    /// Where this page leaves the bank, for [`PlaidService::commit_page`].
    pub next_cursor: String,
    /// Whether more pages follow; the last page's cursor is the one Plaid
    /// keeps valid, and a restart goes back to it.
    pub has_more: bool,
}

/// A sync of one bank under way: where it stands at Plaid and in the store
/// ([`PlaidService::begin_fetch`]).
pub(crate) struct SyncSession {
    item_id: String,
    access_token: Secret,
    /// The bank as stored when the sync began: its accounts and mappings
    /// (which cannot change while it runs: `mapBankAccount` waits for no sync
    /// and is refused instead).
    pub connection: BankConnection,
    /// The cursor stored now: the one the next [`PlaidService::commit_page`]
    /// must find.
    stored: Option<String>,
    /// The cursor of the last page of a finished series (`has_more` false),
    /// stored apart: Plaid asks for a restart from the first cursor of the
    /// series when the history moves while it is paged, and keeps only such
    /// cursors valid for long.
    series_start: Option<String>,
    /// Plaid made this sync start its pages again: what it sends again may
    /// differ from what was written before.
    pub restarted: bool,
    /// The cursor the next page is asked from.
    at: Option<String>,
    restarts: usize,
    pages: usize,
    done: bool,
}

impl SyncSession {
    /// The cursor the sync began at (tests).
    #[cfg(test)]
    pub(crate) fn began_at(&self) -> Option<&str> {
        self.series_start.as_deref()
    }
}
/// The most webhook verification keys asked of Plaid a minute, in all (step
/// 6d): a guard on the company's Plaid account.
const MAX_KEY_FETCHES_A_MINUTE: u32 = 60;

/// The most a minute one client's calls may have the node ask Plaid for:
/// Plaid sends from a handful of addresses, so a stranger's made-up key ids
/// spend that stranger's budget, not Plaid's.
const MAX_KEY_FETCHES_A_CLIENT_A_MINUTE: u32 = 10;

/// How long a cached webhook key is used before Plaid is asked about it
/// again (at most once a minute while it is stale): a key Plaid has since set
/// to expire is dropped at the next answer, and never trusted past
/// [`KEY_TRUSTED_UNCONFIRMED`].
const KEY_FRESH_FOR: Duration = Duration::from_secs(60 * 60);

/// How long a cached webhook key is used without Plaid confirming it — while
/// asking keeps failing, or cannot be done: past it the key is refused until
/// Plaid answers, so a key Plaid has rotated out is never trusted for long.
const KEY_TRUSTED_UNCONFIRMED: Duration = Duration::from_secs(24 * 60 * 60);

/// A webhook key Plaid gave, as an uncompressed P-256 point.
#[derive(Clone)]
struct CachedKey {
    /// When Plaid last gave it.
    fetched: std::time::Instant,
    /// When Plaid was last asked about it: once a minute at most.
    asked: std::time::Instant,
    point: Vec<u8>,
}

/// What [`PlaidService::cached_key`] has for a key id.
enum Cached {
    Fresh(Vec<u8>),
    /// Older than [`KEY_FRESH_FOR`]: the point while still usable, and
    /// whether this call is the one to ask Plaid about it again.
    Stale {
        point: Option<Vec<u8>>,
        ask_again: bool,
    },
    /// Refused by Plaid lately.
    Refused,
}

/// Plaid's webhook verification keys as a node knows them, and what asking
/// Plaid for them may cost (007 step 6e): one for the node, shared by every
/// ledger on it through [`PlaidEnv`], as the node holds one Plaid account —
/// a key is fetched once for every company, and the budgets bound what a
/// stranger can spend of the account however many companies are served.
#[derive(Default)]
pub(crate) struct WebhookKeys {
    /// The keys Plaid gave, by key id ([`PlaidService::verification_key`]).
    webhook_keys: std::sync::Mutex<std::collections::HashMap<String, CachedKey>>,
    /// Key ids Plaid would not give, and when: not asked again for five
    /// minutes, so a stranger's made-up key ids do not each cost a call.
    refused_keys: std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
    /// Key fetches in the current minute (when it started, how many): at most
    /// [`MAX_KEY_FETCHES_A_MINUTE`]. `None` before the first.
    key_fetches: std::sync::Mutex<Option<(std::time::Instant, u32)>>,
    /// Key fetches by client in its current minute.
    key_fetches_by_client:
        std::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (std::time::Instant, u32)>>,
    /// Key ids being fetched now.
    fetching_keys: std::sync::Mutex<std::collections::HashSet<String>>,
    /// One key fetch at a time.
    key_fetch: tokio::sync::Mutex<()>,
}

impl std::fmt::Debug for WebhookKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WebhookKeys { .. }")
    }
}

/// A node's [`WebhookKeys`], one set for each Plaid environment: a node serves
/// one environment at a time (`config::ledgers_in_conflict`), but it can move
/// from one to the other while it runs, and a sandbox key is never to verify
/// a production ledger's webhooks.
#[derive(Debug, Default)]
pub(crate) struct NodeWebhookKeys {
    sandbox: Arc<WebhookKeys>,
    production: Arc<WebhookKeys>,
}

impl NodeWebhookKeys {
    /// The keys of Plaid's `environment`.
    pub(crate) fn of(&self, environment: PlaidEnvironment) -> &Arc<WebhookKeys> {
        match environment {
            PlaidEnvironment::Sandbox => &self.sandbox,
            PlaidEnvironment::Production => &self.production,
        }
    }
}

/// What [`PlaidService::verification_key`] has for a key id.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KeyLookup {
    Found(Vec<u8>),
    /// Being fetched (or just set to be): the call is refused, Plaid's
    /// redelivery finds it.
    Pending,
    /// Refused by Plaid lately, unusable, or past the budget.
    Refused,
}

/// A bank with a webhook sync queued ([`PlaidService::queue_webhook_sync`]);
/// the mark is dropped with it, unless [`Self::go_again`] dropped it first.
pub(crate) struct QueuedSync {
    service: Arc<PlaidService>,
    item_id: String,
    /// The mark is dropped already: a later webhook's mark is not this one's.
    ended: bool,
}

impl QueuedSync {
    /// Whether the sync is to go once more (a webhook came while it ran);
    /// when not, the mark is dropped here, under the lock, so a webhook after
    /// this queues a sync of its own and this guard leaves that one's mark.
    pub(crate) fn go_again(&mut self) -> bool {
        let Ok(mut queued) = self.service.webhook_syncs.lock() else {
            return false;
        };
        match queued.get_mut(&self.item_id) {
            Some(again) if *again => {
                *again = false;
                true
            }
            _ => {
                queued.remove(&self.item_id);
                self.ended = true;
                false
            }
        }
    }
}

impl Drop for QueuedSync {
    fn drop(&mut self) {
        if self.ended {
            return;
        }
        if let Ok(mut queued) = self.service.webhook_syncs.lock() {
            queued.remove(&self.item_id);
        }
    }
}

/// A bank marked as syncing ([`PlaidService::begin_sync`]); the mark is
/// dropped with it.
pub(crate) struct SyncGuard {
    service: Arc<PlaidService>,
    item_id: String,
}

impl Drop for SyncGuard {
    fn drop(&mut self) {
        if let Ok(mut syncing) = self.service.syncing.lock() {
            syncing.remove(&self.item_id);
        }
    }
}

/// A link token for the client app to open Plaid Link with.
#[derive(Debug, Clone)]
pub(crate) struct LinkToken {
    pub link_token: String,
    pub expiration: String,
}

/// One connected bank, as `connectedBanks` shows it: never a token. Unknown
/// fields are ignored, so a description a newer build wrote still reads after
/// a rollback.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BankConnection {
    pub item_id: String,
    pub institution_name: Option<String>,
    /// The UTC date it was connected, `YYYY-MM-DD`; `None` when its
    /// description could not be stored or read.
    pub connected_on: Option<String>,
    pub accounts: Vec<BankAccount>,
    /// When a sync of it last finished (RFC 3339, UTC).
    #[serde(default)]
    pub last_synced_at: Option<String>,
    /// Plaid's error code from its last sync that Plaid refused
    /// (`ITEM_LOGIN_REQUIRED`: log in again), cleared by a sync that finishes.
    #[serde(default)]
    pub last_error_code: Option<String>,
    /// Plaid's last consent notice for it (`PENDING_EXPIRATION`,
    /// `PENDING_DISCONNECT`, `USER_PERMISSION_REVOKED`,
    /// `USER_ACCOUNT_REVOKED`, from a webhook), and when it came: unlike the
    /// error code, a finished sync leaves it; logging in again clears it.
    #[serde(default)]
    pub last_notice: Option<String>,
    #[serde(default)]
    pub last_notice_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BankAccount {
    pub account_id: String,
    pub name: String,
    /// The last digits Plaid shows (2–4), never the full number.
    pub mask: Option<String>,
    pub kind: String,
    pub subtype: Option<String>,
    /// The ledger account its transactions are imported to (step 6,
    /// `mapBankAccount`); `None` until an admin maps it, and nothing of it is
    /// imported until then.
    #[serde(default)]
    pub ledger_account: Option<String>,
    /// The first date imported: older transactions are skipped (a ledger
    /// account opened today, a bank connected again after its history was
    /// imported through an earlier connection).
    #[serde(default)]
    pub import_from: Option<chrono::NaiveDate>,
}

impl BankConnection {
    /// What is known of an item whose description is missing or unreadable.
    fn bare(item_id: String) -> Self {
        Self {
            item_id,
            institution_name: None,
            connected_on: None,
            accounts: Vec::new(),
            last_synced_at: None,
            last_error_code: None,
            last_notice: None,
            last_notice_at: None,
        }
    }
}

fn token_name(item_id: &str) -> String {
    format!("{ITEM_PREFIX}{item_id}/access_token")
}

fn cursor_name(item_id: &str) -> String {
    format!("{ITEM_PREFIX}{item_id}/cursor")
}

/// The cursor of the bank's last finished series (`SyncSession::series_start`).
fn complete_cursor_name(item_id: &str) -> String {
    format!("{ITEM_PREFIX}{item_id}/cursor_complete")
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
    suspense_account: String,
    /// `plaid.webhookUrl`: carried by new link tokens (step 6d).
    webhook_url: Option<String>,
    /// Plaid's webhook keys as this node knows them: one for every ledger on
    /// it, as they are one Plaid account's ([`PlaidEnv::webhook_keys`]).
    keys: Arc<WebhookKeys>,
    /// The banks with a webhook sync queued or running
    /// ([`Self::queue_webhook_sync`]), each with whether it is to go once more.
    webhook_syncs: std::sync::Mutex<std::collections::HashMap<String, bool>>,
    environment: PlaidEnvironment,
    /// The ledger's one store instance (`crate::secret_store`): every read and
    /// write goes through this lock, held for store work only.
    store: tokio::sync::Mutex<SecretStore>,
    /// `true` once [`Self::close`] ran. Every bank operation holds a read guard
    /// while it works with the store (a connect or disconnect from start to
    /// end); `close` takes the write side.
    closed: tokio::sync::RwLock<bool>,
    /// Set by [`Self::close`] before it waits for the `closed` gate, so work
    /// that must not wait for a stop (a webhook key fetch, step 6e) sees it at
    /// once.
    closing: std::sync::atomic::AtomicBool,
    /// The banks being synced now ([`Self::begin_sync`]).
    syncing: std::sync::Mutex<std::collections::HashSet<String>>,
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
            suspense_account: config.suspense_account.clone(),
            webhook_url: config.webhook_url.clone(),
            keys: Arc::clone(env.webhook_keys.of(config.environment)),
            webhook_syncs: std::sync::Mutex::default(),
            environment: config.environment,
            store: tokio::sync::Mutex::new(store),
            closed: tokio::sync::RwLock::new(false),
            closing: std::sync::atomic::AtomicBool::new(false),
            syncing: std::sync::Mutex::default(),
        })
    }

    /// Wait for every connect and disconnect under way, then refuse new ones
    /// ([`PlaidError::Closing`]). Bounded by Plaid's timeouts: a connect
    /// makes at most three calls of [`REQUEST_TIMEOUT`] each, about 90 s.
    pub(crate) async fn close(&self) {
        self.closing
            .store(true, std::sync::atomic::Ordering::SeqCst);
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
        self.closing
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    /// A link token for `client_user_id` (Plaid's stable, non-personal id for
    /// the person opening Link).
    ///
    /// With `item_id`, a link token in Plaid's **update mode** for that bank
    /// (step 6b): Link logs the person in again — an expired password, a new
    /// multi-factor prompt, `ITEM_LOGIN_REQUIRED` — on the same connection, so
    /// its item, transaction ids and history carry on; the public token Link
    /// hands back need not be exchanged (`connect` leaves a held item as it
    /// is). Plaid wants the bank's access token and
    /// no `products` then.
    pub(crate) async fn create_link_token(
        &self,
        client_user_id: &str,
        item_id: Option<&str>,
    ) -> Result<LinkToken, PlaidError> {
        let mut body = json!({
            "client_name": self.client_name,
            "user": { "client_user_id": client_user_id },
            "country_codes": ["US"],
            "language": "en",
        });
        let access_token = match item_id {
            Some(item_id) => Some(self.token_for_update(item_id).await?),
            None => {
                body["products"] = json!(["transactions"]);
                None
            }
        };
        if let Some(access_token) = &access_token {
            body["access_token"] = json!(access_token.expose());
        }
        if let Some(url) = &self.webhook_url {
            body["webhook"] = json!(url);
        }
        let created: LinkTokenCreated = self.client.call("/link/token/create", body).await?;
        Ok(LinkToken {
            link_token: created.link_token,
            expiration: created.expiration,
        })
    }

    /// Bank `item_id` as stored, when this ledger holds its token.
    async fn held_connection(&self, item_id: &str) -> Result<Option<BankConnection>, PlaidError> {
        let store = self.store.lock().await;
        if store.get(&token_name(item_id))?.is_none() {
            return Ok(None);
        }
        let connection = store
            .get(&info_name(item_id))?
            .and_then(|text| serde_json::from_str(text.expose()).ok())
            .unwrap_or_else(|| BankConnection::bare(item_id.to_owned()));
        Ok(Some(connection))
    }

    /// The access token of bank `item_id`, for update mode: the bank must be
    /// one this ledger holds, and its token of this node's Plaid environment
    /// (sent to the other one, Plaid would only call it invalid).
    async fn token_for_update(&self, item_id: &str) -> Result<Secret, PlaidError> {
        let closed = self.closed.read().await;
        if *closed {
            return Err(PlaidError::Closing);
        }
        let unknown = || PlaidError::NoSuchBank(format!("this ledger has no bank {item_id:?}"));
        if check_id("item_id", item_id).is_err() {
            return Err(unknown());
        }
        let Some(access_token) = self.store.lock().await.get(&token_name(item_id))? else {
            return Err(unknown());
        };
        if !access_token
            .expose()
            .starts_with(token_prefix(self.environment))
        {
            return Err(PlaidError::WrongEnvironment {
                configured: self.environment,
            });
        }
        Ok(access_token)
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
        // An item this ledger holds already: Link's update mode (a login
        // fixed on a connected bank) also hands back a public token, and one
        // passed here exchanges to the same item. Nothing is stored over it —
        // its token, its mappings and its sync cursor stay as they are.
        if check_id("item_id", &item_id).is_ok() {
            if let Some(mut held) = self.held_connection(&item_id).await? {
                info!(item_id = %item_id, "a bank already connected was connected again; nothing changed");
                // The person went through Link for this bank again: a consent
                // notice (an expiring connection) is answered, as Plaid sends
                // no webhook for a renewal made in update mode. The gate is
                // held open here already.
                self.change_info_open(&item_id, |connection| {
                    connection.last_notice = None;
                    connection.last_notice_at = None;
                })
                .await;
                held.last_notice = None;
                held.last_notice_at = None;
                return Ok(held);
            }
        }
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
        // Step 6: the same bank linked twice is two items, each with its own
        // transaction ids, so every transaction would be imported twice. The
        // new one is removed at Plaid, then here; kept (and listed) when Plaid
        // refuses, for `disconnectBank`.
        if let Some(existing) = self.same_bank_as(&connection).await {
            match self.remove_at_plaid(&access_token).await {
                Ok(_) => {
                    self.store.lock().await.remove(&token_name(&item_id))?;
                    info!(item_id = %item_id, existing = %existing, "the same bank linked again; the new connection was removed");
                    return Err(PlaidError::AlreadyConnected { item_id: existing });
                }
                Err(error) => {
                    warn!(item_id = %item_id, existing = %existing, %error, "the same bank linked again, and removing the new connection at Plaid failed: disconnect it");
                }
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
                ledger_account: None,
                import_from: None,
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

    /// The account on the other side of every imported transaction.
    pub(crate) fn suspense_account(&self) -> &str {
        &self.suspense_account
    }

    /// The item already connected that `connection` is the same bank as: the
    /// same institution and the same accounts (names and masks).
    async fn same_bank_as(&self, connection: &BankConnection) -> Option<String> {
        let institution = connection.institution_name.as_ref()?;
        let accounts = |connection: &BankConnection| {
            let mut accounts: Vec<(String, Option<String>)> = connection
                .accounts
                .iter()
                .map(|account| (account.name.clone(), account.mask.clone()))
                .collect();
            accounts.sort();
            accounts
        };
        let these = accounts(connection);
        if these.is_empty() {
            return None;
        }
        self.connections()
            .await
            .ok()?
            .into_iter()
            .find(|other| {
                other.item_id != connection.item_id
                    && other.institution_name.as_ref() == Some(institution)
                    && accounts(other) == these
            })
            .map(|other| other.item_id)
    }

    /// Import `account_id` of bank `item_id` to `ledger_account`, its
    /// transactions dated `import_from` or later (the caller checked the
    /// account is open). A changed mapping or start date forgets the bank's
    /// sync cursor, so the next sync fetches its whole history again and
    /// imports what was skipped; what was imported already is skipped by its
    /// link.
    pub(crate) async fn map_account(
        &self,
        item_id: &str,
        account_id: &str,
        ledger_account: &str,
        import_from: chrono::NaiveDate,
    ) -> Result<BankConnection, PlaidError> {
        let closed = self.closed.read().await;
        if *closed {
            return Err(PlaidError::Closing);
        }
        let unknown = || {
            PlaidError::NoSuchBank(format!(
                "this ledger has no bank {item_id:?} with an account {account_id:?}"
            ))
        };
        if check_id("item_id", item_id).is_err() {
            return Err(unknown());
        }
        let mut store = self.store.lock().await;
        // Judged under the store lock: a sync begun after this reads the new
        // mapping (its `begin_fetch` waits for the lock); one under way is
        // seen, and would otherwise import with the old one.
        if self.is_syncing(item_id) {
            return Err(PlaidError::SyncInProgress);
        }
        let Some(text) = store.get(&info_name(item_id))? else {
            return Err(unknown());
        };
        let mut connection: BankConnection = serde_json::from_str(text.expose())
            .map_err(|error| PlaidError::Unexpected(format!("stored bank {item_id}: {error}")))?;
        let account = connection
            .accounts
            .iter_mut()
            .find(|account| account.account_id == account_id)
            .ok_or_else(unknown)?;
        let changed = account.ledger_account.as_deref() != Some(ledger_account)
            || account.import_from != Some(import_from);
        account.ledger_account = Some(ledger_account.to_owned());
        account.import_from = Some(import_from);
        let text = serde_json::to_string(&connection)
            .map_err(|error| PlaidError::Unexpected(error.to_string()))?;
        store.put(&info_name(item_id), &Secret::new(text))?;
        if changed {
            store.remove(&cursor_name(item_id))?;
            store.remove(&complete_cursor_name(item_id))?;
        }
        Ok(connection)
    }

    /// Begin syncing bank `item_id`: its token, its stored mapping and the
    /// cursor it is stored at. Nothing is asked of Plaid yet.
    pub(crate) async fn begin_fetch(&self, item_id: &str) -> Result<SyncSession, PlaidError> {
        let closed = self.closed.read().await;
        if *closed {
            return Err(PlaidError::Closing);
        }
        let unknown = || PlaidError::NoSuchBank(format!("this ledger has no bank {item_id:?}"));
        if check_id("item_id", item_id).is_err() {
            return Err(unknown());
        }
        let store = self.store.lock().await;
        let Some(access_token) = store.get(&token_name(item_id))? else {
            return Err(unknown());
        };
        let connection = match store.get(&info_name(item_id))? {
            Some(text) => serde_json::from_str(text.expose()).map_err(|error| {
                PlaidError::Unexpected(format!("stored bank {item_id}: {error}"))
            })?,
            None => BankConnection::bare(item_id.to_owned()),
        };
        let stored = store
            .get(&cursor_name(item_id))?
            .map(|cursor| cursor.expose().to_owned());
        let complete = store
            .get(&complete_cursor_name(item_id))?
            .map(|cursor| cursor.expose().to_owned());
        drop(store);
        if !access_token
            .expose()
            .starts_with(token_prefix(self.environment))
        {
            return Err(PlaidError::WrongEnvironment {
                configured: self.environment,
            });
        }
        Ok(SyncSession {
            item_id: item_id.to_owned(),
            access_token,
            connection,
            series_start: complete,
            restarted: false,
            at: stored.clone(),
            stored,
            restarts: 0,
            pages: 0,
            done: false,
        })
    }

    /// The session's next page from Plaid, or `None` once Plaid has no more.
    /// Nothing is stored: the caller writes the page's entries, then
    /// [`Self::commit_page`] — so a sync cut short asks for the same page
    /// again next time, and earlier pages are not fetched again.
    pub(crate) async fn next_page(
        &self,
        session: &mut SyncSession,
    ) -> Result<Option<Page>, PlaidError> {
        if session.done {
            return Ok(None);
        }
        let closed = self.closed.read().await;
        if *closed {
            return Err(PlaidError::Closing);
        }
        if session.pages >= MAX_SYNC_PAGES {
            return Err(PlaidError::Unexpected(format!(
                "more than {MAX_SYNC_PAGES} pages of transactions in one sync"
            )));
        }
        let raw: SyncPage = loop {
            let mut body = json!({
                "access_token": session.access_token.expose(),
                "count": SYNC_PAGE_SIZE,
            });
            if let Some(at) = &session.at {
                body["cursor"] = json!(at);
            }
            match self.client.call("/transactions/sync", body).await {
                Ok(page) => break page,
                // Plaid's own advice: start the pages again from the first
                // cursor. What was written from them already is skipped by
                // its link.
                Err(error)
                    if error.plaid_code()
                        == Some("TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION")
                        && session.restarts < 3 =>
                {
                    session.restarts += 1;
                    session.restarted = true;
                    session.at = session.series_start.clone();
                }
                Err(error) => return Err(error),
            }
        };
        session.pages += 1;
        let mut page = Page {
            next_cursor: raw.next_cursor.clone(),
            has_more: raw.has_more,
            ..Page::default()
        };
        for value in raw.added {
            // One transaction this node cannot read is noted, not a failed
            // sync: every later sync would stop on it too.
            let id = value
                .get("transaction_id")
                .and_then(Value::as_str)
                .filter(|id| check_id("transaction_id", id).is_ok())
                .map(str::to_owned);
            let posted = serde_json::from_value::<SyncTransaction>(value)
                .map_err(|error| {
                    PlaidError::Unexpected(format!("a transaction that does not read: {error}"))
                })
                .and_then(|transaction| {
                    if transaction.pending {
                        Ok(None)
                    } else {
                        transaction.posted().map(Some)
                    }
                });
            match posted {
                Ok(Some(posted)) => page.added.push(posted),
                Ok(None) => page.pending += 1,
                Err(error) => page.unreadable.push((id, error.to_string())),
            }
        }
        for value in raw.modified {
            if let Ok(transaction) = serde_json::from_value::<SyncChanged>(value) {
                if !transaction.pending {
                    page.changed.push(transaction.transaction_id);
                }
            }
        }
        for value in raw.removed {
            if let Ok(removed) = serde_json::from_value::<SyncRemoved>(value) {
                page.changed.push(removed.transaction_id);
            }
        }
        session.at = Some(raw.next_cursor);
        session.done = !raw.has_more;
        Ok(Some(page))
    }

    /// Store where bank `session` stands once `page`'s entries are written —
    /// only over the cursor the session last stored or began at; the last
    /// page of a series also becomes the cursor a restart goes back to.
    /// `Ok(false)` when the cursor moved under the session, or the bank was
    /// disconnected: the sync should stop there.
    pub(crate) async fn commit_page(
        &self,
        session: &mut SyncSession,
        page: &Page,
    ) -> Result<bool, PlaidError> {
        let cursor = page.next_cursor.as_str();
        let closed = self.closed.read().await;
        if *closed {
            return Err(PlaidError::Closing);
        }
        let item_id = session.item_id.as_str();
        let mut store = self.store.lock().await;
        if store.get(&token_name(item_id))?.is_none() {
            // Disconnected while the sync ran: nothing to keep a cursor for.
            return Ok(false);
        }
        let stored = store.get(&cursor_name(item_id))?;
        if stored.as_ref().map(Secret::expose) != session.stored.as_deref() {
            info!(item_id = %item_id, "the bank's cursor moved while it synced; kept as it is");
            return Ok(false);
        }
        store.put(&cursor_name(item_id), &Secret::new(cursor))?;
        session.stored = Some(cursor.to_owned());
        if !page.has_more {
            store.put(&complete_cursor_name(item_id), &Secret::new(cursor))?;
            session.series_start = Some(cursor.to_owned());
        }
        Ok(true)
    }

    /// Whether bank `item_id` is being synced now.
    fn is_syncing(&self, item_id: &str) -> bool {
        self.syncing
            .lock()
            .map(|syncing| syncing.contains(item_id))
            .unwrap_or(true)
    }

    /// Mark bank `item_id` as syncing, or `None` when a sync of it already
    /// runs: two at once each read the books before the other writes, and
    /// would import the same transactions twice (as two people they are two
    /// records). The mark goes with the guard.
    pub(crate) fn begin_sync(self: &Arc<Self>, item_id: &str) -> Option<SyncGuard> {
        // A poisoned lock counts as syncing, as `is_syncing` reads it.
        let Ok(mut syncing) = self.syncing.lock() else {
            return None;
        };
        syncing.insert(item_id.to_owned()).then(|| SyncGuard {
            service: Arc::clone(self),
            item_id: item_id.to_owned(),
        })
    }

    /// Record how bank `item_id`'s sync went (step 6c), for `connectedBanks`:
    /// `None` a sync that finished (its time noted, any error code cleared),
    /// `Some(code)` Plaid's refusal. Best effort: a bank gone or a store that
    /// cannot be written is logged, never a failed sync.
    pub(crate) async fn note_health(&self, item_id: &str, error_code: Option<&str>) {
        let closed = self.closed.read().await;
        if *closed {
            return;
        }
        let mut store = self.store.lock().await;
        let described = match store.get(&info_name(item_id)) {
            Ok(Some(text)) => serde_json::from_str::<BankConnection>(text.expose()).ok(),
            _ => None,
        };
        let Some(mut connection) = described else {
            return;
        };
        match error_code {
            None => {
                connection.last_synced_at = Some(chrono::Utc::now().to_rfc3339());
                connection.last_error_code = None;
            }
            // Plaid's codes are short words; a missing one says so, and none is
            // kept longer than a code.
            Some(code) => {
                let code: String = code.chars().take(64).collect();
                connection.last_error_code = Some(if code.is_empty() {
                    "UNKNOWN".to_owned()
                } else {
                    code
                });
            }
        }
        let stored = serde_json::to_string(&connection)
            .map_err(|error| PlaidError::Unexpected(error.to_string()))
            .and_then(|text| {
                store
                    .put(&info_name(item_id), &Secret::new(text))
                    .map_err(PlaidError::from)
            });
        if let Err(error) = stored {
            warn!(item_id = %item_id, %error, "a bank's sync health was not stored");
        }
    }

    /// Read bank `item_id`'s accounts from Plaid again (step 6c): accounts it
    /// added since it was connected join the list, unmapped; the accounts
    /// already known keep their mappings, with Plaid's names and masks of now.
    /// An account Plaid no longer lists is kept, so its mapping is not lost.
    pub(crate) async fn refresh_accounts(
        &self,
        item_id: &str,
    ) -> Result<BankConnection, PlaidError> {
        let access_token = self.token_for_update(item_id).await?;
        let closed = self.closed.read().await;
        if *closed {
            return Err(PlaidError::Closing);
        }
        let (institution_name, fresh) = self.describe(&access_token).await?;
        let mut store = self.store.lock().await;
        // Disconnected while Plaid was asked: nothing to write back, or a bank
        // with no token would be listed for good.
        if store.get(&token_name(item_id))?.is_none() {
            return Err(PlaidError::NoSuchBank(format!(
                "this ledger has no bank {item_id:?} (disconnected)"
            )));
        }
        let mut connection = match store.get(&info_name(item_id))? {
            Some(text) => serde_json::from_str(text.expose()).map_err(|error| {
                PlaidError::Unexpected(format!("stored bank {item_id}: {error}"))
            })?,
            None => BankConnection::bare(item_id.to_owned()),
        };
        if institution_name.is_some() {
            connection.institution_name = institution_name;
        }
        for account in fresh {
            match connection
                .accounts
                .iter_mut()
                .find(|known| known.account_id == account.account_id)
            {
                Some(known) => {
                    known.name = account.name;
                    known.mask = account.mask;
                    known.kind = account.kind;
                    known.subtype = account.subtype;
                }
                None => connection.accounts.push(account),
            }
        }
        let text = serde_json::to_string(&connection)
            .map_err(|error| PlaidError::Unexpected(error.to_string()))?;
        store.put(&info_name(item_id), &Secret::new(text))?;
        info!(item_id = %item_id, accounts = connection.accounts.len(), "bank accounts read again");
        Ok(connection)
    }

    /// Stop importing `account_id` of bank `item_id` (step 6c): its mapping
    /// and start date cleared. Refused while the bank syncs, as a mapping is.
    pub(crate) async fn unmap_account(
        &self,
        item_id: &str,
        account_id: &str,
    ) -> Result<BankConnection, PlaidError> {
        let closed = self.closed.read().await;
        if *closed {
            return Err(PlaidError::Closing);
        }
        let unknown = || {
            PlaidError::NoSuchBank(format!(
                "this ledger has no bank {item_id:?} with an account {account_id:?}"
            ))
        };
        if check_id("item_id", item_id).is_err() {
            return Err(unknown());
        }
        let mut store = self.store.lock().await;
        if self.is_syncing(item_id) {
            return Err(PlaidError::SyncInProgress);
        }
        let Some(text) = store.get(&info_name(item_id))? else {
            return Err(unknown());
        };
        let mut connection: BankConnection = serde_json::from_str(text.expose())
            .map_err(|error| PlaidError::Unexpected(format!("stored bank {item_id}: {error}")))?;
        let account = connection
            .accounts
            .iter_mut()
            .find(|account| account.account_id == account_id)
            .ok_or_else(unknown)?;
        account.ledger_account = None;
        account.import_from = None;
        let text = serde_json::to_string(&connection)
            .map_err(|error| PlaidError::Unexpected(error.to_string()))?;
        store.put(&info_name(item_id), &Secret::new(text))?;
        Ok(connection)
    }

    /// Connect one of Plaid's sandbox test banks without Link (step 6c, for
    /// demo users): `/sandbox/public_token/create`, then the usual connect.
    /// Sandbox only: refused, with nothing sent, on any other environment.
    pub(crate) async fn connect_sandbox(
        self: &Arc<Self>,
        institution_id: &str,
    ) -> Result<BankConnection, PlaidError> {
        if self.environment != PlaidEnvironment::Sandbox {
            return Err(PlaidError::SandboxOnly);
        }
        check_id("institution_id", institution_id)?;
        if *self.closed.read().await {
            return Err(PlaidError::Closing);
        }
        let created: SandboxPublicToken = self
            .client
            .call(
                "/sandbox/public_token/create",
                json!({
                    "institution_id": institution_id,
                    "initial_products": ["transactions"],
                }),
            )
            .await?;
        self.connect(created.public_token).await
    }

    /// Put sandbox bank `item_id` into `ITEM_LOGIN_REQUIRED`
    /// (`/sandbox/item/reset_login`), to show logging in again. Sandbox only.
    pub(crate) async fn reset_sandbox_login(&self, item_id: &str) -> Result<(), PlaidError> {
        if self.environment != PlaidEnvironment::Sandbox {
            return Err(PlaidError::SandboxOnly);
        }
        let access_token = self.token_for_update(item_id).await?;
        let _: Value = self
            .client
            .call(
                "/sandbox/item/reset_login",
                json!({ "access_token": access_token.expose() }),
            )
            .await?;
        info!(item_id = %item_id, "sandbox bank set to need a new login");
        Ok(())
    }

    /// Whether this ledger holds bank `item_id` (a webhook about another is
    /// refused).
    pub(crate) async fn holds(&self, item_id: &str) -> bool {
        check_id("item_id", item_id).is_ok()
            && matches!(
                self.store.lock().await.get(&token_name(item_id)),
                Ok(Some(_))
            )
    }

    /// Tell Plaid `plaid.webhookUrl` for every bank this ledger holds
    /// (`/item/webhook/update`, step 6d): banks connected before it was set,
    /// or since it changed. The number updated.
    pub(crate) async fn update_webhooks(&self) -> Result<usize, PlaidError> {
        let Some(url) = self.webhook_url.clone() else {
            return Err(PlaidError::NoWebhookUrl);
        };
        let item_ids = item_ids(self.store.lock().await.names());
        let mut updated = 0;
        for item_id in item_ids {
            let access_token = match self.token_for_update(&item_id).await {
                Ok(token) => token,
                Err(PlaidError::NoSuchBank(_)) => continue,
                Err(error) => return Err(error),
            };
            let _: Value = self
                .client
                .call(
                    "/item/webhook/update",
                    json!({ "access_token": access_token.expose(), "webhook": url }),
                )
                .await?;
            updated += 1;
        }
        info!(updated, "banks told where to send their webhooks");
        Ok(updated)
    }

    /// Have Plaid's sandbox send bank `item_id` a webhook
    /// (`/sandbox/item/fire_webhook`), `SYNC_UPDATES_AVAILABLE` by default: to
    /// show a webhook-started sync. Sandbox only.
    pub(crate) async fn fire_sandbox_webhook(
        &self,
        item_id: &str,
        webhook_code: &str,
    ) -> Result<(), PlaidError> {
        if self.environment != PlaidEnvironment::Sandbox {
            return Err(PlaidError::SandboxOnly);
        }
        check_id("webhook_code", webhook_code)?;
        let access_token = self.token_for_update(item_id).await?;
        let _: Value = self
            .client
            .call(
                "/sandbox/item/fire_webhook",
                json!({ "access_token": access_token.expose(), "webhook_code": webhook_code }),
            )
            .await?;
        Ok(())
    }

    /// Plaid's webhook verification key `key_id`, as an uncompressed P-256
    /// point (`0x04 || x || y`), when this node has it.
    ///
    /// The route that asks is open to anyone, so a key not cached is never
    /// fetched while the caller waits: the answer is [`KeyLookup::Pending`]
    /// (the webhook is refused, and Plaid redelivers it about 30 s later),
    /// and the key is fetched in the background — one fetch of a key id at a
    /// time, at most [`MAX_KEY_FETCHES_A_CLIENT_A_MINUTE`] for `client` and
    /// [`MAX_KEY_FETCHES_A_MINUTE`] in all. So a call never waits on Plaid,
    /// and a stranger's made-up key ids spend only that stranger's budget. A
    /// key id Plaid refused is not asked again for five minutes; a key Plaid
    /// has set to expire is refused.
    ///
    /// A key Plaid gave is asked about again once [`KEY_FRESH_FOR`] old: in
    /// the background, at most once a minute, outside both budgets (only keys
    /// Plaid gave are cached, so strangers cannot add to these), and used
    /// meanwhile — up to [`KEY_TRUSTED_UNCONFIRMED`], after which it is
    /// refused until Plaid confirms it. One Plaid refuses or has since set to
    /// expire is dropped.
    pub(crate) fn verification_key(
        self: &Arc<Self>,
        key_id: &str,
        client: std::net::IpAddr,
    ) -> KeyLookup {
        if check_id("key_id", key_id).is_err() {
            return KeyLookup::Refused;
        }
        match self.cached_key(key_id) {
            Some(Cached::Fresh(point)) => return KeyLookup::Found(point),
            Some(Cached::Stale { point, ask_again }) => {
                if ask_again {
                    self.start_key_fetch(key_id);
                }
                return point.map_or(KeyLookup::Pending, KeyLookup::Found);
            }
            Some(Cached::Refused) => return KeyLookup::Refused,
            None => {}
        }
        if !self.key_fetch_free(key_id) {
            return KeyLookup::Pending;
        }
        if !self.spend_key_fetch(client) {
            return KeyLookup::Refused;
        }
        self.start_key_fetch(key_id);
        KeyLookup::Pending
    }

    /// Whether a fetch of `key_id` could start now: none of it under way, and
    /// fewer than 64 of any.
    fn key_fetch_free(&self, key_id: &str) -> bool {
        self.keys
            .fetching_keys
            .lock()
            .is_ok_and(|fetching| !fetching.contains(key_id) && fetching.len() < 64)
    }

    /// Fetch key `key_id` in the background, unless one is under way: cached
    /// when Plaid gives it, dropped and remembered as refused when Plaid
    /// refuses it, kept as it was after a passing failure.
    fn start_key_fetch(self: &Arc<Self>, key_id: &str) {
        let Ok(mut fetching) = self.keys.fetching_keys.lock() else {
            return;
        };
        if fetching.contains(key_id) || fetching.len() >= 64 {
            return;
        }
        fetching.insert(key_id.to_owned());
        drop(fetching);
        let service = Arc::clone(self);
        let key_id = key_id.to_owned();
        tokio::spawn(
            async move {
                // A stopping ledger asks Plaid nothing more, and never waits for
                // its stop: the one-fetch lock is the node's, so a wait here
                // would hold up every other company's keys (`closing`, not the
                // `closed` gate a connect under way holds for up to 90 s). Its
                // key id is left uncached; the next call asks again.
                let fetched = if service.closing.load(std::sync::atomic::Ordering::SeqCst) {
                    Err(PlaidError::Closing)
                } else {
                    let _one_at_a_time = service.keys.key_fetch.lock().await;
                    if service.closing.load(std::sync::atomic::Ordering::SeqCst) {
                        Err(PlaidError::Closing)
                    } else {
                        service.fetch_key(&key_id).await
                    }
                };
                match fetched {
                    Ok(point) => {
                        if let Ok(mut keys) = service.keys.webhook_keys.lock() {
                            if keys.len() >= 64 {
                                keys.clear();
                            }
                            let now = std::time::Instant::now();
                            keys.insert(
                                key_id.clone(),
                                CachedKey {
                                    fetched: now,
                                    asked: now,
                                    point,
                                },
                            );
                        }
                    }
                    // Only Plaid's own refusal, or a key it gave that is not
                    // usable, is remembered: a timeout or a 5xx is tried again
                    // later, a stale key kept meanwhile.
                    Err(error) if error.is_definite_refusal() => {
                        if let Ok(mut keys) = service.keys.webhook_keys.lock() {
                            keys.remove(&key_id);
                        }
                        if let Ok(mut refused) = service.keys.refused_keys.lock() {
                            if refused.len() >= 256 {
                                refused.clear();
                            }
                            refused.insert(key_id.clone(), std::time::Instant::now());
                        }
                    }
                    Err(PlaidError::Closing) => {}
                    Err(error) => {
                        warn!(key_id = %key_id, %error, "a Plaid webhook key could not be fetched; asked again later");
                    }
                }
                if let Ok(mut fetching) = service.keys.fetching_keys.lock() {
                    fetching.remove(&key_id);
                }
            }
            .in_current_span(),
        );
    }

    /// Spend one key fetch from `client`'s budget and the node's: `false`
    /// when either is spent this minute. A client is keyed as the rate limit
    /// keys it (M-04b): an IPv6 /64 is one client, so rotating addresses inside
    /// it gets no fresh budget.
    fn spend_key_fetch(&self, client: std::net::IpAddr) -> bool {
        let client = crate::rate_limit::bucket_key(client);
        let minute = Duration::from_secs(60);
        let (Ok(mut node), Ok(mut clients)) = (
            self.keys.key_fetches.lock(),
            self.keys.key_fetches_by_client.lock(),
        ) else {
            return false;
        };
        let all = node.get_or_insert_with(|| (std::time::Instant::now(), 0));
        if all.0.elapsed() >= minute {
            *all = (std::time::Instant::now(), 0);
        }
        if clients.len() >= 1024 {
            clients.retain(|_, (since, _)| since.elapsed() < minute);
            if clients.len() >= 1024 {
                clients.clear();
            }
        }
        let mine = clients
            .entry(client)
            .or_insert_with(|| (std::time::Instant::now(), 0));
        if mine.0.elapsed() >= minute {
            *mine = (std::time::Instant::now(), 0);
        }
        if all.1 >= MAX_KEY_FETCHES_A_MINUTE || mine.1 >= MAX_KEY_FETCHES_A_CLIENT_A_MINUTE {
            return false;
        }
        all.1 += 1;
        mine.1 += 1;
        true
    }

    /// What is cached for key `key_id`, `None` when nothing is. A stale key
    /// due to be asked about again is marked asked here, under the lock, so
    /// one call a minute starts the asking.
    fn cached_key(&self, key_id: &str) -> Option<Cached> {
        if let Ok(mut keys) = self.keys.webhook_keys.lock() {
            if let Some(key) = keys.get_mut(key_id) {
                if key.fetched.elapsed() < KEY_FRESH_FOR {
                    return Some(Cached::Fresh(key.point.clone()));
                }
                let ask_again = key.asked.elapsed() >= Duration::from_secs(60);
                if ask_again {
                    key.asked = std::time::Instant::now();
                }
                let usable = key.fetched.elapsed() < KEY_TRUSTED_UNCONFIRMED;
                return Some(Cached::Stale {
                    point: usable.then(|| key.point.clone()),
                    ask_again,
                });
            }
        }
        let refused_lately = self.keys.refused_keys.lock().ok().is_some_and(|refused| {
            refused
                .get(key_id)
                .is_some_and(|when| when.elapsed() < Duration::from_secs(5 * 60))
        });
        refused_lately.then_some(Cached::Refused)
    }

    /// Whether a key fetch is under way (tests).
    #[cfg(test)]
    pub(crate) fn key_fetch_under_way(&self) -> bool {
        self.keys
            .fetching_keys
            .lock()
            .is_ok_and(|fetching| !fetching.is_empty())
    }

    /// Have cached key `key_id` fetched, and last asked about, `by` earlier
    /// (tests).
    #[cfg(test)]
    pub(crate) fn age_webhook_key(&self, key_id: &str, by: Duration) {
        if let Some(key) = self.keys.webhook_keys.lock().unwrap().get_mut(key_id) {
            let back = |when: std::time::Instant| {
                when.checked_sub(by)
                    .expect("a monotonic clock that far back")
            };
            key.fetched = back(key.fetched);
            key.asked = back(key.asked);
        }
    }

    async fn fetch_key(&self, key_id: &str) -> Result<Vec<u8>, PlaidError> {
        let got: VerificationKeyGot = self
            .client
            .call("/webhook_verification_key/get", json!({ "key_id": key_id }))
            .await?;
        let key = got.key;
        let unusable = |what: &str| PlaidError::Unexpected(format!("webhook key {key_id}: {what}"));
        if key.kid != key_id {
            return Err(unusable("another key than the one asked for"));
        }
        if key.alg != "ES256" || key.crv != "P-256" || key.kty != "EC" {
            return Err(unusable("not an ES256 P-256 key"));
        }
        if key.expired_at.is_some() {
            return Err(unusable("set to expire"));
        }
        use base64::Engine as _;
        let decode = |part: &str| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(part)
                .ok()
                .filter(|bytes| bytes.len() == 32)
        };
        let (Some(x), Some(y)) = (decode(&key.x), decode(&key.y)) else {
            return Err(unusable("a point that does not read"));
        };
        let mut point = Vec::with_capacity(65);
        point.push(0x04);
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        Ok(point)
    }

    /// Mark bank `item_id` as having a webhook sync queued, or `None` when one
    /// is queued or running already. The mark goes with the guard, a task
    /// aborted at a stop included.
    pub(crate) fn queue_webhook_sync(self: &Arc<Self>, item_id: &str) -> Option<QueuedSync> {
        let Ok(mut queued) = self.webhook_syncs.lock() else {
            return None;
        };
        if let Some(again) = queued.get_mut(item_id) {
            *again = true;
            return None;
        }
        queued.insert(item_id.to_owned(), false);
        Some(QueuedSync {
            service: Arc::clone(self),
            item_id: item_id.to_owned(),
            ended: false,
        })
    }

    /// Keep consent notice `code` on bank `item_id`, with its time.
    pub(crate) async fn note_notice(&self, item_id: &str, code: &str) {
        let code: String = code.chars().take(64).collect();
        self.change_info(item_id, |connection| {
            connection.last_notice = Some(code);
            connection.last_notice_at = Some(chrono::Utc::now().to_rfc3339());
        })
        .await;
    }

    /// Clear bank `item_id`'s consent notice (its login works again).
    pub(crate) async fn clear_notice(&self, item_id: &str) {
        self.change_info(item_id, |connection| {
            connection.last_notice = None;
            connection.last_notice_at = None;
        })
        .await;
    }

    /// Change bank `item_id`'s stored description, best effort, as
    /// [`Self::note_health`] does: nothing for a bank gone or a ledger closing.
    async fn change_info(&self, item_id: &str, change: impl FnOnce(&mut BankConnection)) {
        let closed = self.closed.read().await;
        if *closed {
            return;
        }
        self.change_info_open(item_id, change).await;
    }

    /// [`Self::change_info`] for a caller that holds the `closed` gate open
    /// already: a second read of it would wait behind a stop waiting for the
    /// first, and neither would end.
    async fn change_info_open(&self, item_id: &str, change: impl FnOnce(&mut BankConnection)) {
        let mut store = self.store.lock().await;
        let described = match store.get(&info_name(item_id)) {
            Ok(Some(text)) => serde_json::from_str::<BankConnection>(text.expose()).ok(),
            _ => None,
        };
        let Some(mut connection) = described else {
            return;
        };
        change(&mut connection);
        let stored = serde_json::to_string(&connection)
            .map_err(|error| PlaidError::Unexpected(error.to_string()))
            .and_then(|text| {
                store
                    .put(&info_name(item_id), &Secret::new(text))
                    .map_err(PlaidError::from)
            });
        if let Err(error) = stored {
            warn!(item_id = %item_id, %error, "a bank's description was not stored");
        }
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
        store.remove(&cursor_name(item_id))?;
        store.remove(&complete_cursor_name(item_id))?;
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

    /// One `/transactions/sync` answer: a page, or a (status, Plaid code) error.
    pub(crate) type SyncAnswer = Result<Value, (u16, String)>;

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
        /// `/transactions/sync`'s answers, one per call: a page, or a one-off
        /// (status, Plaid code) error. Empty: one page with nothing new.
        pub sync: Arc<Mutex<std::collections::VecDeque<SyncAnswer>>>,
        /// The item id the next exchange answers with, instead of [`ITEM_ID`].
        pub next_item: Arc<Mutex<Option<String>>>,
        /// The accounts `/accounts/get` answers with, instead of the two.
        pub accounts: Arc<Mutex<Option<Value>>>,
        /// The JWK `/webhook_verification_key/get` answers with; none, a refusal.
        pub webhook_key: Arc<Mutex<Option<Value>>>,
        /// Answer with `webhook_key` whatever key id was asked for (a Plaid
        /// that sends the wrong key).
        pub webhook_key_any_id: Arc<Mutex<bool>>,
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

        pub(crate) fn sync_page(&self, page: Value) {
            self.sync.lock().unwrap().push_back(Ok(page));
        }

        pub(crate) fn sync_error(&self, status: u16, code: &str) {
            self.sync
                .lock()
                .unwrap()
                .push_back(Err((status, code.to_owned())));
        }

        /// The `/transactions/sync` request bodies, in order.
        pub(crate) fn sync_bodies(&self) -> Vec<Value> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|(path, _)| path == "/transactions/sync")
                .map(|(_, body)| body.clone())
                .collect()
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
                let mut failure = mock.fail.lock().unwrap().get(path).cloned();
                let mut page = None;
                if path == "/webhook_verification_key/get" && failure.is_none() {
                    let asked = mock
                        .body_of("/webhook_verification_key/get")
                        .and_then(|body| body["key_id"].as_str().map(str::to_owned));
                    let key = mock.webhook_key.lock().unwrap().clone().filter(|key| {
                        *mock.webhook_key_any_id.lock().unwrap()
                            || key["kid"].as_str() == asked.as_deref()
                    });
                    return match key {
                        Some(key) => (
                            StatusCode::OK,
                            Json(json!({ "key": key, "request_id": "req-11" })),
                        ),
                        None => (
                            StatusCode::BAD_REQUEST,
                            Json(
                                json!({ "error_type": "INVALID_INPUT", "error_code": "INVALID_FIELD", "request_id": "req-mock" }),
                            ),
                        ),
                    };
                }
                if path == "/transactions/sync" {
                    match mock.sync.lock().unwrap().pop_front() {
                        Some(Ok(next)) => page = Some(next),
                        Some(Err(error)) => failure = Some(error),
                        None => {}
                    }
                }
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
                        "item_id": mock.next_item.lock().unwrap().take().unwrap_or_else(|| ITEM_ID.to_owned()),
                        "request_id": "req-2",
                    }),
                    "/accounts/get" => json!({
                        "accounts": mock.accounts.lock().unwrap().clone().unwrap_or_else(|| json!([
                            { "account_id": "acc1", "name": "Plaid Checking", "mask": "0000",
                              "type": "depository", "subtype": "checking", "balances": {} },
                            { "account_id": "acc2", "name": "Plaid Saving", "mask": "1111",
                              "type": "depository", "subtype": "savings", "balances": {} },
                        ])),
                        "item": { "item_id": ITEM_ID, "institution_id": "ins_109508" },
                        "request_id": "req-3",
                    }),
                    "/institutions/get_by_id" => json!({
                        "institution": { "institution_id": "ins_109508", "name": "First Platypus Bank" },
                        "request_id": "req-4",
                    }),
                    "/item/remove" => json!({ "request_id": "req-5" }),
                    "/sandbox/public_token/create" => json!({
                        "public_token": "public-sandbox-from-the-sandbox",
                        "request_id": "req-7",
                    }),
                    "/sandbox/item/reset_login" => {
                        json!({ "reset_login": true, "request_id": "req-8" })
                    }
                    "/transactions/sync" => page.unwrap_or_else(|| {
                        json!({
                            "added": [], "modified": [], "removed": [],
                            "next_cursor": "cursor-empty", "has_more": false,
                            "request_id": "req-6",
                        })
                    }),
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
                "/transactions/sync",
                "/sandbox/public_token/create",
                "/sandbox/item/reset_login",
                "/item/webhook/update",
                "/sandbox/item/fire_webhook",
                "/webhook_verification_key/get",
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
            webhook_keys: NodeWebhookKeys::default(),
        }
    }

    pub(crate) fn enabled() -> PlaidConfig {
        PlaidConfig {
            enabled: true,
            ..PlaidConfig::default()
        }
    }

    pub(crate) async fn service(
        mock: &MockPlaid,
        folder: &std::path::Path,
        env: &PlaidEnv,
    ) -> Arc<PlaidService> {
        service_in(mock, folder, env, enabled()).await
    }

    pub(crate) async fn service_in(
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

    pub(crate) fn connect_token() -> String {
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

        let token = plaid
            .create_link_token("u_0123456789abcdef", None)
            .await
            .unwrap();
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
                webhook_keys: NodeWebhookKeys::default(),
            },
            PlaidEnv {
                credentials: None,
                store_key: full.store_key.clone(),
                base_url: None,
                webhook_keys: NodeWebhookKeys::default(),
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

    /// Every page a sync would read, from the stored cursor; nothing stored.
    #[derive(Debug, Default)]
    struct Fetched {
        added: Vec<PostedTransaction>,
        pending: usize,
        changed: Vec<String>,
        unreadable: Vec<String>,
        cursor: String,
    }

    async fn fetch_all(plaid: &PlaidService, item_id: &str) -> Result<Fetched, PlaidError> {
        let mut session = plaid.begin_fetch(item_id).await?;
        let mut fetched = Fetched::default();
        while let Some(page) = plaid.next_page(&mut session).await? {
            fetched.added.extend(page.added);
            fetched.pending += page.pending;
            fetched.changed.extend(page.changed);
            fetched
                .unreadable
                .extend(page.unreadable.into_iter().map(|(_, reason)| reason));
            fetched.cursor = page.next_cursor;
        }
        Ok(fetched)
    }

    /// Store `cursor` as the bank's, as a sync does after a page.
    async fn set_cursor(plaid: &PlaidService, item_id: &str, cursor: &str) {
        let mut session = plaid.begin_fetch(item_id).await.unwrap();
        let page = Page {
            next_cursor: cursor.to_owned(),
            ..Page::default()
        };
        assert!(plaid.commit_page(&mut session, &page).await.unwrap());
    }

    fn day(text: &str) -> chrono::NaiveDate {
        text.parse().unwrap()
    }

    /// A transaction as `/transactions/sync` lists it.
    pub(crate) fn sync_transaction(
        id: &str,
        account: &str,
        amount: f64,
        date: &str,
        pending: bool,
    ) -> Value {
        json!({
            "transaction_id": id, "account_id": account, "amount": amount,
            "iso_currency_code": "USD", "unofficial_currency_code": null,
            "date": date, "name": format!("Payment {id}"), "merchant_name": "Corner Shop",
            "pending": pending, "personal_finance_category": { "primary": "FOOD_AND_DRINK" },
        })
    }

    /// A fetch reads every page, from the stored cursor on, skips pending
    /// transactions, and hands back the last cursor without storing it.
    ///
    /// Bug-catch: stopping after the first page loses every transaction past
    /// it; storing the cursor at fetch, before the entries are written, loses
    /// them when the write fails.
    #[tokio::test]
    async fn a_fetch_reads_every_page_and_stores_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        plaid.connect(connect_token()).await.unwrap();
        mock.sync_page(json!({
            "added": [sync_transaction("t1", "acc1", 12.34, "2026-11-01", false),
                      sync_transaction("t2", "acc1", 5.0, "2026-11-02", true)],
            "modified": [], "removed": [{ "transaction_id": "t0" }],
            "next_cursor": "c1", "has_more": true,
        }));
        mock.sync_page(json!({
            "added": [sync_transaction("t3", "acc2", -100.0, "2026-11-03", false)],
            "modified": [], "removed": [], "next_cursor": "c2", "has_more": false,
        }));

        let fetched = fetch_all(&plaid, ITEM_ID).await.unwrap();
        let ids: Vec<&str> = fetched
            .added
            .iter()
            .map(|t| t.transaction_id.as_str())
            .collect();
        assert_eq!(ids, ["t1", "t3"]);
        assert_eq!(fetched.pending, 1);
        assert_eq!(fetched.changed, ["t0"]);
        assert_eq!(fetched.cursor, "c2");
        assert_eq!(fetched.added[0].amount.to_string(), "12.34");
        let bodies = mock.sync_bodies();
        assert!(
            bodies[0].get("cursor").is_none(),
            "the first sync starts at the beginning"
        );
        assert_eq!(bodies[1]["cursor"], "c1");

        fetch_all(&plaid, ITEM_ID).await.unwrap();
        assert!(
            mock.sync_bodies()[2].get("cursor").is_none(),
            "nothing was stored"
        );
        set_cursor(&plaid, ITEM_ID, "c2").await;
        fetch_all(&plaid, ITEM_ID).await.unwrap();
        assert_eq!(mock.sync_bodies()[3]["cursor"], "c2");
    }

    /// When Plaid says the history changed while being paged, the fetch starts
    /// again from its first cursor, as Plaid asks.
    ///
    /// Bug-catch: carrying on from the page that failed keeps half of an old
    /// view and half of a new one.
    #[tokio::test]
    async fn a_fetch_starts_again_when_plaid_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        plaid.connect(connect_token()).await.unwrap();
        mock.sync_page(json!({
            "added": [sync_transaction("t1", "acc1", 1.0, "2026-11-01", false)],
            "modified": [], "removed": [], "next_cursor": "c1", "has_more": true,
        }));
        mock.sync_error(400, "TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION");
        mock.sync_page(json!({
            "added": [sync_transaction("t1", "acc1", 1.0, "2026-11-01", false)],
            "modified": [], "removed": [], "next_cursor": "c9", "has_more": false,
        }));

        let fetched = fetch_all(&plaid, ITEM_ID).await.unwrap();
        // Page one, then all of it again from the first cursor: the link
        // skips what page one wrote.
        assert_eq!(fetched.added.len(), 2);
        assert_eq!(fetched.cursor, "c9");
        assert!(
            mock.sync_bodies()[2].get("cursor").is_none(),
            "started again"
        );
    }

    /// Mapping an account forgets the bank's cursor, so the next fetch reads
    /// its whole history again; mapping it to the same account keeps it.
    ///
    /// Bug-catch: keeping the cursor loses for good every transaction the
    /// account had before it was mapped.
    #[tokio::test]
    async fn mapping_an_account_starts_its_bank_from_the_beginning() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        plaid.connect(connect_token()).await.unwrap();
        set_cursor(&plaid, ITEM_ID, "c5").await;

        let connection = plaid
            .map_account(ITEM_ID, "acc1", "Assets:Bank:Checking", day("2026-01-01"))
            .await
            .unwrap();
        assert_eq!(
            connection.accounts[0].ledger_account.as_deref(),
            Some("Assets:Bank:Checking")
        );
        fetch_all(&plaid, ITEM_ID).await.unwrap();
        assert!(mock.sync_bodies()[0].get("cursor").is_none());

        set_cursor(&plaid, ITEM_ID, "c6").await;
        plaid
            .map_account(ITEM_ID, "acc1", "Assets:Bank:Checking", day("2026-01-01"))
            .await
            .unwrap();
        fetch_all(&plaid, ITEM_ID).await.unwrap();
        assert_eq!(mock.sync_bodies()[1]["cursor"], "c6");

        let error = plaid
            .map_account(ITEM_ID, "nope", "Assets:Bank:Checking", day("2026-01-01"))
            .await
            .unwrap_err();
        assert!(matches!(error, PlaidError::NoSuchBank(_)), "{error}");
    }

    /// The same bank linked a second time is refused, and the new connection
    /// removed at Plaid and here.
    ///
    /// Bug-catch: keeping both connections imports every transaction twice,
    /// each copy with its own transaction ids.
    #[tokio::test]
    async fn the_same_bank_linked_twice_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        plaid.connect(connect_token()).await.unwrap();
        *mock.next_item.lock().unwrap() = Some("item2".to_owned());

        let error = plaid.connect(connect_token()).await.unwrap_err();
        assert!(
            matches!(&error, PlaidError::AlreadyConnected { item_id } if item_id == ITEM_ID),
            "{error}"
        );
        assert!(mock.paths().contains(&"/item/remove".to_owned()));
        assert_eq!(connected_item_count(dir.path()).unwrap(), 1);
    }

    /// A disconnected bank leaves nothing behind, its sync cursor included,
    /// so it is not listed, and the ledger can be removed.
    ///
    /// Bug-catch: keeping the cursor keeps a bare bank listed and counted, and
    /// `BANKS_CONNECTED` then refuses removing the ledger for good.
    #[tokio::test]
    async fn a_disconnected_bank_leaves_no_cursor() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        plaid.connect(connect_token()).await.unwrap();
        set_cursor(&plaid, ITEM_ID, "c1").await;

        assert!(plaid.disconnect(ITEM_ID.to_owned()).await.unwrap());
        assert!(plaid.connections().await.unwrap().is_empty());
        assert_eq!(connected_item_count(dir.path()).unwrap(), 0);
    }

    /// A page's cursor is stored only over the one the sync last stored or
    /// began at: a cursor moved under it wins, and the sync stops there.
    ///
    /// Bug-catch: storing the cursor regardless loses the history a mapping
    /// asked to read again.
    #[tokio::test]
    async fn a_cursor_moved_under_a_sync_wins() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        plaid.connect(connect_token()).await.unwrap();
        set_cursor(&plaid, ITEM_ID, "c0").await;

        let mut session = plaid.begin_fetch(ITEM_ID).await.unwrap();
        assert_eq!(session.began_at(), Some("c0"));
        plaid
            .map_account(ITEM_ID, "acc2", "Assets:Bank:Savings", day("2026-01-01"))
            .await
            .unwrap();
        let page = Page {
            next_cursor: "c1".to_owned(),
            ..Page::default()
        };
        assert!(!plaid.commit_page(&mut session, &page).await.unwrap());
        fetch_all(&plaid, ITEM_ID).await.unwrap();
        assert!(
            mock.sync_bodies().last().unwrap().get("cursor").is_none(),
            "the mapping's reset kept"
        );
    }

    /// A mapping is refused while its bank syncs, the first sync included
    /// (no cursor yet, so a reset could not be seen); another bank's is not.
    ///
    /// Bug-catch: a mapping made during a bank's first sync is counted
    /// unmapped, the cursor moves past it, and its history never arrives.
    #[tokio::test]
    async fn a_mapping_waits_for_no_sync() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        plaid.connect(connect_token()).await.unwrap();
        let syncing = plaid.begin_sync(ITEM_ID).expect("free");
        let error = plaid
            .map_account(ITEM_ID, "acc1", "Assets:Bank:Checking", day("2026-01-01"))
            .await
            .unwrap_err();
        assert!(matches!(error, PlaidError::SyncInProgress), "{error}");
        drop(syncing);
        plaid
            .map_account(ITEM_ID, "acc1", "Assets:Bank:Checking", day("2026-01-01"))
            .await
            .unwrap();
    }

    /// One sync of a bank at a time; the next may start once it ends.
    ///
    /// Bug-catch: two syncs at once each read the books before the other
    /// writes, and import the same transactions twice.
    #[tokio::test]
    async fn one_sync_of_a_bank_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        let first = plaid.begin_sync(ITEM_ID).expect("free");
        assert!(plaid.begin_sync(ITEM_ID).is_none());
        assert!(plaid.begin_sync("another").is_some());
        drop(first);
        assert!(plaid.begin_sync(ITEM_ID).is_some());
    }

    /// A transaction this node cannot read (here one without a date, and one
    /// with an id Plaid does not issue) is noted, and the rest of the page still arrives.
    ///
    /// Bug-catch: failing the whole fetch on it stops every later sync of the
    /// bank at the same transaction.
    #[tokio::test]
    async fn an_unreadable_transaction_is_noted_not_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        plaid.connect(connect_token()).await.unwrap();
        mock.sync_page(json!({
            "added": [{ "transaction_id": "t9", "account_id": "acc1", "amount": 1.0, "date": null },
                      sync_transaction("t/1", "acc1", 1.0, "2026-11-01", false),
                      sync_transaction("t2", "acc1", 4.0, "2026-11-02", false)],
            "modified": [], "removed": [], "next_cursor": "c1", "has_more": false,
        }));

        let fetched = fetch_all(&plaid, ITEM_ID).await.unwrap();
        assert_eq!(fetched.added.len(), 1);
        assert_eq!(fetched.unreadable.len(), 2, "{:?}", fetched.unreadable);
        assert!(
            fetched
                .unreadable
                .iter()
                .any(|reason| reason.contains("transaction_id")),
            "{:?}",
            fetched.unreadable
        );
    }

    /// A link token for a connected bank is one in Plaid's update mode: the
    /// bank's access token, no products, nothing stored or changed here.
    ///
    /// Bug-catch: asking for a new connection instead makes Link create a
    /// second item for the same login — new ids, the history imported again.
    #[tokio::test]
    async fn a_login_again_link_token_is_for_the_same_connection() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        plaid.connect(connect_token()).await.unwrap();

        plaid
            .create_link_token("u_0123456789abcdef", Some(ITEM_ID))
            .await
            .unwrap();
        let body = mock.body_of("/link/token/create").unwrap();
        assert_eq!(body["access_token"], ACCESS_TOKEN);
        assert!(body.get("products").is_none(), "{body}");
        assert_eq!(body["user"]["client_user_id"], "u_0123456789abcdef");
        assert_eq!(body["client_name"], "NewGL");
        assert_eq!(body["country_codes"], json!(["US"]));
        assert_eq!(body["language"], "en");
        assert_eq!(connected_item_count(dir.path()).unwrap(), 1);

        plaid
            .create_link_token("u_0123456789abcdef", None)
            .await
            .unwrap();
        let body = mock.body_of("/link/token/create").unwrap();
        assert!(body.get("access_token").is_none(), "{body}");
        assert_eq!(body["products"], json!(["transactions"]));
    }

    /// A login-again token is only for a bank this ledger holds, with a token
    /// of this node's environment; nothing is sent to Plaid otherwise.
    ///
    /// Bug-catch: asking Plaid with no access token, or another environment's,
    /// gets a refusal that names no remedy.
    #[tokio::test]
    async fn a_login_again_link_token_needs_a_bank_of_this_ledger() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let env = env();
        let plaid = service(&mock, dir.path(), &env).await;
        plaid.connect(connect_token()).await.unwrap();
        let calls = mock.paths().len();

        let error = plaid
            .create_link_token("operator", Some("no-such-item"))
            .await
            .unwrap_err();
        assert!(matches!(error, PlaidError::NoSuchBank(_)), "{error}");
        plaid.close().await;
        let error = plaid
            .create_link_token("operator", Some(ITEM_ID))
            .await
            .unwrap_err();
        assert!(matches!(error, PlaidError::Closing), "{error}");
        drop(plaid);
        let production = PlaidConfig {
            environment: PlaidEnvironment::Production,
            ..enabled()
        };
        let plaid = service_in(&mock, dir.path(), &env, production).await;
        let error = plaid
            .create_link_token("operator", Some(ITEM_ID))
            .await
            .unwrap_err();
        assert!(
            matches!(error, PlaidError::WrongEnvironment { .. }),
            "{error}"
        );
        assert_eq!(mock.paths().len(), calls, "nothing sent to Plaid");
    }

    /// A public token for a bank this ledger holds already — Link's update
    /// mode hands one back too — changes nothing: its mappings and its sync
    /// cursor stay.
    ///
    /// Bug-catch: storing over it resets the bank to a bare description, and
    /// every account's mapping is lost without a word.
    #[tokio::test]
    async fn connecting_a_held_bank_again_changes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        plaid.connect(connect_token()).await.unwrap();
        plaid
            .map_account(ITEM_ID, "acc1", "Assets:Bank:Checking", day("2026-01-01"))
            .await
            .unwrap();
        set_cursor(&plaid, ITEM_ID, "c5").await;

        let again = plaid.connect(connect_token()).await.unwrap();
        assert_eq!(
            again.accounts[0].ledger_account.as_deref(),
            Some("Assets:Bank:Checking")
        );
        assert_eq!(
            plaid.connections().await.unwrap()[0].accounts[0]
                .ledger_account
                .as_deref(),
            Some("Assets:Bank:Checking")
        );
        fetch_all(&plaid, ITEM_ID).await.unwrap();
        assert_eq!(mock.sync_bodies().last().unwrap()["cursor"], "c5");
        assert!(!mock.paths().contains(&"/item/remove".to_owned()));
    }

    /// A refused sync's Plaid code is kept on the bank, and a finished sync
    /// clears it and notes the time.
    ///
    /// Bug-catch: without it the app cannot tell a bank that needs a new
    /// login from one that is fine, short of syncing and failing.
    #[tokio::test]
    async fn a_banks_health_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        plaid.connect(connect_token()).await.unwrap();

        plaid
            .note_health(ITEM_ID, Some("ITEM_LOGIN_REQUIRED"))
            .await;
        let bank = &plaid.connections().await.unwrap()[0];
        assert_eq!(bank.last_error_code.as_deref(), Some("ITEM_LOGIN_REQUIRED"));
        assert!(bank.last_synced_at.is_none());

        plaid.note_health(ITEM_ID, None).await;
        let bank = &plaid.connections().await.unwrap()[0];
        assert!(bank.last_error_code.is_none());
        assert!(bank.last_synced_at.is_some());
    }

    /// Reading a bank's accounts again adds the ones it opened since, keeps
    /// every mapping, and keeps an account Plaid no longer lists.
    ///
    /// Bug-catch: replacing the list loses every mapping; not reading it
    /// again leaves a new account unmappable for good.
    #[tokio::test]
    async fn refreshing_accounts_adds_new_ones_and_keeps_mappings() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        plaid.connect(connect_token()).await.unwrap();
        plaid
            .map_account(ITEM_ID, "acc1", "Assets:Bank:Checking", day("2026-01-01"))
            .await
            .unwrap();
        *mock.accounts.lock().unwrap() = Some(json!([
            { "account_id": "acc1", "name": "Plaid Checking (renamed)", "mask": "0000",
              "type": "depository", "subtype": "checking" },
            { "account_id": "acc3", "name": "Plaid CD", "mask": "2222",
              "type": "depository", "subtype": "cd" },
        ]));

        let bank = plaid.refresh_accounts(ITEM_ID).await.unwrap();
        let ids: Vec<&str> = bank
            .accounts
            .iter()
            .map(|a| a.account_id.as_str())
            .collect();
        assert_eq!(ids, ["acc1", "acc2", "acc3"]);
        assert_eq!(bank.accounts[0].name, "Plaid Checking (renamed)");
        assert_eq!(
            bank.accounts[0].ledger_account.as_deref(),
            Some("Assets:Bank:Checking")
        );
        assert!(bank.accounts[2].ledger_account.is_none());
        assert_eq!(
            plaid.connections().await.unwrap()[0].accounts.len(),
            3,
            "stored"
        );
    }

    /// Unmapping clears an account's mapping and start date; it waits for no
    /// sync, as a mapping does not.
    ///
    /// Bug-catch: an unmapping under a sync is undone by the sync's view of
    /// the old mapping, and the account goes on being imported.
    #[tokio::test]
    async fn unmapping_stops_an_account() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        plaid.connect(connect_token()).await.unwrap();
        plaid
            .map_account(ITEM_ID, "acc1", "Assets:Bank:Checking", day("2026-01-01"))
            .await
            .unwrap();

        let syncing = plaid.begin_sync(ITEM_ID).expect("free");
        let error = plaid.unmap_account(ITEM_ID, "acc1").await.unwrap_err();
        assert!(matches!(error, PlaidError::SyncInProgress), "{error}");
        drop(syncing);
        let bank = plaid.unmap_account(ITEM_ID, "acc1").await.unwrap();
        assert!(bank.accounts[0].ledger_account.is_none());
        assert!(bank.accounts[0].import_from.is_none());
        assert!(plaid.connections().await.unwrap()[0].accounts[0]
            .ledger_account
            .is_none());
    }

    /// In the sandbox a test bank connects without Link: Plaid makes the
    /// public token, the usual connect keeps the access token.
    ///
    /// Bug-catch: a sandbox helper that skips the usual connect would keep no
    /// token, or keep it outside the secret store.
    #[tokio::test]
    async fn a_sandbox_bank_connects_without_link() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;

        let bank = plaid.connect_sandbox("ins_109508").await.unwrap();
        assert_eq!(bank.item_id, ITEM_ID);
        let create = mock.body_of("/sandbox/public_token/create").unwrap();
        assert_eq!(create["institution_id"], "ins_109508");
        assert_eq!(create["initial_products"], json!(["transactions"]));
        assert_eq!(
            mock.body_of("/item/public_token/exchange").unwrap()["public_token"],
            "public-sandbox-from-the-sandbox"
        );
        assert_eq!(connected_item_count(dir.path()).unwrap(), 1);

        plaid.reset_sandbox_login(ITEM_ID).await.unwrap();
        assert_eq!(
            mock.body_of("/sandbox/item/reset_login").unwrap()["access_token"],
            ACCESS_TOKEN
        );
    }

    /// The sandbox helpers are refused, with nothing sent, on production.
    ///
    /// Bug-catch: a demo helper reaching production would ask the real Plaid
    /// for a test bank, or reset a real customer's bank login.
    #[tokio::test]
    async fn the_sandbox_helpers_stay_in_the_sandbox() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let production = PlaidConfig {
            environment: PlaidEnvironment::Production,
            ..enabled()
        };
        let plaid = service_in(&mock, dir.path(), &env(), production).await;

        let error = plaid.connect_sandbox("ins_109508").await.unwrap_err();
        assert!(matches!(error, PlaidError::SandboxOnly), "{error}");
        let error = plaid.reset_sandbox_login(ITEM_ID).await.unwrap_err();
        assert!(matches!(error, PlaidError::SandboxOnly), "{error}");
        assert!(mock.paths().is_empty(), "{:?}", mock.paths());
    }

    /// A refresh that finds its bank disconnected while Plaid was asked
    /// writes nothing back: no bank without a token is left listed.
    ///
    /// Bug-catch: writing the description back leaves a bank that cannot be
    /// disconnected, synced or cleared, and refuses the ledger's removal for
    /// good (`BANKS_CONNECTED`).
    #[tokio::test]
    async fn a_refresh_racing_a_disconnect_leaves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        plaid.connect(connect_token()).await.unwrap();
        mock.delay("/accounts/get", Duration::from_millis(300));
        let asked = || {
            mock.paths()
                .iter()
                .filter(|path| path.as_str() == "/accounts/get")
                .count()
        };
        let before = asked();

        let refreshing = tokio::spawn({
            let plaid = Arc::clone(&plaid);
            async move { plaid.refresh_accounts(ITEM_ID).await }
        });
        while asked() == before {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(plaid.disconnect(ITEM_ID.to_owned()).await.unwrap());

        let error = refreshing.await.unwrap().unwrap_err();
        assert!(matches!(error, PlaidError::NoSuchBank(_)), "{error}");
        assert_eq!(connected_item_count(dir.path()).unwrap(), 0);
        assert!(plaid.connections().await.unwrap().is_empty());
    }

    /// With `plaid.webhookUrl`, new link tokens carry it and
    /// `update_webhooks` gives it to every bank already connected; without
    /// it, the update is refused and nothing sent.
    ///
    /// Bug-catch: a link token without the address leaves new banks without
    /// webhooks; banks connected earlier keep none until told.
    #[tokio::test]
    async fn the_webhook_address_reaches_every_bank() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let env = env();
        let plaid = service(&mock, dir.path(), &env).await;
        plaid.connect(connect_token()).await.unwrap();
        let error = plaid.update_webhooks().await.unwrap_err();
        assert!(matches!(error, PlaidError::NoWebhookUrl), "{error}");
        assert!(mock.body_of("/item/webhook/update").is_none());
        plaid.close().await;
        drop(plaid);

        let url = "https://ledger.example.com/ledgers/acme/plaid/webhook";
        let with_url = PlaidConfig {
            webhook_url: Some(url.to_owned()),
            ..enabled()
        };
        let plaid = service_in(&mock, dir.path(), &env, with_url).await;
        plaid.create_link_token("operator", None).await.unwrap();
        assert_eq!(mock.body_of("/link/token/create").unwrap()["webhook"], url);
        assert_eq!(plaid.update_webhooks().await.unwrap(), 1);
        let update = mock.body_of("/item/webhook/update").unwrap();
        assert_eq!(update["webhook"], url);
        assert_eq!(update["access_token"], ACCESS_TOKEN);
    }

    /// The sandbox can be asked to send a webhook; never elsewhere.
    ///
    /// Bug-catch: a demo helper reaching production asks the real Plaid to
    /// fire webhooks at a customer's bank.
    #[tokio::test]
    async fn a_sandbox_webhook_can_be_fired() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let env = env();
        let plaid = service(&mock, dir.path(), &env).await;
        plaid.connect(connect_token()).await.unwrap();
        plaid
            .fire_sandbox_webhook(ITEM_ID, "SYNC_UPDATES_AVAILABLE")
            .await
            .unwrap();
        let fired = mock.body_of("/sandbox/item/fire_webhook").unwrap();
        assert_eq!(fired["webhook_code"], "SYNC_UPDATES_AVAILABLE");
        assert_eq!(fired["access_token"], ACCESS_TOKEN);

        let production = PlaidConfig {
            environment: PlaidEnvironment::Production,
            ..enabled()
        };
        let calls = mock.paths().len();
        plaid.close().await;
        drop(plaid);
        let plaid = service_in(&mock, dir.path(), &env, production).await;
        let error = plaid
            .fire_sandbox_webhook(ITEM_ID, "SYNC_UPDATES_AVAILABLE")
            .await
            .unwrap_err();
        assert!(matches!(error, PlaidError::SandboxOnly), "{error}");
        assert_eq!(mock.paths().len(), calls);
    }

    /// One webhook sync of a bank queued at a time; the next may queue once
    /// it ends.
    ///
    /// Bug-catch: every webhook queuing its own sync piles up tasks, each
    /// waiting 30 s at a time behind the one running.
    #[tokio::test]
    async fn one_webhook_sync_of_a_bank_queued_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        let queued = plaid.queue_webhook_sync(ITEM_ID).expect("free");
        assert!(plaid.queue_webhook_sync(ITEM_ID).is_none());
        assert!(plaid.queue_webhook_sync("another").is_some());
        drop(queued);
        assert!(plaid.queue_webhook_sync(ITEM_ID).is_some());
    }

    /// A webhook that comes while a bank's webhook sync runs has it go once
    /// more, once however many came; when it is done, the next webhook
    /// queues a sync of its own, and the ended guard leaves that one's mark.
    ///
    /// Bug-catch: a webhook during a sync dropped leaves what Plaid has since
    /// at Plaid until the next webhook, maybe days; an ended guard dropping
    /// the next sync's mark lets a third sync queue beside it.
    #[tokio::test]
    async fn a_webhook_during_a_sync_has_it_go_once_more() {
        let dir = tempfile::tempdir().unwrap();
        let mock = MockPlaid::default();
        let plaid = service(&mock, dir.path(), &env()).await;
        let mut queued = plaid.queue_webhook_sync(ITEM_ID).expect("free");
        assert!(!queued.go_again(), "nothing came: done");
        let mut queued = plaid.queue_webhook_sync(ITEM_ID).expect("free again");
        assert!(plaid.queue_webhook_sync(ITEM_ID).is_none());
        assert!(plaid.queue_webhook_sync(ITEM_ID).is_none());
        assert!(queued.go_again(), "two came: once more");
        assert!(!queued.go_again(), "and once only");

        let next = plaid
            .queue_webhook_sync(ITEM_ID)
            .expect("a sync of its own");
        drop(queued);
        assert!(
            plaid.queue_webhook_sync(ITEM_ID).is_none(),
            "the next sync's mark is kept"
        );
        drop(next);
    }
}
