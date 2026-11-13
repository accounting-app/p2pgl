//! The Plaid fields (`docs/build-log/007-plaid-commitments`, steps 5 and 6):
//! `createPlaidLinkToken`, `connectBank`, `disconnectBank`, `mapBankAccount`
//! and `syncBank` (admin only: [`crate::access_control::ADMIN_FIELDS`]) and
//! `connectedBanks` (read). None of them ever returns an access token.

use std::collections::HashMap;
use std::sync::Arc;

use async_graphql::{Context, ErrorExtensions, Result, SimpleObject};
use ledger::model::{Amount, Flag};
use ledger::service::{PostingInput, TransactionInput};

use super::SharedLedger;
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
    /// The ledger account its transactions are imported to; null until an
    /// admin maps it (`mapBankAccount`), and nothing is imported until then.
    pub ledger_account: Option<String>,
    /// The first date imported (`mapBankAccount`'s `importFrom`).
    pub import_from: Option<super::scalars::DateScalar>,
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
                    ledger_account: account.ledger_account,
                    import_from: account.import_from.map(super::scalars::DateScalar),
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

pub(super) async fn create_link_token(
    ctx: &Context<'_>,
    item_id: Option<String>,
) -> Result<PlaidLinkToken> {
    let token = service(ctx)?
        .create_link_token(&client_user_id(ctx), item_id.as_deref())
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

/// What one `syncBank` did.
#[derive(SimpleObject, Debug, Clone, Default)]
pub struct BankSync {
    /// Entries written, each flagged `!` for review.
    pub imported: usize,
    /// Transactions whose entry (`^plaid-<transaction id>`) the books already
    /// hold: skipped.
    pub already_imported: usize,
    /// Pending transactions, skipped: imported once the bank posts them.
    pub skipped_pending: usize,
    /// Transactions of accounts not mapped to a ledger account: imported once
    /// `mapBankAccount` maps them.
    pub skipped_unmapped: usize,
    /// Transactions dated before their account's `importFrom`: skipped.
    pub skipped_before_start: usize,
    /// What the accountant should look at, one note per transaction: an
    /// imported one Plaid changed or removed since, one the ledger refused
    /// (and why), one without a currency or amount, one this node could not
    /// read. Nothing is reversed or retried for them; enter what is needed
    /// by hand.
    pub needs_review: Vec<BankSyncNote>,
    /// Why the sync stopped before the end, when it stopped once a page was
    /// stored (Plaid unreachable, the node's disk): what it did is kept, and
    /// the next sync goes on from its last page. Null when it finished.
    pub stopped_by: Option<String>,
}

/// One transaction for review, and why.
#[derive(SimpleObject, Debug, Clone)]
pub struct BankSyncNote {
    /// Plaid's transaction id, when there is one this node can repeat.
    pub transaction_id: Option<String>,
    pub reason: String,
}

/// Note `transaction_id` for review, once, and log it at once: a sync that
/// fails later still leaves the note in the node's log.
fn note(
    sync: &mut BankSync,
    item_id: &str,
    transaction_id: Option<&str>,
    reason: impl Into<String>,
) {
    let note = BankSyncNote {
        transaction_id: transaction_id.map(str::to_owned),
        reason: reason.into(),
    };
    if sync
        .needs_review
        .iter()
        .any(|other| other.transaction_id == note.transaction_id && other.reason == note.reason)
    {
        return;
    }
    tracing::warn!(item_id = %item_id, transaction_id = note.transaction_id.as_deref().unwrap_or("-"), reason = %note.reason, "a bank transaction for review");
    sync.needs_review.push(note);
}

/// The codes `appendTransaction` gives when it refuses **this entry** for
/// what it says (its account, currency, balance, date, text). Such an entry is
/// noted and the sync goes on. Any other refusal — the disk, the journal, the
/// ledger's size cap, a commit in flight — stops the sync with its cursor
/// kept, so the entry is tried again next time instead of skipped for good.
const ENTRY_REFUSALS: &[&str] = &[
    "ACCOUNT_CLOSED",
    "ACCOUNT_CURRENCY_MISMATCH",
    "ACCOUNT_NOT_OPEN",
    "ELIDED_POSTING_INVALID",
    "INVALID_POSTING",
    "UNBALANCED_TRANSACTION",
    "INVALID_CURRENCY",
    "INVALID_INPUT",
    "INVALID_LINK",
    "INVALID_TAG",
    "INVALID_ACCOUNT_NAME",
    "DATE_OUT_OF_RANGE",
];

fn refused(code: &'static str, message: String) -> async_graphql::Error {
    async_graphql::Error::new(message).extend_with(|_, ext| ext.set("code", code))
}

fn ledger<'a>(ctx: &Context<'a>) -> Result<&'a SharedLedger> {
    ctx.data::<SharedLedger>().map_err(|_| {
        async_graphql::Error::new("Ledger service not initialized")
            .extend_with(|_, ext| ext.set("code", "INTERNAL"))
    })
}

/// The date `account` was opened, when it is open in the ledger now.
async fn opened_on(ledger: &SharedLedger, account: &str) -> Option<chrono::NaiveDate> {
    ledger
        .read()
        .await
        .accounts()
        .summaries()
        .into_iter()
        .find(|summary| summary.name == account && summary.closed_on.is_none())
        .map(|summary| summary.opened_on)
}

pub(super) async fn map_bank_account(
    ctx: &Context<'_>,
    item_id: String,
    account_id: String,
    ledger_account: String,
    import_from: Option<chrono::NaiveDate>,
) -> Result<ConnectedBank> {
    let plaid = service(ctx)?;
    if ledger_account == plaid.suspense_account() {
        return Err(refused(
            "INVALID_INPUT",
            format!(
                "{ledger_account} is plaid.suspenseAccount, the other side of every imported \
                 entry: map the bank account to an account of its own"
            ),
        ));
    }
    let Some(opened) = opened_on(ledger(ctx)?, &ledger_account).await else {
        return Err(refused(
            "ACCOUNT_NOT_OPEN",
            format!("{ledger_account} is not an open account of this ledger: open it first"),
        ));
    };
    let import_from = import_from.unwrap_or(opened);
    let connection = plaid
        .map_account(&item_id, &account_id, &ledger_account, import_from)
        .await
        .map_err(failed)?;
    Ok(connection.into())
}

/// The link an imported transaction carries: how a repeated sync knows it.
fn import_link(transaction_id: &str) -> String {
    format!("plaid-{transaction_id}")
}

/// Fetch what Plaid has for bank `item_id` since the last sync and write one
/// entry per posted transaction of a mapped account dated on or after its
/// `importFrom` and the suspense account's open date (decisions 6–10): its
/// date, payee and narration from Plaid, flag `!`, link `^plaid-<id>`, the
/// mapped account with the amount (Plaid counts money out as positive, so the
/// sign is turned) and the suspense account balancing it. Each entry goes
/// through `appendTransaction`'s path; one the ledger refuses for what it says
/// is noted and skipped. Page by page: a page's cursor is stored once its
/// entries are written, so a sync cut short (the request timeout, a node
/// failure) goes on from the last page written next time, and writes nothing
/// twice. A sync that stops once a page is stored answers with what it did
/// and `stoppedBy`, so the notes of the pages it stored are not lost.
pub(super) async fn sync_bank(ctx: &Context<'_>, item_id: String) -> Result<BankSync> {
    let plaid = service(ctx)?;
    let ledger = ledger(ctx)?;
    let suspense = plaid.suspense_account().to_owned();
    let Some(suspense_opened) = opened_on(ledger, &suspense).await else {
        return Err(refused(
            "ACCOUNT_NOT_OPEN",
            format!(
                "{suspense} (plaid.suspenseAccount) is not an open account of this ledger: open \
                 it first; nothing was imported"
            ),
        ));
    };
    let Some(_syncing) = plaid.begin_sync(&item_id) else {
        return Err(refused(
            "SYNC_IN_PROGRESS",
            format!("bank {item_id} is being synced already; try again once that ends"),
        ));
    };
    let mut session = plaid.begin_fetch(&item_id).await.map_err(failed)?;
    // The first day an entry can be written: on or after the mapping's
    // `importFrom`, and not before the suspense account was opened (it is
    // one side of every entry).
    let mapped: HashMap<String, (String, chrono::NaiveDate)> = session
        .connection
        .accounts
        .iter()
        .filter_map(|account| {
            let start = account
                .import_from
                .map_or(suspense_opened, |first| first.max(suspense_opened));
            Some((
                account.account_id.clone(),
                (account.ledger_account.clone()?, start),
            ))
        })
        .collect();
    let mut held = held_imports(ledger, &suspense).await;
    let mut sync = BankSync::default();
    let mut stored_a_page = false;
    loop {
        let page = match plaid.next_page(&mut session).await {
            Ok(Some(page)) => page,
            Ok(None) => break,
            Err(error) => return stopped(sync, &item_id, stored_a_page, failed(error)),
        };
        sync.skipped_pending += page.pending;
        for (id, reason) in &page.unreadable {
            note(&mut sync, &item_id, id.as_deref(), reason.clone());
        }
        for transaction in &page.added {
            let id = transaction.transaction_id.as_str();
            let Some((account, start)) = mapped.get(&transaction.account_id) else {
                sync.skipped_unmapped += 1;
                continue;
            };
            if transaction.date < *start {
                sync.skipped_before_start += 1;
                continue;
            }
            let link = import_link(id);
            if let Some(entry) = held.get(&link) {
                sync.already_imported += 1;
                // Sent again with another date or amount (a restart from an
                // earlier cursor, or Plaid revising it): the books keep what
                // was written, the accountant is told.
                if entry.date != transaction.date
                    || entry
                        .amount
                        .is_some_and(|amount| amount != -transaction.amount)
                {
                    note(
                        &mut sync,
                        &item_id,
                        Some(id),
                        "changed at Plaid after it was imported (another date or amount)",
                    );
                }
                continue;
            }
            let Some(currency) = &transaction.currency else {
                note(
                    &mut sync,
                    &item_id,
                    Some(id),
                    "no currency from Plaid: not imported",
                );
                continue;
            };
            if transaction.amount.is_zero() {
                note(
                    &mut sync,
                    &item_id,
                    Some(id),
                    "a zero amount: nothing to book",
                );
                continue;
            }
            let entry = TransactionInput {
                date: transaction.date,
                flag: Flag::Incomplete,
                payee: transaction.merchant_name.clone(),
                narration: transaction.name.clone(),
                tags: Vec::new(),
                links: vec![link.clone()],
                postings: vec![
                    PostingInput {
                        account: account.clone(),
                        amount: Some(Amount {
                            number: -transaction.amount,
                            currency: currency.clone(),
                        }),
                        cost: None,
                        price: None,
                    },
                    PostingInput {
                        account: suspense.clone(),
                        amount: None,
                        cost: None,
                        price: None,
                    },
                ],
            };
            match super::mutation::append_transaction_input(ctx, ledger, entry).await {
                Ok(appended) if appended.already_existed => sync.already_imported += 1,
                Ok(_) => sync.imported += 1,
                Err(error) => {
                    let code = error
                        .extensions
                        .as_ref()
                        .and_then(|ext| ext.get("code"))
                        .and_then(|code| match code {
                            async_graphql::Value::String(code) => Some(code.clone()),
                            _ => None,
                        })
                        .unwrap_or_default();
                    if !ENTRY_REFUSALS.contains(&code.as_str()) {
                        return stopped(sync, &item_id, stored_a_page, error);
                    }
                    note(
                        &mut sync,
                        &item_id,
                        Some(id),
                        format!("refused by the ledger ({code}): {}", error.message),
                    );
                    continue;
                }
            }
            held.insert(
                link,
                HeldImport {
                    date: transaction.date,
                    amount: Some(-transaction.amount),
                },
            );
        }
        for id in &page.changed {
            if held.contains_key(&import_link(id)) {
                note(
                    &mut sync,
                    &item_id,
                    Some(id),
                    "changed or removed at Plaid after it was imported",
                );
            }
        }
        match plaid.commit_page(&mut session, &page).await {
            Ok(true) => stored_a_page = true,
            Ok(false) => break,
            Err(error) => return stopped(sync, &item_id, stored_a_page, failed(error)),
        }
    }
    tracing::info!(
        item_id = %item_id,
        imported = sync.imported,
        already_imported = sync.already_imported,
        skipped_pending = sync.skipped_pending,
        skipped_unmapped = sync.skipped_unmapped,
        skipped_before_start = sync.skipped_before_start,
        needs_review = sync.needs_review.len(),
        restarted = session.restarted,
        "bank synced"
    );
    Ok(sync)
}

/// An imported entry as the books hold it: its date and the bank leg.
struct HeldImport {
    date: chrono::NaiveDate,
    amount: Option<rust_decimal::Decimal>,
}

/// Every entry in the books carrying an import link, by link: what a sync
/// skips, and compares what Plaid sends again with.
async fn held_imports(ledger: &SharedLedger, suspense: &str) -> HashMap<String, HeldImport> {
    let ledger = ledger.read().await;
    let mut held = HashMap::new();
    for transaction in ledger.dag().transactions() {
        for link in &transaction.links {
            if !link.starts_with("plaid-") {
                continue;
            }
            let amount = transaction
                .postings
                .iter()
                .find(|posting| posting.account != suspense)
                .and_then(|posting| posting.amount.as_ref())
                .map(|amount| amount.number);
            held.insert(
                link.clone(),
                HeldImport {
                    date: transaction.date,
                    amount,
                },
            );
        }
    }
    held
}

/// A sync that cannot go on: an error while nothing is stored (the next sync
/// does it all again), or — once a page is stored — what it did, with
/// `stoppedBy`, so the notes of the pages stored are not lost with it.
fn stopped(
    mut sync: BankSync,
    item_id: &str,
    stored_a_page: bool,
    error: async_graphql::Error,
) -> Result<BankSync> {
    tracing::warn!(item_id = %item_id, error = %error.message, "a bank sync stopped; the pages written are kept, the next sync goes on from there");
    if !stored_a_page {
        return Err(error);
    }
    sync.stopped_by = Some(error.message);
    Ok(sync)
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
        let map = format!(
            r#"mutation {{ mapBankAccount(itemId: "{ITEM_ID}", accountId: "acc1", ledgerAccount: "Assets:Bank") {{ itemId }} }}"#
        );
        let sync = sync();
        for query in [
            LINK,
            CONNECT,
            disconnect.as_str(),
            map.as_str(),
            sync.as_str(),
        ] {
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

    async fn operator(schema: &AppSchema, query: &str) -> Value {
        let response = schema
            .execute(async_graphql::Request::new(query).data(Caller::operator()))
            .await;
        serde_json::to_value(&response).unwrap()
    }

    /// A ledger with Plaid on, its bank connected, `Assets:Bank:Checking`
    /// (and, when `suspense`, `Expenses:Uncategorized`) open since 2026-01-01,
    /// and the bank's checking account mapped to it.
    async fn mapped(suspense: bool) -> Fixture {
        let fixture = fixture(true).await;
        let mut accounts = vec!["Assets:Bank:Checking"];
        if suspense {
            accounts.push("Expenses:Uncategorized");
        }
        for account in accounts {
            let body = operator(
                &fixture.schema,
                &format!(r#"mutation {{ openAccount(name: "{account}", date: "2026-01-01") }}"#),
            )
            .await;
            assert!(body["errors"].is_null(), "{body}");
        }
        let body = operator(&fixture.schema, CONNECT).await;
        assert!(body["errors"].is_null(), "{body}");
        let map = format!(
            r#"mutation {{ mapBankAccount(itemId: "{ITEM_ID}", accountId: "acc1", ledgerAccount: "Assets:Bank:Checking") {{ accounts {{ accountId ledgerAccount }} }} }}"#
        );
        let body = operator(&fixture.schema, &map).await;
        assert!(body["errors"].is_null(), "{body}");
        assert_eq!(
            body["data"]["mapBankAccount"]["accounts"][0]["ledgerAccount"],
            "Assets:Bank:Checking"
        );
        fixture
    }

    fn sync() -> String {
        format!(
            r#"mutation {{ syncBank(itemId: "{ITEM_ID}") {{ imported alreadyImported skippedPending skippedUnmapped skippedBeforeStart needsReview {{ transactionId reason }} stoppedBy }} }}"#
        )
    }

    const JOURNAL: &str =
        "{ journal { date flag payee narration links postings { account amount { number currency } } } }";

    fn page(added: Vec<Value>, changed: Vec<Value>, removed: Vec<&str>) -> Value {
        serde_json::json!({
            "added": added, "modified": changed,
            "removed": removed.iter().map(|id| serde_json::json!({ "transaction_id": id })).collect::<Vec<_>>(),
            "next_cursor": "c1", "has_more": false,
        })
    }

    /// A sync writes one entry per posted transaction of a mapped account:
    /// flagged `!`, linked `^plaid-<id>`, money out of the bank as a negative
    /// posting to it, the suspense account balancing it; pending and unmapped
    /// transactions are skipped and counted.
    ///
    /// Bug-catch: keeping Plaid's sign posts every payment as a deposit.
    #[tokio::test]
    async fn a_sync_writes_one_entry_per_posted_transaction() {
        let fixture = mapped(true).await;
        fixture.mock.sync_page(page(
            vec![
                mock::sync_transaction("t1", "acc1", 12.34, "2026-11-01", false),
                mock::sync_transaction("t2", "acc1", 3.0, "2026-11-02", true),
                mock::sync_transaction("t3", "acc2", 50.0, "2026-11-02", false),
                mock::sync_transaction("t4", "acc1", -200.0, "2026-11-03", false),
            ],
            vec![],
            vec![],
        ));

        let body = operator(&fixture.schema, &sync()).await;
        assert!(body["errors"].is_null(), "{body}");
        let counts = &body["data"]["syncBank"];
        assert_eq!(counts["imported"], 2, "{body}");
        assert_eq!(counts["skippedPending"], 1);
        assert_eq!(counts["skippedUnmapped"], 1);

        let journal = operator(&fixture.schema, JOURNAL).await;
        let entries = journal["data"]["journal"].as_array().unwrap().clone();
        let coffee = entries
            .iter()
            .find(|entry| entry["links"] == serde_json::json!(["plaid-t1"]))
            .unwrap_or_else(|| panic!("t1 imported: {journal}"));
        assert_eq!(coffee["flag"], "!");
        assert_eq!(coffee["date"], "2026-11-01");
        assert_eq!(coffee["payee"], "Corner Shop");
        let posting = |account: &str| {
            coffee["postings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|posting| posting["account"] == account)
                .map(|posting| posting["amount"]["number"].as_str().unwrap().to_owned())
        };
        assert_eq!(posting("Assets:Bank:Checking").as_deref(), Some("-12.34"));
        assert_eq!(posting("Expenses:Uncategorized").as_deref(), Some("12.34"));
        let deposit = entries
            .iter()
            .find(|entry| entry["links"] == serde_json::json!(["plaid-t4"]))
            .expect("t4 imported");
        let bank_leg = deposit["postings"]
            .as_array()
            .unwrap()
            .iter()
            .find(|posting| posting["account"] == "Assets:Bank:Checking")
            .map(|posting| posting["amount"]["number"].as_str().unwrap().to_owned())
            .unwrap();
        let bank_leg: rust_decimal::Decimal = bank_leg.parse().unwrap();
        assert_eq!(
            bank_leg,
            rust_decimal::Decimal::from(200),
            "a deposit adds to the bank"
        );
    }

    /// A transaction the books already hold is skipped: syncing again, or
    /// after a mapping sent the bank's history again, imports nothing twice —
    /// also when someone else syncs, whose entry would be another record.
    ///
    /// Bug-catch: without the link check, a second admin's sync doubles the
    /// books (the content id alone only catches the same person twice).
    #[tokio::test]
    async fn a_repeated_sync_imports_nothing_twice() {
        let fixture = mapped(true).await;
        let added = || {
            vec![mock::sync_transaction(
                "t1",
                "acc1",
                12.34,
                "2026-11-01",
                false,
            )]
        };
        fixture.mock.sync_page(page(added(), vec![], vec![]));
        fixture.mock.sync_page(page(added(), vec![], vec![]));

        let first = operator(&fixture.schema, &sync()).await;
        assert_eq!(first["data"]["syncBank"]["imported"], 1, "{first}");
        let second = run(&fixture.schema, Role::Admin, &sync()).await;
        assert_eq!(second["data"]["syncBank"]["imported"], 0, "{second}");
        assert_eq!(second["data"]["syncBank"]["alreadyImported"], 1);
        let journal = operator(&fixture.schema, JOURNAL).await;
        let imported = journal["data"]["journal"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["links"] == serde_json::json!(["plaid-t1"]))
            .count();
        assert_eq!(imported, 1);
    }

    /// A transaction dated before its account's `importFrom` — by default the
    /// day the ledger account was opened — is skipped, not refused.
    ///
    /// Bug-catch: without the start date, Plaid's months of history before
    /// the account was opened are refused one by one.
    #[tokio::test]
    async fn a_transaction_before_the_start_date_is_skipped() {
        let fixture = mapped(true).await;
        fixture.mock.sync_page(page(
            vec![
                mock::sync_transaction("t1", "acc1", 1.0, "2026-11-01", false),
                mock::sync_transaction("t2", "acc1", 2.0, "2025-06-01", false),
            ],
            vec![],
            vec![],
        ));

        let body = operator(&fixture.schema, &sync()).await;
        assert!(body["errors"].is_null(), "{body}");
        assert_eq!(body["data"]["syncBank"]["imported"], 1, "{body}");
        assert_eq!(body["data"]["syncBank"]["skippedBeforeStart"], 1);
        assert_eq!(
            body["data"]["syncBank"]["needsReview"],
            serde_json::json!([])
        );
    }

    /// An entry the ledger refuses for what it says is noted, with Plaid's id
    /// and the reason, and the sync goes on and stores its cursor.
    ///
    /// Bug-catch: stopping at the refused entry leaves the cursor where it
    /// was, and every later sync of the bank stops at the same entry.
    #[tokio::test]
    async fn an_entry_the_ledger_refuses_is_noted_and_the_sync_goes_on() {
        let fixture = mapped(true).await;
        let open = r#"mutation { openAccount(name: "Assets:Bank:Dollars", date: "2026-01-01", currencies: ["USD"]) }"#;
        let body = operator(&fixture.schema, open).await;
        assert!(body["errors"].is_null(), "{body}");
        let map = format!(
            r#"mutation {{ mapBankAccount(itemId: "{ITEM_ID}", accountId: "acc1", ledgerAccount: "Assets:Bank:Dollars") {{ itemId }} }}"#
        );
        let body = operator(&fixture.schema, &map).await;
        assert!(body["errors"].is_null(), "{body}");
        let mut euros = mock::sync_transaction("t2", "acc1", 2.0, "2026-10-01", false);
        euros["iso_currency_code"] = serde_json::json!("EUR");
        fixture.mock.sync_page(page(
            vec![
                euros,
                mock::sync_transaction("t1", "acc1", 1.0, "2026-11-01", false),
            ],
            vec![],
            vec![],
        ));

        let body = operator(&fixture.schema, &sync()).await;
        assert!(body["errors"].is_null(), "{body}");
        let sync_result = &body["data"]["syncBank"];
        assert_eq!(sync_result["imported"], 1, "{body}");
        assert_eq!(sync_result["needsReview"][0]["transactionId"], "t2");
        assert!(
            sync_result["needsReview"][0]["reason"]
                .as_str()
                .unwrap()
                .contains("ACCOUNT_CURRENCY_MISMATCH"),
            "{body}"
        );
        operator(&fixture.schema, &sync()).await;
        let bodies = fixture.mock.sync_bodies();
        assert_eq!(bodies[1]["cursor"], "c1", "the cursor was stored");
    }

    /// Imported transactions Plaid later changes or removes are noted for
    /// review, once each; nothing is reversed.
    ///
    /// Bug-catch: noting every removed id, pending ones included, buries the
    /// ones that matter.
    #[tokio::test]
    async fn changed_imported_transactions_are_counted_for_review() {
        let fixture = mapped(true).await;
        fixture.mock.sync_page(page(
            vec![mock::sync_transaction(
                "t1",
                "acc1",
                1.0,
                "2026-11-01",
                false,
            )],
            vec![],
            vec![],
        ));
        fixture.mock.sync_page(page(
            vec![],
            vec![mock::sync_transaction(
                "t1",
                "acc1",
                1.5,
                "2026-11-01",
                false,
            )],
            vec!["t1", "pending-never-imported"],
        ));
        operator(&fixture.schema, &sync()).await;
        let body = operator(&fixture.schema, &sync()).await;
        let review = body["data"]["syncBank"]["needsReview"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(review.len(), 1, "t1 once, modified and removed: {body}");
        assert_eq!(review[0]["transactionId"], "t1");
        assert_eq!(body["data"]["syncBank"]["imported"], 0);
    }

    /// No sync without an open suspense account, and no mapping to an account
    /// the ledger has not opened.
    ///
    /// Bug-catch: syncing anyway asks Plaid for the history and then refuses
    /// every entry, one by one.
    #[tokio::test]
    async fn a_sync_and_a_mapping_need_open_accounts() {
        let fixture = mapped(false).await;
        let body = operator(&fixture.schema, &sync()).await;
        assert_eq!(code(&body), Some("ACCOUNT_NOT_OPEN"), "{body}");
        assert!(fixture.mock.sync_bodies().is_empty());

        let map = format!(
            r#"mutation {{ mapBankAccount(itemId: "{ITEM_ID}", accountId: "acc2", ledgerAccount: "Assets:Bank:Savings") {{ itemId }} }}"#
        );
        let body = operator(&fixture.schema, &map).await;
        assert_eq!(code(&body), Some("ACCOUNT_NOT_OPEN"), "{body}");
    }

    /// A zero amount is noted, not written (an entry of nothing would not
    /// balance against the suspense account anyway).
    ///
    /// Bug-catch: writing it gets the ledger's refusal instead of saying why.
    #[tokio::test]
    async fn a_zero_amount_is_noted() {
        let fixture = mapped(true).await;
        fixture.mock.sync_page(page(
            vec![mock::sync_transaction(
                "t1",
                "acc1",
                0.0,
                "2026-11-01",
                false,
            )],
            vec![],
            vec![],
        ));
        let body = operator(&fixture.schema, &sync()).await;
        assert_eq!(body["data"]["syncBank"]["imported"], 0, "{body}");
        let reason = body["data"]["syncBank"]["needsReview"][0]["reason"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        assert!(reason.contains("zero amount"), "{body}");
    }

    /// A sync cut short keeps the pages it wrote: the next one goes on from
    /// the last page stored, not from the beginning. It answers with what it
    /// did and why it stopped, the notes of the stored page included.
    ///
    /// Bug-catch: storing the cursor only at the end makes a history longer
    /// than the request timeout start over at every sync, and never arrive;
    /// answering with the error alone loses the stored page's notes for good.
    #[tokio::test]
    async fn a_sync_cut_short_goes_on_from_its_last_page() {
        let fixture = mapped(true).await;
        let mut euros = mock::sync_transaction("t0", "acc1", 2.0, "2026-10-01", false);
        euros["iso_currency_code"] = serde_json::json!("EUR");
        let open = r#"mutation { openAccount(name: "Assets:Bank:Dollars", date: "2026-01-01", currencies: ["USD"]) }"#;
        assert!(operator(&fixture.schema, open).await["errors"].is_null());
        let map = format!(
            r#"mutation {{ mapBankAccount(itemId: "{ITEM_ID}", accountId: "acc1", ledgerAccount: "Assets:Bank:Dollars") {{ itemId }} }}"#
        );
        assert!(operator(&fixture.schema, &map).await["errors"].is_null());
        fixture.mock.sync_page(serde_json::json!({
            "added": [euros, mock::sync_transaction("t1", "acc1", 1.0, "2026-11-01", false)],
            "modified": [], "removed": [], "next_cursor": "c1", "has_more": true,
        }));
        fixture.mock.sync_error(500, "INTERNAL_SERVER_ERROR");

        let body = operator(&fixture.schema, &sync()).await;
        assert!(body["errors"].is_null(), "{body}");
        let result = &body["data"]["syncBank"];
        assert!(
            result["stoppedBy"]
                .as_str()
                .unwrap_or_default()
                .contains("INTERNAL_SERVER_ERROR"),
            "{body}"
        );
        assert_eq!(result["needsReview"][0]["transactionId"], "t0", "{body}");
        let journal = operator(&fixture.schema, JOURNAL).await;
        assert!(
            journal.to_string().contains("plaid-t1"),
            "page one written: {journal}"
        );
        operator(&fixture.schema, &sync()).await;
        let bodies = fixture.mock.sync_bodies();
        assert_eq!(bodies.last().unwrap()["cursor"], "c1", "{bodies:?}");
    }

    /// Nothing is imported from before the suspense account was opened, even
    /// when the bank account was opened earlier: it is one side of every
    /// entry.
    ///
    /// Bug-catch: starting at the bank account's open date alone has the
    /// ledger refuse every transaction in between, each one noted for review
    /// and none ever importable.
    #[tokio::test]
    async fn nothing_is_imported_from_before_the_suspense_account_opened() {
        let fixture = fixture(true).await;
        for (account, date) in [
            ("Assets:Bank:Checking", "2026-01-01"),
            ("Expenses:Uncategorized", "2026-06-01"),
        ] {
            let open = format!(r#"mutation {{ openAccount(name: "{account}", date: "{date}") }}"#);
            let body = operator(&fixture.schema, &open).await;
            assert!(body["errors"].is_null(), "{body}");
        }
        operator(&fixture.schema, CONNECT).await;
        let map = format!(
            r#"mutation {{ mapBankAccount(itemId: "{ITEM_ID}", accountId: "acc1", ledgerAccount: "Assets:Bank:Checking") {{ itemId }} }}"#
        );
        assert!(operator(&fixture.schema, &map).await["errors"].is_null());
        fixture.mock.sync_page(page(
            vec![
                mock::sync_transaction("t1", "acc1", 1.0, "2026-03-01", false),
                mock::sync_transaction("t2", "acc1", 1.0, "2026-07-01", false),
            ],
            vec![],
            vec![],
        ));

        let body = operator(&fixture.schema, &sync()).await;
        let result = &body["data"]["syncBank"];
        assert_eq!(result["imported"], 1, "{body}");
        assert_eq!(result["skippedBeforeStart"], 1);
        assert_eq!(result["needsReview"], serde_json::json!([]));
    }

    /// A bank account cannot be mapped to the suspense account itself.
    ///
    /// Bug-catch: such entries net to nothing on one account, and every
    /// transaction of the bank vanishes from the books.
    #[tokio::test]
    async fn a_bank_account_is_not_mapped_to_the_suspense_account() {
        let fixture = mapped(true).await;
        let map = format!(
            r#"mutation {{ mapBankAccount(itemId: "{ITEM_ID}", accountId: "acc2", ledgerAccount: "Expenses:Uncategorized") {{ itemId }} }}"#
        );
        let body = operator(&fixture.schema, &map).await;
        assert_eq!(code(&body), Some("INVALID_INPUT"), "{body}");
    }

    /// A description longer than the ledger takes is cut, and imported.
    ///
    /// Bug-catch: passing it whole has the ledger refuse it for its size, a
    /// refusal that stops every later sync of the bank at that entry.
    #[tokio::test]
    async fn an_over_long_description_is_cut_and_imported() {
        let fixture = mapped(true).await;
        let mut long = mock::sync_transaction("t1", "acc1", 1.0, "2026-11-01", false);
        // One byte, then two-byte characters: the cut at 10,000 bytes falls
        // inside one, and must step back to its start.
        long["name"] = serde_json::json!(format!("a{}", "é".repeat(8_000)));
        long["merchant_name"] = serde_json::json!("m".repeat(5_000));
        fixture.mock.sync_page(page(vec![long], vec![], vec![]));

        let body = operator(&fixture.schema, &sync()).await;
        assert_eq!(body["data"]["syncBank"]["imported"], 1, "{body}");
        let journal = operator(&fixture.schema, JOURNAL).await;
        let entry = &journal["data"]["journal"].as_array().unwrap()[0];
        assert!(entry["narration"].as_str().unwrap().len() <= 10_000);
        assert!(entry["payee"].as_str().unwrap().len() <= 1_000);
    }

    fn more(added: Vec<Value>, cursor: &str) -> Value {
        serde_json::json!({
            "added": added, "modified": [], "removed": [],
            "next_cursor": cursor, "has_more": true,
        })
    }

    /// Every page of one sync is written and stored, the last one included:
    /// the next sync starts after it.
    ///
    /// Bug-catch: a page stored without the session noting it makes the next
    /// page's store look like a cursor moved under the sync, which then stops
    /// after one page while answering as if it had finished.
    #[tokio::test]
    async fn a_sync_stores_every_page() {
        let fixture = mapped(true).await;
        fixture.mock.sync_page(more(
            vec![mock::sync_transaction(
                "t1",
                "acc1",
                1.0,
                "2026-11-01",
                false,
            )],
            "c1",
        ));
        fixture.mock.sync_page(serde_json::json!({
            "added": [mock::sync_transaction("t2", "acc1", 2.0, "2026-11-02", false)],
            "modified": [], "removed": [], "next_cursor": "c2", "has_more": false,
        }));

        let body = operator(&fixture.schema, &sync()).await;
        assert_eq!(body["data"]["syncBank"]["imported"], 2, "{body}");
        assert!(body["data"]["syncBank"]["stoppedBy"].is_null());
        operator(&fixture.schema, &sync()).await;
        assert_eq!(fixture.mock.sync_bodies().last().unwrap()["cursor"], "c2");
    }

    /// When Plaid restarts the pages, a transaction written before the
    /// restart that comes back with another amount is noted for review.
    ///
    /// Bug-catch: taking it for already imported keeps the old amount in the
    /// books with no word to the accountant.
    #[tokio::test]
    async fn a_restart_notes_what_changed_under_it() {
        let fixture = mapped(true).await;
        fixture.mock.sync_page(more(
            vec![mock::sync_transaction(
                "t1",
                "acc1",
                10.0,
                "2026-11-01",
                false,
            )],
            "c1",
        ));
        fixture
            .mock
            .sync_error(400, "TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION");
        fixture.mock.sync_page(page(
            vec![mock::sync_transaction(
                "t1",
                "acc1",
                12.0,
                "2026-11-01",
                false,
            )],
            vec![],
            vec![],
        ));

        let body = operator(&fixture.schema, &sync()).await;
        let result = &body["data"]["syncBank"];
        assert_eq!(result["imported"], 1, "{body}");
        assert_eq!(result["alreadyImported"], 1);
        assert_eq!(result["needsReview"][0]["transactionId"], "t1", "{body}");
        assert!(
            fixture.mock.sync_bodies()[2].get("cursor").is_none(),
            "restarted"
        );
    }

    /// A restart goes back to the cursor of the last finished series, not to
    /// a page cursor a sync cut short stored.
    ///
    /// Bug-catch: restarting from a mid-series cursor, which Plaid keeps valid
    /// only within its series, can fail every later sync of the bank.
    #[tokio::test]
    async fn a_restart_goes_back_to_the_last_finished_series() {
        let fixture = mapped(true).await;
        fixture.mock.sync_page(page(vec![], vec![], vec![]));
        operator(&fixture.schema, &sync()).await;
        fixture.mock.sync_page(more(
            vec![mock::sync_transaction(
                "t1",
                "acc1",
                1.0,
                "2026-11-01",
                false,
            )],
            "c2",
        ));
        fixture.mock.sync_error(500, "INTERNAL_SERVER_ERROR");
        operator(&fixture.schema, &sync()).await;
        fixture
            .mock
            .sync_error(400, "TRANSACTIONS_SYNC_MUTATION_DURING_PAGINATION");

        operator(&fixture.schema, &sync()).await;
        let bodies = fixture.mock.sync_bodies();
        let n = bodies.len();
        assert_eq!(bodies[n - 2]["cursor"], "c2", "went on from its last page");
        assert_eq!(
            bodies[n - 1]["cursor"],
            "c1",
            "restarted from the finished series"
        );
    }

    /// `createPlaidLinkToken(itemId:)` answers with a link token and no
    /// access token, and is admin only like the rest.
    ///
    /// Bug-catch: an update-mode token open to a write key lets anyone with
    /// one re-authorise the company's bank.
    #[tokio::test]
    async fn a_login_again_link_token_over_graphql() {
        let fixture = fixture(true).await;
        assert!(operator(&fixture.schema, CONNECT).await["errors"].is_null());
        let query = format!(
            r#"mutation {{ createPlaidLinkToken(itemId: "{ITEM_ID}") {{ linkToken expiration }} }}"#
        );

        let body = run(&fixture.schema, Role::Write, &query).await;
        assert_eq!(code(&body), Some("FORBIDDEN"), "{body}");
        let body = operator(&fixture.schema, &query).await;
        assert_eq!(
            body["data"]["createPlaidLinkToken"]["linkToken"], "link-sandbox-abc",
            "{body}"
        );
        assert!(!body.to_string().contains(ACCESS_TOKEN));
        let unknown = r#"mutation { createPlaidLinkToken(itemId: "nope") { linkToken } }"#;
        assert_eq!(
            code(&operator(&fixture.schema, unknown).await),
            Some("NO_SUCH_BANK")
        );
    }
}
