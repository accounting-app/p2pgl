//! The bank-feed inbox over GraphQL (build-log 008): `fetchBankTransactions`
//! puts a bank's new posted transactions in the ledger's inbox without writing
//! anything to the books; `bankInbox` lists what waits there for a bookkeeper
//! (a write key). Booking from it is a separate step, by a person.

use std::collections::HashMap;

use async_graphql::{Context, InputObject, Result, SimpleObject};
use ledger::model::{Amount as LedgerAmount, Flag};
use ledger::service::{PostingInput, TransactionInput};

use super::plaid::{
    client_user_id, failed, held_imports, import_link, ledger, refused, service, BankSyncNote,
    HeldImport,
};
use super::scalars::{DateScalar, DecimalScalar, TransactionId};
use super::types::Amount;
use super::SharedLedger;
use crate::bank_inbox::{IgnoredTransaction, InboxTransaction};

/// What one `fetchBankTransactions` did.
#[derive(SimpleObject, Debug, Clone, Default)]
pub struct BankFetch {
    /// Transactions put in the inbox.
    pub added: usize,
    /// Transactions waiting in the inbox that Plaid changed since: updated
    /// there.
    pub updated: usize,
    /// Transactions waiting in the inbox that Plaid removed: dropped there.
    pub dropped: usize,
    /// Transactions the books hold already (booked, or imported by
    /// `syncBank`): skipped.
    pub already_booked: usize,
    /// Transactions the inbox holds already, waiting or ignored: skipped.
    pub already_in_inbox: usize,
    /// Pending transactions, skipped: fetched once the bank posts them.
    pub skipped_pending: usize,
    /// Transactions of accounts not mapped to a ledger account: fetched once
    /// `mapBankAccount` maps them.
    pub skipped_unmapped: usize,
    /// Transactions dated before their account's `importFrom`: skipped.
    pub skipped_before_start: usize,
    /// What the accountant should look at: a booked transaction Plaid changed
    /// or removed since, one without a currency or amount, one this node could
    /// not read.
    pub needs_review: Vec<BankSyncNote>,
    /// Why the fetch stopped before the end, when it stopped once a page was
    /// stored: what it did is kept, and the next fetch goes on from there.
    pub stopped_by: Option<String>,
}

/// A bank transaction waiting to be booked.
#[derive(SimpleObject, Debug, Clone)]
pub struct InboxEntry {
    /// Plaid's id for it; booking and ignoring take it.
    pub transaction_id: String,
    pub item_id: String,
    pub institution_name: Option<String>,
    /// The bank account it is from: Plaid's id, its name and last digits.
    pub account_id: String,
    pub account_name: Option<String>,
    pub account_mask: Option<String>,
    /// The ledger account the bank account is mapped to now: the side of the
    /// entry booking writes for the bank. Null once unmapped.
    pub ledger_account: Option<String>,
    pub date: DateScalar,
    /// As the bank account's posting carries it: money out is negative.
    pub amount: Amount,
    /// Plaid's merchant name, when it has one.
    pub payee: Option<String>,
    /// The bank's description.
    pub description: Option<String>,
    /// Plaid's category (`FOOD_AND_DRINK`, …): a hint only.
    pub category: Option<String>,
    /// When it was fetched (RFC 3339, UTC).
    pub fetched_at: String,
}

/// A page of the inbox.
#[derive(SimpleObject, Debug, Clone)]
pub struct BankInboxPage {
    /// How many transactions wait (of this bank, when one was asked for).
    pub total: usize,
    /// Oldest first, then by Plaid's id.
    pub transactions: Vec<InboxEntry>,
}

/// The most transactions one `bankInbox` returns.
const MAX_PAGE: usize = 1000;

/// Note `transaction_id` for review, once, and log it.
fn note(notes: &mut Vec<BankSyncNote>, item_id: &str, transaction_id: Option<&str>, reason: &str) {
    let note = BankSyncNote {
        transaction_id: transaction_id.map(str::to_owned),
        reason: reason.to_owned(),
    };
    if notes
        .iter()
        .any(|other| other.transaction_id == note.transaction_id && other.reason == note.reason)
    {
        return;
    }
    tracing::warn!(item_id = %item_id, transaction_id = note.transaction_id.as_deref().unwrap_or("-"), reason = %note.reason, "a bank transaction for review");
    notes.push(note);
}

/// Fetch what Plaid has for bank `item_id` since the last fetch — by either
/// `fetchBankTransactions` or `syncBank`: they share the bank's place at
/// Plaid, and one runs at a time (`SYNC_IN_PROGRESS`) — into the inbox.
/// Nothing is written to the books. Page by page: a page's place at Plaid is
/// stored only once the inbox holding it is on disk, so a fetch cut short
/// goes on from there and fetches nothing twice.
pub(super) async fn fetch_bank_transactions(
    ctx: &Context<'_>,
    item_id: String,
) -> Result<BankFetch> {
    let plaid = service(ctx)?;
    let ledger = ledger(ctx)?;
    let Some(_syncing) = plaid.begin_sync(&item_id) else {
        return Err(refused(
            "SYNC_IN_PROGRESS",
            format!("bank {item_id} is being fetched or synced already; try again once that ends"),
        ));
    };
    let mut session = plaid.begin_fetch(&item_id).await.map_err(failed)?;
    // A mapped account's transactions from its `importFrom` on.
    let mapped: HashMap<String, chrono::NaiveDate> = session
        .connection
        .accounts
        .iter()
        .filter(|account| account.ledger_account.is_some())
        .map(|account| {
            (
                account.account_id.clone(),
                account.import_from.unwrap_or(chrono::NaiveDate::MIN),
            )
        })
        .collect();
    let held = held_imports(ledger, plaid.suspense_account()).await;
    let mut fetch = BankFetch::default();
    let mut stored_a_page = false;
    let mut finished = false;
    loop {
        let page = match plaid.next_page(&mut session).await {
            Ok(Some(page)) => page,
            Ok(None) => {
                finished = true;
                break;
            }
            Err(error) => {
                if let Some(code) = error.plaid_code() {
                    plaid.note_health(&item_id, Some(code)).await;
                }
                return stopped(fetch, &item_id, stored_a_page, failed(error));
            }
        };
        fetch.skipped_pending += page.pending;
        for (id, reason) in &page.unreadable {
            note(&mut fetch.needs_review, &item_id, id.as_deref(), reason);
        }
        let now = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        let changed = {
            let mut open = match plaid.open_inbox().await {
                Ok(open) => open,
                Err(error) => return stopped(fetch, &item_id, stored_a_page, failed(error)),
            };
            let inbox = &mut open.inbox;
            let mut counts = fetch.clone();
            let booked_lately: std::collections::HashSet<String> = page
                .added
                .iter()
                .map(|transaction| transaction.transaction_id.as_str())
                .chain(page.changed.iter().map(String::as_str))
                .filter(|id| inbox.booked_lately(id))
                .map(str::to_owned)
                .collect();
            let written = inbox.update(|contents| {
                // First, Plaid's changes to what already waits — sent again or
                // modified, as it is now; removed, dropped — so what follows
                // only adds what is new.
                let (updated, dropped) = contents
                    .take_plaid_changes(page.added.iter().chain(&page.modified), &page.removed);
                counts.updated += updated;
                counts.dropped += dropped;
                for transaction in &page.added {
                    let id = transaction.transaction_id.as_str();
                    let Some(start) = mapped.get(&transaction.account_id) else {
                        counts.skipped_unmapped += 1;
                        continue;
                    };
                    if transaction.date < *start {
                        counts.skipped_before_start += 1;
                        continue;
                    }
                    if let Some(entry) = held.get(&import_link(id)) {
                        counts.already_booked += 1;
                        // Sent again with another date or amount (a restart of
                        // Plaid's pages, or Plaid revising it): the books keep
                        // what was booked, the accountant is told.
                        if entry.date != transaction.date
                            || entry
                                .amount
                                .is_some_and(|amount| amount != -transaction.amount)
                        {
                            note(
                                &mut counts.needs_review,
                                &item_id,
                                Some(id),
                                "changed at Plaid after it was booked (another date or amount)",
                            );
                        }
                        continue;
                    }
                    if booked_lately.contains(id) {
                        counts.already_booked += 1;
                        continue;
                    }
                    if contents.holds(id) {
                        counts.already_in_inbox += 1;
                        continue;
                    }
                    let Some(currency) = &transaction.currency else {
                        note(
                            &mut counts.needs_review,
                            &item_id,
                            Some(id),
                            "no currency from Plaid: not fetched",
                        );
                        continue;
                    };
                    if transaction.amount.is_zero() {
                        note(
                            &mut counts.needs_review,
                            &item_id,
                            Some(id),
                            "a zero amount: nothing to book",
                        );
                        continue;
                    }
                    contents.waiting.insert(
                        id.to_owned(),
                        InboxTransaction {
                            transaction_id: id.to_owned(),
                            item_id: item_id.clone(),
                            account_id: transaction.account_id.clone(),
                            date: transaction.date,
                            amount: -transaction.amount,
                            currency: currency.clone(),
                            payee: transaction.merchant_name.clone(),
                            description: transaction.name.clone(),
                            category: transaction.category.clone(),
                            fetched_at: now.clone(),
                        },
                    );
                    counts.added += 1;
                }
                // Plaid's changes to what is booked are only reported (the
                // books are never changed by the node).
                for id in &page.changed {
                    if held.contains_key(&import_link(id)) || booked_lately.contains(id) {
                        note(
                            &mut counts.needs_review,
                            &item_id,
                            Some(id),
                            "changed or removed at Plaid after it was booked",
                        );
                    }
                }
                counts
            });
            written
        };
        match changed {
            Ok(counts) => fetch = counts,
            Err(error) => return stopped(fetch, &item_id, stored_a_page, failed(error.into())),
        }
        match plaid.commit_page(&mut session, &page).await {
            Ok(true) => stored_a_page = true,
            Ok(false) => break,
            Err(error) => return stopped(fetch, &item_id, stored_a_page, failed(error)),
        }
    }
    if finished {
        plaid.note_health(&item_id, None).await;
    }
    tracing::info!(
        item_id = %item_id,
        added = fetch.added,
        updated = fetch.updated,
        dropped = fetch.dropped,
        already_booked = fetch.already_booked,
        already_in_inbox = fetch.already_in_inbox,
        needs_review = fetch.needs_review.len(),
        "bank transactions fetched into the inbox"
    );
    Ok(fetch)
}

/// A fetch that cannot go on: an error while nothing is stored (the next
/// fetch does it all again), or — once a page is stored — what it did, with
/// `stoppedBy`.
fn stopped(
    mut fetch: BankFetch,
    item_id: &str,
    stored_a_page: bool,
    error: async_graphql::Error,
) -> Result<BankFetch> {
    tracing::warn!(item_id = %item_id, error = %error.message, "a bank fetch stopped; the pages stored are kept, the next fetch goes on from there");
    if !stored_a_page {
        return Err(error);
    }
    fetch.stopped_by = Some(error.message);
    Ok(fetch)
}

/// The transactions waiting in the inbox — of bank `item_id`, or of every
/// bank — oldest first, `first` of them (at most [`MAX_PAGE`]) from `offset`.
pub(super) async fn bank_inbox(
    ctx: &Context<'_>,
    item_id: Option<String>,
    first: usize,
    offset: usize,
) -> Result<BankInboxPage> {
    let plaid = service(ctx)?;
    let connections = plaid.connections().await.map_err(failed)?;
    let mut waiting: Vec<InboxTransaction> = {
        let open = plaid.open_inbox().await.map_err(failed)?;
        open.inbox
            .contents()
            .waiting
            .values()
            .filter(|transaction| {
                item_id
                    .as_ref()
                    .is_none_or(|item| &transaction.item_id == item)
            })
            .cloned()
            .collect()
    };
    waiting.sort_by(|a, b| (a.date, &a.transaction_id).cmp(&(b.date, &b.transaction_id)));
    let total = waiting.len();
    let transactions = waiting
        .into_iter()
        .skip(offset)
        .take(first.min(MAX_PAGE))
        .map(|transaction| {
            let bank = connections
                .iter()
                .find(|connection| connection.item_id == transaction.item_id);
            let account = bank.and_then(|bank| {
                bank.accounts
                    .iter()
                    .find(|account| account.account_id == transaction.account_id)
            });
            InboxEntry {
                institution_name: bank.and_then(|bank| bank.institution_name.clone()),
                account_name: account.map(|account| account.name.clone()),
                account_mask: account.and_then(|account| account.mask.clone()),
                ledger_account: account.and_then(|account| account.ledger_account.clone()),
                transaction_id: transaction.transaction_id,
                item_id: transaction.item_id,
                account_id: transaction.account_id,
                date: DateScalar(transaction.date),
                amount: Amount {
                    number: DecimalScalar(transaction.amount),
                    currency: transaction.currency,
                },
                payee: transaction.payee,
                description: transaction.description,
                category: transaction.category,
                fetched_at: transaction.fetched_at,
            }
        })
        .collect();
    Ok(BankInboxPage {
        total,
        transactions,
    })
}

/// One transaction to book: the account it goes to (the other side of the
/// bank's), and the payee and narration when not Plaid's (an empty one
/// leaves it out).
#[derive(InputObject, Debug, Clone)]
pub struct ClassifyInput {
    pub transaction_id: String,
    pub account: String,
    pub payee: Option<String>,
    pub narration: Option<String>,
}

/// One transaction to ignore, and why.
#[derive(InputObject, Debug, Clone)]
pub struct IgnoreInput {
    pub transaction_id: String,
    pub reason: Option<String>,
}

/// What became of one transaction of a `classifyBankTransactions` or
/// `ignoreBankTransactions`: done, or refused with a code — the others of
/// the call are done or refused on their own.
#[derive(SimpleObject, Debug, Clone)]
pub struct BankBooking {
    pub transaction_id: String,
    pub ok: bool,
    /// The entry written, when booked.
    pub txid: Option<TransactionId>,
    /// Why not: `NOT_IN_INBOX`, `ALREADY_BOOKED`, `BANK_TRANSACTION_IGNORED`,
    /// `ALREADY_IGNORED`, `ACCOUNT_NOT_MAPPED`, `INVALID_INPUT`, or the
    /// ledger's refusal of the entry (`ACCOUNT_NOT_OPEN`, …).
    pub code: Option<String>,
    pub message: Option<String>,
}

/// The most transactions one call books or ignores.
const MAX_BOOKINGS: usize = 200;

/// The longest reason an ignored transaction keeps.
const MAX_REASON_CHARS: usize = 500;

impl BankBooking {
    fn done(transaction_id: &str, txid: Option<TransactionId>) -> Self {
        Self {
            transaction_id: transaction_id.to_owned(),
            ok: true,
            txid,
            code: None,
            message: None,
        }
    }

    fn refused(transaction_id: &str, code: &str, message: impl Into<String>) -> Self {
        Self {
            transaction_id: transaction_id.to_owned(),
            ok: false,
            txid: None,
            code: Some(code.to_owned()),
            message: Some(message.into()),
        }
    }

    fn failed(transaction_id: &str, error: &async_graphql::Error) -> Self {
        let code = error
            .extensions
            .as_ref()
            .and_then(|ext| ext.get("code"))
            .and_then(|code| match code {
                async_graphql::Value::String(code) => Some(code.clone()),
                _ => None,
            })
            .unwrap_or_else(|| "INTERNAL".to_owned());
        Self::refused(transaction_id, &code, error.message.clone())
    }
}

fn too_many(count: usize) -> Result<()> {
    if count > MAX_BOOKINGS {
        return Err(refused(
            "INVALID_INPUT",
            format!("at most {MAX_BOOKINGS} transactions a call; this one has {count}"),
        ));
    }
    Ok(())
}

/// Book transactions from the inbox (008): each one entry — the bank's
/// mapped ledger account with the amount, `account` balancing it — flag `*`,
/// link `^plaid-<transaction id>`, entered by the caller, through
/// `appendTransaction`'s path; then it leaves the inbox. Each transaction is
/// booked or refused on its own.
///
/// The inbox is held for the whole call, and the books and the accounts'
/// mappings are read only once it is. A call cut short — the request timeout
/// drops it while an entry it staged still commits — leaves that transaction
/// waiting though booked; the next call, reading the books after it, finds
/// the entry and drops the transaction instead of booking it again. The
/// transactions booked are removed from the inbox in one write at the end.
pub(super) async fn classify_bank_transactions(
    ctx: &Context<'_>,
    items: Vec<ClassifyInput>,
) -> Result<Vec<BankBooking>> {
    let plaid = service(ctx)?;
    let ledger = ledger(ctx)?;
    too_many(items.len())?;
    let mut open = plaid.open_inbox().await.map_err(failed)?;
    // The bank side is the account's mapping now, not when it was fetched.
    // (`connections` takes the store's lock, never the `closed` gate.)
    let mapping: HashMap<(String, String), String> = plaid
        .connections()
        .await
        .map_err(failed)?
        .into_iter()
        .flat_map(|connection| {
            let item_id = connection.item_id;
            connection.accounts.into_iter().filter_map(move |account| {
                Some((
                    (item_id.clone(), account.account_id),
                    account.ledger_account?,
                ))
            })
        })
        .collect();
    let held = held_imports(ledger, plaid.suspense_account()).await;
    let mut leaving = Vec::new();
    let mut bookings = Vec::with_capacity(items.len());
    for item in items {
        bookings.push(
            classify_one(
                ctx,
                ledger,
                &mut open.inbox,
                &mapping,
                &held,
                &mut leaving,
                item,
            )
            .await,
        );
    }
    if !leaving.is_empty() {
        if let Err(error) = open.inbox.update(|contents| {
            for id in &leaving {
                contents.waiting.remove(id);
            }
        }) {
            // Booked all the same; the next call finds them in the books and
            // drops them.
            tracing::warn!(%error, booked = leaving.len(), "booked transactions stay in the bank inbox for now");
        }
    }
    Ok(bookings)
}

async fn classify_one(
    ctx: &Context<'_>,
    ledger: &SharedLedger,
    inbox: &mut crate::bank_inbox::BankInbox,
    mapping: &HashMap<(String, String), String>,
    held: &HashMap<String, HeldImport>,
    leaving: &mut Vec<String>,
    item: ClassifyInput,
) -> BankBooking {
    let id = item.transaction_id.as_str();
    let mut leave = |id: &str| {
        if !leaving.iter().any(|left| left == id) {
            leaving.push(id.to_owned());
        }
    };
    // Booked before this call read the books, or by it since.
    let in_books = held.contains_key(&import_link(id)) || inbox.booked_lately(id);
    let Some(waiting) = inbox.contents().waiting.get(id).cloned() else {
        if inbox.contents().ignored.contains_key(id) {
            return BankBooking::refused(
                id,
                "BANK_TRANSACTION_IGNORED",
                "this transaction was ignored; it is not booked",
            );
        }
        if in_books {
            return BankBooking::refused(
                id,
                "ALREADY_BOOKED",
                "this transaction is booked already",
            );
        }
        return BankBooking::refused(
            id,
            "NOT_IN_INBOX",
            "no such transaction waits in the bank inbox",
        );
    };
    if in_books {
        // The books hold it — some other way (`syncBank` before it was
        // fetched), or by a call cut short — so it leaves the inbox, and
        // nothing is written.
        leave(id);
        return BankBooking::refused(id, "ALREADY_BOOKED", "this transaction is booked already");
    }
    let Some(bank_account) = mapping.get(&(waiting.item_id.clone(), waiting.account_id.clone()))
    else {
        return BankBooking::refused(
            id,
            "ACCOUNT_NOT_MAPPED",
            "its bank account is not mapped to a ledger account now (mapBankAccount)",
        );
    };
    if item.account == *bank_account {
        return BankBooking::refused(
            id,
            "INVALID_INPUT",
            format!("{bank_account} is the bank's own account: book it to another"),
        );
    }
    let given = |text: Option<String>, plaid: Option<String>| match text {
        Some(text) if text.trim().is_empty() => None,
        Some(text) => Some(text),
        None => plaid,
    };
    let entry = TransactionInput {
        date: waiting.date,
        flag: Flag::Complete,
        payee: given(item.payee, waiting.payee),
        narration: given(item.narration, waiting.description),
        tags: Vec::new(),
        links: vec![import_link(id)],
        postings: vec![
            PostingInput {
                account: bank_account.clone(),
                amount: Some(LedgerAmount {
                    number: waiting.amount,
                    currency: waiting.currency.clone(),
                }),
                cost: None,
                price: None,
            },
            PostingInput {
                account: item.account,
                amount: None,
                cost: None,
                price: None,
            },
        ],
    };
    match super::mutation::append_transaction_input(ctx, ledger, entry).await {
        Ok(appended) => {
            inbox.note_booked(id);
            leave(id);
            if appended.already_existed {
                // The very same entry was in the books already: nothing new
                // was written, and it is said so.
                return BankBooking {
                    txid: Some(appended.transaction.txid),
                    ..BankBooking::refused(
                        id,
                        "ALREADY_BOOKED",
                        "this very entry is in the books already",
                    )
                };
            }
            BankBooking::done(id, Some(appended.transaction.txid))
        }
        Err(error) => BankBooking::failed(id, &error),
    }
}

/// Ignore transactions waiting in the inbox (008): each leaves it with the
/// caller, the time and the reason, is never booked and never fetched again;
/// nothing is written to the books. One write of the inbox for the call.
pub(super) async fn ignore_bank_transactions(
    ctx: &Context<'_>,
    items: Vec<IgnoreInput>,
) -> Result<Vec<BankBooking>> {
    let plaid = service(ctx)?;
    too_many(items.len())?;
    let by = client_user_id(ctx);
    let at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let mut open = plaid.open_inbox().await.map_err(failed)?;
    let outcome = open.inbox.update(|contents| {
        items
            .iter()
            .map(|item| {
                let id = item.transaction_id.as_str();
                let reason = item
                    .reason
                    .clone()
                    .filter(|reason| !reason.trim().is_empty());
                if reason.as_ref().is_some_and(|reason| {
                    reason.chars().count() > MAX_REASON_CHARS
                        || reason.chars().any(char::is_control)
                }) {
                    return BankBooking::refused(
                        id,
                        "INVALID_INPUT",
                        format!(
                            "a reason is at most {MAX_REASON_CHARS} characters, without control characters"
                        ),
                    );
                }
                if let Some(waiting) = contents.waiting.remove(id) {
                    contents.ignored.insert(
                        id.to_owned(),
                        IgnoredTransaction {
                            item_id: waiting.item_id,
                            at: at.clone(),
                            by: by.clone(),
                            reason,
                        },
                    );
                    BankBooking::done(id, None)
                } else if contents.ignored.contains_key(id) {
                    BankBooking::refused(id, "ALREADY_IGNORED", "this transaction was ignored already")
                } else {
                    BankBooking::refused(id, "NOT_IN_INBOX", "no such transaction waits in the bank inbox")
                }
            })
            .collect::<Vec<_>>()
    });
    match outcome {
        Ok(bookings) => Ok(bookings),
        Err(error) => {
            let error = failed(error.into());
            Ok(items
                .iter()
                .map(|item| BankBooking::failed(&item.transaction_id, &error))
                .collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use crate::access_control::Role;
    use crate::graphql::plaid::tests::{code, mapped, operator, page, run, JOURNAL};
    use crate::plaid::tests::{self as mock, ITEM_ID};

    fn fetch() -> String {
        format!(
            r#"mutation {{ fetchBankTransactions(itemId: "{ITEM_ID}") {{ added updated dropped alreadyBooked alreadyInInbox skippedPending skippedUnmapped skippedBeforeStart needsReview {{ transactionId reason }} stoppedBy }} }}"#
        )
    }

    const INBOX: &str = "{ bankInbox { total transactions { transactionId itemId institutionName accountId accountName accountMask ledgerAccount date amount { number currency } payee description category fetchedAt } } }";

    fn plaid_entries(journal: &Value) -> usize {
        journal["data"]["journal"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| {
                entry["links"].as_array().is_some_and(|links| {
                    links
                        .iter()
                        .any(|link| link.as_str().unwrap_or("").starts_with("plaid-"))
                })
            })
            .count()
    }

    /// 008: a fetch puts a mapped account's posted transactions in the inbox
    /// — money out negative, as the bank's posting will carry it, with
    /// Plaid's payee, description and category — skips pending and unmapped
    /// ones, and writes nothing to the books; the inbox is on disk, and a
    /// second fetch adds nothing.
    ///
    /// Bug-catch: a fetch that writes entries is the old import under a new
    /// name — the bookkeeper never decides; one that keeps Plaid's sign shows
    /// every payment as a deposit.
    #[tokio::test]
    async fn a_fetch_fills_the_inbox_and_writes_nothing() {
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

        let body = operator(&fixture.schema, &fetch()).await;
        assert!(body["errors"].is_null(), "{body}");
        let counts = &body["data"]["fetchBankTransactions"];
        assert_eq!(counts["added"], 2, "{body}");
        assert_eq!(counts["skippedPending"], 1);
        assert_eq!(counts["skippedUnmapped"], 1);
        assert_eq!(plaid_entries(&operator(&fixture.schema, JOURNAL).await), 0);

        let inbox = run(&fixture.schema, Role::Write, INBOX).await;
        assert!(inbox["errors"].is_null(), "{inbox}");
        assert_eq!(inbox["data"]["bankInbox"]["total"], 2);
        let first = &inbox["data"]["bankInbox"]["transactions"][0];
        assert_eq!(first["transactionId"], "t1", "oldest first: {inbox}");
        assert_eq!(
            first["amount"],
            json!({ "number": "-12.34", "currency": "USD" })
        );
        assert_eq!(first["ledgerAccount"], "Assets:Bank:Checking");
        assert_eq!(first["payee"], "Corner Shop");
        assert_eq!(first["description"], "Payment t1");
        assert_eq!(first["category"], "FOOD_AND_DRINK");
        assert_eq!(first["date"], "2026-11-01");
        let deposit = &inbox["data"]["bankInbox"]["transactions"][1];
        assert_eq!(deposit["amount"]["number"], "200.0");

        let on_disk = crate::bank_inbox::BankInbox::open(fixture._dir.path()).unwrap();
        assert_eq!(on_disk.contents().waiting.len(), 2);

        // Plaid sends the same page again (a restart of its pages): nothing
        // is added twice.
        fixture.mock.sync_page(page(
            vec![
                mock::sync_transaction("t1", "acc1", 12.34, "2026-11-01", false),
                mock::sync_transaction("t4", "acc1", -200.0, "2026-11-03", false),
            ],
            vec![],
            vec![],
        ));
        let again = operator(&fixture.schema, &fetch()).await;
        let counts = &again["data"]["fetchBankTransactions"];
        assert_eq!(counts["added"], 0, "{again}");
        assert_eq!(counts["alreadyInInbox"], 2);
        assert_eq!(
            run(&fixture.schema, Role::Write, INBOX).await["data"]["bankInbox"]["total"],
            2
        );
    }

    /// 008: Plaid's change to a transaction still waiting is taken in the
    /// inbox, and a removed one is dropped from it; one Plaid sends again is
    /// not added twice.
    ///
    /// Bug-catch: an inbox that ignores Plaid's changes has the bookkeeper
    /// book an amount the bank has since corrected, or a transaction the bank
    /// reversed.
    #[tokio::test]
    async fn plaids_changes_reach_what_still_waits() {
        let fixture = mapped(true).await;
        fixture.mock.sync_page(page(
            vec![
                mock::sync_transaction("t1", "acc1", 12.34, "2026-11-01", false),
                mock::sync_transaction("t2", "acc1", 5.0, "2026-11-02", false),
            ],
            vec![],
            vec![],
        ));
        operator(&fixture.schema, &fetch()).await;
        fixture.mock.sync_page(page(
            vec![mock::sync_transaction(
                "t1",
                "acc1",
                12.34,
                "2026-11-01",
                false,
            )],
            vec![mock::sync_transaction(
                "t1",
                "acc1",
                15.0,
                "2026-11-01",
                false,
            )],
            vec!["t2"],
        ));

        let body = operator(&fixture.schema, &fetch()).await;
        let counts = &body["data"]["fetchBankTransactions"];
        assert_eq!(counts["updated"], 1, "{body}");
        assert_eq!(counts["dropped"], 1);
        assert_eq!(counts["alreadyInInbox"], 1);
        let inbox = run(&fixture.schema, Role::Write, INBOX).await;
        assert_eq!(inbox["data"]["bankInbox"]["total"], 1, "{inbox}");
        assert_eq!(
            inbox["data"]["bankInbox"]["transactions"][0]["amount"]["number"],
            "-15.0"
        );
    }

    /// 008: the inbox is a bookkeeper's — a write key lists it, a read key is
    /// refused — and fetching is an admin's.
    ///
    /// Bug-catch: the inbox under the read rule shows unbooked bank
    /// transactions to every viewer; a fetch open to write keys lets any
    /// bookkeeper move the bank's place at Plaid.
    #[tokio::test]
    async fn the_inbox_is_a_bookkeepers_and_fetching_an_admins() {
        let fixture = mapped(true).await;
        let read = run(&fixture.schema, Role::Read, INBOX).await;
        assert_eq!(code(&read), Some("FORBIDDEN"), "{read}");
        let write = run(&fixture.schema, Role::Write, INBOX).await;
        assert!(write["errors"].is_null(), "{write}");
        let fetch_as_write = run(&fixture.schema, Role::Write, &fetch()).await;
        assert_eq!(code(&fetch_as_write), Some("FORBIDDEN"), "{fetch_as_write}");
    }

    /// 008: a transaction waiting in the inbox is the bookkeeper's: when
    /// Plaid sends it again to `syncBank` (a restart of its pages), the sync
    /// leaves it there and writes nothing for it.
    ///
    /// Bug-catch: a sync that does not look at the inbox books a transaction
    /// the bookkeeper is about to book — two entries for one payment.
    #[tokio::test]
    async fn sync_bank_leaves_the_inbox_alone() {
        let fixture = mapped(true).await;
        let t1 = || {
            vec![mock::sync_transaction(
                "t1",
                "acc1",
                12.34,
                "2026-11-01",
                false,
            )]
        };
        fixture.mock.sync_page(page(t1(), vec![], vec![]));
        operator(&fixture.schema, &fetch()).await;
        fixture.mock.sync_page(page(t1(), vec![], vec![]));

        let sync =
            format!(r#"mutation {{ syncBank(itemId: "{ITEM_ID}") {{ imported inInbox }} }}"#);
        let body = operator(&fixture.schema, &sync).await;
        assert!(body["errors"].is_null(), "{body}");
        assert_eq!(body["data"]["syncBank"]["imported"], 0, "{body}");
        assert_eq!(body["data"]["syncBank"]["inInbox"], 1);
        assert_eq!(plaid_entries(&operator(&fixture.schema, JOURNAL).await), 0);
    }

    /// 008: Plaid's changes to what waits in the inbox are taken whichever
    /// fetch reads them — `syncBank` too, as the two share the bank's place
    /// at Plaid — and a disconnected bank's waiting transactions leave the
    /// inbox.
    ///
    /// Bug-catch: a sync that reads Plaid's correction or reversal of a
    /// waiting transaction and does not take it stores the page's cursor, so
    /// the change never comes again and the bookkeeper books what the bank
    /// has undone.
    #[tokio::test]
    async fn sync_bank_takes_plaids_changes_to_what_waits() {
        let fixture = mapped(true).await;
        fixture.mock.sync_page(page(
            vec![
                mock::sync_transaction("t1", "acc1", 12.34, "2026-11-01", false),
                mock::sync_transaction("t2", "acc1", 5.0, "2026-11-02", false),
            ],
            vec![],
            vec![],
        ));
        operator(&fixture.schema, &fetch()).await;
        fixture.mock.sync_page(page(
            vec![],
            vec![mock::sync_transaction(
                "t1",
                "acc1",
                15.0,
                "2026-11-01",
                false,
            )],
            vec!["t2"],
        ));
        let sync = format!(r#"mutation {{ syncBank(itemId: "{ITEM_ID}") {{ imported }} }}"#);
        let body = operator(&fixture.schema, &sync).await;
        assert!(body["errors"].is_null(), "{body}");
        let inbox = run(&fixture.schema, Role::Write, INBOX).await;
        assert_eq!(inbox["data"]["bankInbox"]["total"], 1, "{inbox}");
        assert_eq!(
            inbox["data"]["bankInbox"]["transactions"][0]["amount"]["number"],
            "-15.0"
        );

        let disconnect = format!(r#"mutation {{ disconnectBank(itemId: "{ITEM_ID}") }}"#);
        let body = operator(&fixture.schema, &disconnect).await;
        assert_eq!(body["data"]["disconnectBank"], true, "{body}");
        let on_disk = crate::bank_inbox::BankInbox::open(fixture._dir.path()).unwrap();
        assert!(
            on_disk.contents().waiting.is_empty(),
            "the bank's waiting transactions are dropped"
        );
    }

    /// 008: a transaction Plaid sends again with other values is taken as it
    /// is now while it waits; one the books hold is skipped and, when Plaid's
    /// date or amount differs from what was booked, reported.
    ///
    /// Bug-catch: a fetch that skips what the books hold without a look lets
    /// a booked payment differ from the bank unnoticed; one that does not
    /// skip it puts it in the inbox to be booked a second time.
    #[tokio::test]
    async fn a_transaction_sent_again_is_taken_as_it_is_now() {
        let fixture = mapped(true).await;
        fixture.mock.sync_page(page(
            vec![mock::sync_transaction(
                "t9",
                "acc1",
                7.0,
                "2026-11-01",
                false,
            )],
            vec![],
            vec![],
        ));
        let sync = format!(r#"mutation {{ syncBank(itemId: "{ITEM_ID}") {{ imported }} }}"#);
        let body = operator(&fixture.schema, &sync).await;
        assert_eq!(body["data"]["syncBank"]["imported"], 1, "{body}");
        fixture.mock.sync_page(page(
            vec![mock::sync_transaction(
                "t1",
                "acc1",
                10.0,
                "2026-11-01",
                false,
            )],
            vec![],
            vec![],
        ));
        operator(&fixture.schema, &fetch()).await;

        fixture.mock.sync_page(page(
            vec![
                mock::sync_transaction("t1", "acc1", 12.0, "2026-11-01", false),
                mock::sync_transaction("t9", "acc1", 8.0, "2026-11-01", false),
            ],
            vec![],
            vec![],
        ));
        let body = operator(&fixture.schema, &fetch()).await;
        let counts = &body["data"]["fetchBankTransactions"];
        assert_eq!(counts["updated"], 1, "{body}");
        assert_eq!(counts["alreadyBooked"], 1);
        assert_eq!(counts["added"], 0);
        assert!(
            counts["needsReview"]
                .as_array()
                .unwrap()
                .iter()
                .any(|note| note["transactionId"] == "t9"
                    && note["reason"]
                        .as_str()
                        .unwrap()
                        .contains("another date or amount")),
            "{body}"
        );
        let inbox = run(&fixture.schema, Role::Write, INBOX).await;
        assert_eq!(inbox["data"]["bankInbox"]["total"], 1, "{inbox}");
        assert_eq!(
            inbox["data"]["bankInbox"]["transactions"][0]["amount"]["number"],
            "-12.0"
        );
    }

    /// 008: a page's place at Plaid is stored only once the inbox holding its
    /// transactions is on disk: an inbox that cannot be written leaves the
    /// bank where it was, and the next fetch asks Plaid from there again.
    ///
    /// Bug-catch: the place stored before the inbox, or despite its failure,
    /// moves the bank past transactions the inbox never held — lost, as
    /// Plaid does not send them again.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_page_is_not_passed_until_the_inbox_holds_it() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = mapped(true).await;
        fixture.mock.sync_page(page(
            vec![mock::sync_transaction(
                "t1",
                "acc1",
                12.34,
                "2026-11-01",
                false,
            )],
            vec![],
            vec![],
        ));
        operator(&fixture.schema, &fetch()).await;
        let mut next = page(
            vec![mock::sync_transaction(
                "t2",
                "acc1",
                5.0,
                "2026-11-02",
                false,
            )],
            vec![],
            vec![],
        );
        next["next_cursor"] = json!("c2");
        fixture.mock.sync_page(next);

        let folder = fixture._dir.path();
        std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o500)).unwrap();
        let body = operator(&fixture.schema, &fetch()).await;
        std::fs::set_permissions(folder, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(code(&body), Some("BANK_INBOX"), "{body}");

        operator(&fixture.schema, &fetch()).await;
        let bodies = fixture.mock.sync_bodies();
        assert_eq!(
            bodies[bodies.len() - 1]["cursor"],
            "c1",
            "asked from where the last stored page left it: {bodies:?}"
        );
    }

    /// A ledger with Plaid on, its checking account mapped, `Expenses:Office`
    /// open, and t1 (-12.34) and t4 (+200) waiting in the inbox.
    async fn waiting() -> crate::graphql::plaid::tests::Fixture {
        let fixture = mapped(true).await;
        let body = operator(
            &fixture.schema,
            r#"mutation { openAccount(name: "Expenses:Office", date: "2026-01-01") }"#,
        )
        .await;
        assert!(body["errors"].is_null(), "{body}");
        fixture.mock.sync_page(page(
            vec![
                mock::sync_transaction("t1", "acc1", 12.34, "2026-11-01", false),
                mock::sync_transaction("t4", "acc1", -200.0, "2026-11-03", false),
            ],
            vec![],
            vec![],
        ));
        let body = operator(&fixture.schema, &fetch()).await;
        assert_eq!(body["data"]["fetchBankTransactions"]["added"], 2, "{body}");
        fixture
    }

    fn classify(items: &str) -> String {
        format!(
            "mutation {{ classifyBankTransactions(items: [{items}]) {{ transactionId ok txid code message }} }}"
        )
    }

    fn ignore(items: &str) -> String {
        format!(
            "mutation {{ ignoreBankTransactions(items: [{items}]) {{ transactionId ok code message }} }}"
        )
    }

    const BOOKED: &str =
        "{ journal { flag payee narration links enteredBy postings { account amount { number currency } } } }";

    fn booked(journal: &Value, transaction_id: &str) -> Vec<Value> {
        journal["data"]["journal"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|entry| entry["links"] == json!([format!("plaid-{transaction_id}")]))
            .cloned()
            .collect()
    }

    /// 008: classifying books one entry — the bank's mapped account with the
    /// amount, the chosen account balancing it — flag `*`, Plaid's payee or
    /// the bookkeeper's, entered by the bookkeeper; the transaction leaves
    /// the inbox, and classifying it again is refused, nothing written twice.
    ///
    /// Bug-catch: a booking that leaves the transaction waiting lets a second
    /// bookkeeper book it again — two entries for one payment.
    #[tokio::test]
    async fn classifying_books_one_entry_and_empties_its_slot() {
        let fixture = waiting().await;
        let body = run(
            &fixture.schema,
            Role::Write,
            &classify(r#"{ transactionId: "t1", account: "Expenses:Office", narration: "Printer paper" }"#),
        )
        .await;
        assert!(body["errors"].is_null(), "{body}");
        let result = &body["data"]["classifyBankTransactions"][0];
        assert_eq!(result["ok"], true, "{body}");
        assert!(result["txid"].is_string());

        let journal = operator(&fixture.schema, BOOKED).await;
        let entries = booked(&journal, "t1");
        assert_eq!(entries.len(), 1, "{journal}");
        let entry = &entries[0];
        assert_eq!(entry["flag"], "*");
        assert_eq!(entry["payee"], "Corner Shop");
        assert_eq!(entry["narration"], "Printer paper");
        assert_eq!(entry["enteredBy"], "u_0123456789abcdef");
        let amount = |account: &str| {
            entry["postings"]
                .as_array()
                .unwrap()
                .iter()
                .find(|posting| posting["account"] == account)
                .map(|posting| posting["amount"]["number"].as_str().unwrap().to_owned())
        };
        assert_eq!(amount("Assets:Bank:Checking").as_deref(), Some("-12.34"));
        assert_eq!(amount("Expenses:Office").as_deref(), Some("12.34"));
        let inbox = run(&fixture.schema, Role::Write, INBOX).await;
        assert_eq!(inbox["data"]["bankInbox"]["total"], 1, "{inbox}");

        let again = run(
            &fixture.schema,
            Role::Write,
            &classify(r#"{ transactionId: "t1", account: "Expenses:Uncategorized" }"#),
        )
        .await;
        assert_eq!(
            again["data"]["classifyBankTransactions"][0]["code"], "ALREADY_BOOKED",
            "{again}"
        );
        assert_eq!(
            booked(&operator(&fixture.schema, BOOKED).await, "t1").len(),
            1
        );
    }

    /// 008: one call books several, each on its own: an account not open,
    /// the bank's own account, and a transaction not in the inbox are each
    /// refused with their code, and the rest are booked.
    ///
    /// Bug-catch: one bad line refusing the whole list makes a bookkeeper
    /// working through a month start over at every typo; booking to the
    /// bank's own account writes an entry that moves no money.
    #[tokio::test]
    async fn a_bad_item_does_not_stop_the_others() {
        let fixture = waiting().await;
        let body = run(
            &fixture.schema,
            Role::Write,
            &classify(
                r#"{ transactionId: "t1", account: "Expenses:Nowhere" },
                   { transactionId: "t1", account: "Assets:Bank:Checking" },
                   { transactionId: "zz", account: "Expenses:Office" },
                   { transactionId: "t4", account: "Expenses:Office" }"#,
            ),
        )
        .await;
        assert!(body["errors"].is_null(), "{body}");
        let results = body["data"]["classifyBankTransactions"].as_array().unwrap();
        assert_eq!(results[0]["code"], "ACCOUNT_NOT_OPEN", "{body}");
        assert_eq!(results[1]["code"], "INVALID_INPUT");
        assert_eq!(results[2]["code"], "NOT_IN_INBOX");
        assert_eq!(results[3]["ok"], true);
        let inbox = run(&fixture.schema, Role::Write, INBOX).await;
        assert_eq!(
            inbox["data"]["bankInbox"]["total"], 1,
            "t1 still waits: {inbox}"
        );
        assert_eq!(
            inbox["data"]["bankInbox"]["transactions"][0]["transactionId"],
            "t1"
        );
    }

    /// 008: an ignored transaction leaves the inbox with its reason, writes
    /// nothing, is not fetched again, and cannot be booked or ignored again.
    ///
    /// Bug-catch: an ignore that only hides a transaction has it fetched back
    /// at the next restart of Plaid's pages, and the bookkeeper sees it again
    /// for good.
    #[tokio::test]
    async fn an_ignored_transaction_is_gone_for_good() {
        let fixture = waiting().await;
        let body = run(
            &fixture.schema,
            Role::Write,
            &ignore(r#"{ transactionId: "t1", reason: "a transfer entered by hand" }"#),
        )
        .await;
        assert_eq!(
            body["data"]["ignoreBankTransactions"][0]["ok"], true,
            "{body}"
        );
        assert!(booked(&operator(&fixture.schema, BOOKED).await, "t1").is_empty());
        let on_disk = crate::bank_inbox::BankInbox::open(fixture._dir.path()).unwrap();
        let ignored = &on_disk.contents().ignored["t1"];
        assert_eq!(
            ignored.reason.as_deref(),
            Some("a transfer entered by hand")
        );
        assert_eq!(ignored.by, "u_0123456789abcdef");

        fixture.mock.sync_page(page(
            vec![mock::sync_transaction(
                "t1",
                "acc1",
                12.34,
                "2026-11-01",
                false,
            )],
            vec![],
            vec![],
        ));
        let body = operator(&fixture.schema, &fetch()).await;
        assert_eq!(
            body["data"]["fetchBankTransactions"]["alreadyInInbox"], 1,
            "{body}"
        );
        let inbox = run(&fixture.schema, Role::Write, INBOX).await;
        assert_eq!(inbox["data"]["bankInbox"]["total"], 1, "only t4: {inbox}");

        let again = run(
            &fixture.schema,
            Role::Write,
            &ignore(r#"{ transactionId: "t1" }"#),
        )
        .await;
        assert_eq!(
            again["data"]["ignoreBankTransactions"][0]["code"],
            "ALREADY_IGNORED"
        );
        let book = run(
            &fixture.schema,
            Role::Write,
            &classify(r#"{ transactionId: "t1", account: "Expenses:Office" }"#),
        )
        .await;
        assert_eq!(
            book["data"]["classifyBankTransactions"][0]["code"],
            "BANK_TRANSACTION_IGNORED"
        );
    }

    /// 008: a waiting transaction the books hold some other way — an entry
    /// carrying its link — is refused and leaves the inbox; booking needs a
    /// write key.
    ///
    /// Bug-catch: booking without a look at the books writes a second entry
    /// for a payment already there.
    #[tokio::test]
    async fn what_the_books_hold_is_not_booked_again() {
        let fixture = waiting().await;
        let by_hand = r#"mutation { appendTransaction(input: { date: "2026-11-01", flag: "*", narration: "by hand", links: ["plaid-t1"], postings: [{ account: "Assets:Bank:Checking", amount: { number: "-12.34", currency: "USD" } }, { account: "Expenses:Office" }] }) { txid } }"#;
        let body = operator(&fixture.schema, by_hand).await;
        assert!(body["errors"].is_null(), "{body}");

        let body = run(
            &fixture.schema,
            Role::Write,
            &classify(r#"{ transactionId: "t1", account: "Expenses:Office" }"#),
        )
        .await;
        assert_eq!(
            body["data"]["classifyBankTransactions"][0]["code"], "ALREADY_BOOKED",
            "{body}"
        );
        assert_eq!(
            booked(&operator(&fixture.schema, BOOKED).await, "t1").len(),
            1
        );
        let inbox = run(&fixture.schema, Role::Write, INBOX).await;
        assert_eq!(
            inbox["data"]["bankInbox"]["total"], 1,
            "t1 left the inbox: {inbox}"
        );

        let read = run(
            &fixture.schema,
            Role::Read,
            &classify(r#"{ transactionId: "t4", account: "Expenses:Office" }"#),
        )
        .await;
        assert_eq!(code(&read), Some("FORBIDDEN"), "{read}");
    }

    /// 008: one transaction listed twice in a call is booked once — the
    /// second refused as booked, though the call read the books before the
    /// first — and a call of more than 200 is refused whole.
    ///
    /// Bug-catch: a booking not remembered until the books are read again
    /// lets the same list book it a second time (the call read the books
    /// before its first booking); no cap lets one call hold the inbox for
    /// thousands of writes.
    #[tokio::test]
    async fn one_transaction_twice_in_a_call_is_booked_once() {
        let fixture = waiting().await;
        let body = run(
            &fixture.schema,
            Role::Write,
            &classify(
                r#"{ transactionId: "t1", account: "Expenses:Office" },
                   { transactionId: "t1", account: "Expenses:Uncategorized" }"#,
            ),
        )
        .await;
        let results = body["data"]["classifyBankTransactions"].as_array().unwrap();
        assert_eq!(results[0]["ok"], true, "{body}");
        assert_eq!(results[1]["code"], "ALREADY_BOOKED");
        assert_eq!(
            booked(&operator(&fixture.schema, BOOKED).await, "t1").len(),
            1
        );

        let many = vec![r#"{ transactionId: "t4", account: "Expenses:Office" }"#; 201].join(",");
        let body = run(&fixture.schema, Role::Write, &classify(&many)).await;
        assert_eq!(code(&body), Some("INVALID_INPUT"), "{body}");
        assert_eq!(
            run(&fixture.schema, Role::Write, INBOX).await["data"]["bankInbox"]["total"],
            1
        );
    }

    /// 008: a transaction booked while a fetch runs — the fetch read the
    /// books before it was booked — is not fetched back into the inbox when
    /// Plaid sends it again.
    ///
    /// Bug-catch: a fetch that knows only the books as they were at its
    /// start puts the transaction back in the inbox, and the bookkeeper books
    /// it a second time.
    #[tokio::test]
    async fn a_transaction_booked_while_a_fetch_runs_is_not_fetched_back() {
        let fixture = waiting().await;
        let syncs = || {
            fixture
                .mock
                .paths()
                .iter()
                .filter(|path| path.as_str() == "/transactions/sync")
                .count()
        };
        let before = syncs();
        fixture
            .mock
            .delay("/transactions/sync", std::time::Duration::from_millis(500));
        fixture.mock.sync_page(page(
            vec![mock::sync_transaction(
                "t1",
                "acc1",
                12.34,
                "2026-11-01",
                false,
            )],
            vec![],
            vec![],
        ));
        let schema = fixture.schema.clone();
        let fetching = tokio::spawn(async move { operator(&schema, &fetch()).await });
        while syncs() == before {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let body = run(
            &fixture.schema,
            Role::Write,
            &classify(r#"{ transactionId: "t1", account: "Expenses:Office" }"#),
        )
        .await;
        assert_eq!(
            body["data"]["classifyBankTransactions"][0]["ok"], true,
            "{body}"
        );

        let fetched = fetching.await.unwrap();
        let counts = &fetched["data"]["fetchBankTransactions"];
        assert_eq!(counts["added"], 0, "{fetched}");
        assert_eq!(counts["alreadyBooked"], 1);
        let inbox = run(&fixture.schema, Role::Write, INBOX).await;
        assert_eq!(inbox["data"]["bankInbox"]["total"], 1, "only t4: {inbox}");
    }

    /// 008: what booking checks besides the books — a bank account no longer
    /// mapped is refused and left waiting; an empty narration leaves it out
    /// rather than taking the bank's; a reason too long or with a control
    /// character is refused, the others of the call ignored.
    ///
    /// Bug-catch: booking to the mapping kept at fetch time posts to an
    /// account the operator has since taken off the bank; a bad reason
    /// refusing the whole call loses the bookkeeper's other lines.
    #[tokio::test]
    async fn booking_checks_the_mapping_and_the_text() {
        let fixture = waiting().await;
        let body = run(
            &fixture.schema,
            Role::Write,
            &classify(r#"{ transactionId: "t1", account: "Expenses:Office", narration: " " }"#),
        )
        .await;
        assert_eq!(
            body["data"]["classifyBankTransactions"][0]["ok"], true,
            "{body}"
        );
        let entry = &booked(&operator(&fixture.schema, BOOKED).await, "t1")[0];
        assert!(
            entry["narration"].is_null() || entry["narration"] == "",
            "{entry}"
        );

        let long = "x".repeat(501);
        let body = run(
            &fixture.schema,
            Role::Write,
            &ignore(&format!(
                r#"{{ transactionId: "t4", reason: "{long}" }}, {{ transactionId: "t4", reason: "bell\u0007" }}, {{ transactionId: "zz" }}"#
            )),
        )
        .await;
        let results = body["data"]["ignoreBankTransactions"].as_array().unwrap();
        assert_eq!(results[0]["code"], "INVALID_INPUT", "{body}");
        assert_eq!(results[1]["code"], "INVALID_INPUT");
        assert_eq!(results[2]["code"], "NOT_IN_INBOX");

        let unmap = format!(
            r#"mutation {{ unmapBankAccount(itemId: "{ITEM_ID}", accountId: "acc1") {{ itemId }} }}"#
        );
        let body = operator(&fixture.schema, &unmap).await;
        assert!(body["errors"].is_null(), "{body}");
        let body = run(
            &fixture.schema,
            Role::Write,
            &classify(r#"{ transactionId: "t4", account: "Expenses:Office" }"#),
        )
        .await;
        assert_eq!(
            body["data"]["classifyBankTransactions"][0]["code"], "ACCOUNT_NOT_MAPPED",
            "{body}"
        );
        assert_eq!(
            run(&fixture.schema, Role::Write, INBOX).await["data"]["bankInbox"]["total"],
            1
        );
    }
}
