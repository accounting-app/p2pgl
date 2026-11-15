//! The bank-feed inbox over GraphQL (build-log 008): `fetchBankTransactions`
//! puts a bank's new posted transactions in the ledger's inbox without writing
//! anything to the books; `bankInbox` lists what waits there for a bookkeeper
//! (a write key). Booking from it is a separate step, by a person.

use std::collections::HashMap;

use async_graphql::{Context, Result, SimpleObject};

use super::plaid::{failed, held_imports, import_link, ledger, refused, service, BankSyncNote};
use super::scalars::{DateScalar, DecimalScalar};
use super::types::Amount;
use crate::bank_inbox::InboxTransaction;

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
}
