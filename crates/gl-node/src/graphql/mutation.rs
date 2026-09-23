use async_graphql::{Context, ErrorExtensions, Object, Result};
use std::sync::Arc;

use super::broadcast::TransactionBroadcast;
use super::inputs;
use super::query::txn_to_graphql;
use super::scalars::DateScalar;
use super::types::AppendedTransaction;
use super::{GossipSender, SharedLedger, HEAVY_RESOLVER_COMPLEXITY};
use crate::ledger_commit::{acquire_write_permit, commit_pending, prepare_or_recover};

use ledger::model::{Amount, CostSpec, Flag, PriceSpec};
use ledger::service::{PostingInput, ServiceError, TransactionInput};
use security::signing::{SignableMessage, SignatureProvider};

/// GraphQL mutation root.
///
/// Every mutation runs the same T44 sequence: take the single-writer permit,
/// take the ledger write lock, mutate memory and *prepare* the durable write,
/// drop the lock, run the write + fsync on a blocking thread, then fold the
/// result back in. The lock is therefore held for in-memory work only, and a
/// slow disk delays the next writer rather than every GraphQL reader. See
/// [`crate::ledger_commit`].
pub struct MutationRoot;

#[Object]
impl MutationRoot {
    /// Append a balanced journal entry (FR-1, enforces I1–I3).
    ///
    /// Appends are idempotent by economic content (FR-1 AC4), so a body the
    /// ledger already holds records nothing new. Check `alreadyExisted` on the
    /// payload to tell that case apart from a fresh insert (M-10).
    // Each mutation costs a durable write and an fsync, so alias batching must
    // be budget-limited like the heavy read resolvers (M-1/M-03). T44 made that
    // write O(directive) on a large ledger rather than a whole-file rewrite, but
    // the fsync — which is what the budget is really about — is unchanged.
    #[graphql(complexity = "HEAVY_RESOLVER_COMPLEXITY")]
    async fn append_transaction(
        &self,
        ctx: &Context<'_>,
        input: inputs::TransactionInput,
    ) -> Result<AppendedTransaction> {
        let ledger = ctx.data::<SharedLedger>().map_err(|_| {
            async_graphql::Error::new("Ledger service not initialized")
                .extend_with(|_, ext| ext.set("code", "INTERNAL"))
        })?;

        let flag = match input.flag.as_str() {
            "*" => Flag::Complete,
            "!" => Flag::Incomplete,
            other => {
                return Err(async_graphql::Error::new(format!(
                    "flag must be \"*\" or \"!\", got \"{other}\""
                ))
                .extend_with(|_, ext| ext.set("code", "INVALID_FLAG")));
            }
        };

        let domain_input = TransactionInput {
            date: input.date.0,
            flag,
            payee: input.payee,
            narration: input.narration,
            tags: input.tags,
            links: input.links,
            postings: input
                .postings
                .into_iter()
                .map(|p| PostingInput {
                    account: p.account,
                    amount: p.amount.map(|a| Amount {
                        number: a.number.0,
                        currency: a.currency,
                    }),
                    cost: p.cost.map(|c| CostSpec {
                        amount: Some(Amount {
                            number: c.number.0,
                            currency: c.currency,
                        }),
                        date: None,
                    }),
                    price: p.price.map(|pr| {
                        PriceSpec::Unit(Amount {
                            number: pr.number.0,
                            currency: pr.currency,
                        })
                    }),
                })
                .collect(),
        };

        // T44: single writer from here until the commit is finished.
        let permit = acquire_write_permit(ledger).await;
        let mut svc = ledger.write().await;
        let signer = ctx.data::<Arc<dyn SignatureProvider>>().ok().cloned();
        // M-10: the service tells us whether this body was already in the DAG.
        // It is the only party that can — re-checking here would be a
        // get-then-append race — and the answer rides out on `alreadyExisted`.
        let outcome = svc
            .append_transaction_staged(domain_input, |id, parents, lamport| {
                signer.as_ref().and_then(|provider| {
                    provider.sign(&SignableMessage {
                        content_id: id,
                        is_transaction: true,
                        parents,
                        lamport,
                    })
                })
            })
            .map_err(service_error_to_graphql)?;
        let content_id = outcome.txid;
        // M-39: a failed prepare releases the write lock BEFORE its L-13
        // reload runs, so readers are not queued behind a full-ledger rebuild;
        // the permit rides back out for the commit.
        let (svc, pending, permit) = prepare_or_recover(ledger, svc, false, permit)
            .await
            .map_err(service_error_to_graphql)?;

        // Look up the just-inserted transaction to return it.
        let txn = svc
            .get_directive(&content_id)
            .and_then(|d| {
                if let ledger::model::Directive::Transaction(t) = d {
                    // M-45: `content_id` is this transaction's id; no re-hash.
                    Some(txn_to_graphql(t, content_id.clone(), true))
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                async_graphql::Error::new("Transaction inserted but not found")
                    .extend_with(|_, ext| ext.set("code", "INTERNAL"))
            })?;

        // T41: a duplicate append records nothing new, so it announces nothing.
        //
        // Both of these used to fire on a body the DAG already held. The
        // broadcast published a "new transaction" event to every subscriber for
        // a transaction that had been there for hours — indistinguishable from a
        // real append, so a client counting the stream over-counts and a client
        // reacting to it acts twice. The gossip send re-announced someone else's
        // directive, envelope and all: under M-10 the stored envelope names
        // whoever inserted the body FIRST, so a squatted transaction was
        // re-broadcast by its victim, with its victim's node as the relay.
        //
        // The write itself is unchanged — `appendTransaction` is still
        // idempotent by economic content (FR-1 AC4) and still returns the txid
        // and `alreadyExisted: true`. Nothing is lost by staying quiet: the
        // directive is already persisted here and already known to the mesh,
        // which is precisely why it was a duplicate.
        let to_gossip = if outcome.already_existed {
            None
        } else {
            svc.get_directive(&content_id).cloned()
        };
        drop(svc);

        // T44: the write and the fsync happen here — no ledger lock held, and
        // on a blocking-pool thread rather than a runtime worker. The caller
        // still awaits the outcome, so a mutation that returns success is still
        // a mutation whose directive is on disk.
        // T44/H-11: `commit_pending` owns the permit from here, so the
        // single-writer slot is released by the commit itself rather than by
        // this frame — which a dropped request future would not run.
        commit_pending(ledger, pending, permit)
            .await
            .map_err(service_error_to_graphql)?;

        if !outcome.already_existed {
            // Publish to subscribers (local + remote appends) only once the
            // write is durable: announcing a transaction that a failed commit
            // then rolled out of memory would be a lie to every subscriber.
            if let Ok(broadcast) = ctx.data::<TransactionBroadcast>() {
                broadcast.publish(txn.clone());
            }
            gossip_after_unlock(ctx, to_gossip).await;
        }

        Ok(AppendedTransaction {
            transaction: txn,
            already_existed: outcome.already_existed,
        })
    }

    /// Open an account (FR-3 AC1).
    // Each mutation costs a durable write and an fsync, so alias batching must
    // be budget-limited like the heavy read resolvers (M-1/M-03). T44 made that
    // write O(directive) on a large ledger rather than a whole-file rewrite, but
    // the fsync — which is what the budget is really about — is unchanged.
    #[graphql(complexity = "HEAVY_RESOLVER_COMPLEXITY")]
    async fn open_account(
        &self,
        ctx: &Context<'_>,
        name: String,
        date: DateScalar,
        currencies: Option<Vec<String>>,
    ) -> Result<bool> {
        let ledger = ctx.data::<SharedLedger>().map_err(|_| {
            async_graphql::Error::new("Ledger service not initialized")
                .extend_with(|_, ext| ext.set("code", "INTERNAL"))
        })?;

        let permit = acquire_write_permit(ledger).await;
        let mut svc = ledger.write().await;
        let signer = ctx.data::<Arc<dyn SignatureProvider>>().ok().cloned();
        let content_id = svc
            .open_account_staged(
                name,
                date.0,
                currencies.unwrap_or_default(),
                |id, parents, lamport| {
                    signer.as_ref().and_then(|provider| {
                        provider.sign(&SignableMessage {
                            content_id: id,
                            is_transaction: false,
                            parents,
                            lamport,
                        })
                    })
                },
            )
            .map_err(service_error_to_graphql)?;
        // M-39: see `append_transaction`.
        let (svc, pending, permit) = prepare_or_recover(ledger, svc, false, permit)
            .await
            .map_err(service_error_to_graphql)?;

        // L-18: take the directive out, drop the write lock, THEN gossip —
        // exactly as `append_transaction` does. See [`gossip_after_unlock`].
        //
        // T41 (noticed, not fixed here): unlike `appendTransaction`, this has no
        // `already_existed` signal to suppress a duplicate re-gossip with.
        // `open_account_signing` returns a bare `String`, and its DAG-duplicate
        // arm is reachable — reopening an account after it was closed, with an
        // identical date and currency list, hashes to the id the first `open`
        // already has (the content hash strips the envelope, M-10), so the guard
        // above passes and the insert is a duplicate. Giving it the
        // `AppendOutcome` treatment means changing a public service signature
        // and the mutation's `Boolean` payload, which is an API change rather
        // than hygiene; see `duplicate_reopen_is_still_re_gossiped` for the
        // pinned current behaviour.
        let to_gossip = svc.get_directive(&content_id).cloned();
        drop(svc);
        commit_pending(ledger, pending, permit)
            .await
            .map_err(service_error_to_graphql)?;
        gossip_after_unlock(ctx, to_gossip).await;
        Ok(true)
    }

    /// Close an account (FR-3 AC2).
    // Each mutation costs a durable write and an fsync, so alias batching must
    // be budget-limited like the heavy read resolvers (M-1/M-03). T44 made that
    // write O(directive) on a large ledger rather than a whole-file rewrite, but
    // the fsync — which is what the budget is really about — is unchanged.
    #[graphql(complexity = "HEAVY_RESOLVER_COMPLEXITY")]
    async fn close_account(
        &self,
        ctx: &Context<'_>,
        name: String,
        date: DateScalar,
    ) -> Result<bool> {
        let ledger = ctx.data::<SharedLedger>().map_err(|_| {
            async_graphql::Error::new("Ledger service not initialized")
                .extend_with(|_, ext| ext.set("code", "INTERNAL"))
        })?;

        let permit = acquire_write_permit(ledger).await;
        let mut svc = ledger.write().await;
        let signer = ctx.data::<Arc<dyn SignatureProvider>>().ok().cloned();
        let content_id = svc
            .close_account_staged(name, date.0, |id, parents, lamport| {
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

        // L-18: see `open_account`.
        let to_gossip = svc.get_directive(&content_id).cloned();
        drop(svc);
        commit_pending(ledger, pending, permit)
            .await
            .map_err(service_error_to_graphql)?;
        gossip_after_unlock(ctx, to_gossip).await;
        Ok(true)
    }
}

/// Convert a `ServiceError` into a client-facing GraphQL error.
///
/// `Io` errors can embed filesystem paths and OS details (L3), so they are
/// collapsed to a generic message and the underlying error is logged
/// server-side only. Other variants carry no sensitive data and are surfaced
/// as-is to help API callers correct their request. The machine-readable `code`
/// is preserved in every case.
fn service_error_to_graphql(error: ServiceError) -> async_graphql::Error {
    let code = error.error_code();
    let message = match &error {
        ServiceError::Io(io_error) => {
            tracing::error!(%io_error, "ledger I/O error serving mutation");
            "internal storage error".to_owned()
        }
        _ => error.to_string(),
    };
    async_graphql::Error::new(message).extend_with(|_, ext| ext.set("code", code))
}

/// Announce a just-written directive on the gossip topic (R1).
///
/// Takes the directive **by value**, which is the whole point (L-18): the caller
/// must have cloned it out of the service and dropped the ledger write guard
/// before calling, so this function cannot be handed a live borrow of the
/// locked service.
///
/// `GossipSender` is a bounded `mpsc::Sender`, so `send` awaits when the gossip
/// task is behind — a slow or wedged mesh, or a publish backlog. `openAccount`
/// and `closeAccount` used to await it while still holding the write guard,
/// which parks not just the next writer but every *reader* behind the `RwLock`:
/// one full channel turned a single account mutation into a full GraphQL
/// outage. `appendTransaction` already dropped the guard first; all three paths
/// now run the identical sequence.
///
/// The send result is deliberately discarded: a closed channel means the gossip
/// task is gone, the directive is already durably persisted, and anti-entropy
/// will carry it to peers regardless — failing the mutation would be a lie about
/// what was written.
async fn gossip_after_unlock(ctx: &Context<'_>, directive: Option<ledger::model::Directive>) {
    if let (Some(directive), Ok(sender)) = (directive, ctx.data::<GossipSender>()) {
        let _ = sender.send(directive).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphql::{build_schema_with_service, SharedLedger};
    use ledger::service::LedgerService;
    use std::io;
    use std::time::Duration;
    use tokio::sync::RwLock;

    /// A schema whose gossip channel is bounded at 1 and **already full**, so
    /// the next `send` inside a mutation will await indefinitely.
    ///
    /// Returns the ledger too, so a test can prove whether the write lock is
    /// still held while that send is parked. The receiver is returned and held
    /// (never read) — dropping it would close the channel and make `send` fail
    /// fast instead of blocking, which is the opposite of what we want to test.
    fn schema_with_a_full_gossip_channel() -> (
        tempfile::TempDir,
        SharedLedger,
        crate::graphql::AppSchema,
        tokio::sync::mpsc::Receiver<ledger::model::Directive>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let bean_path = dir.path().join("test.bean");
        std::fs::write(&bean_path, "").unwrap();
        let service = LedgerService::boot(&bean_path, "test-node".to_owned()).unwrap();
        let ledger: SharedLedger = Arc::new(RwLock::new(service));

        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        // Fill the single slot. Nothing ever drains it.
        sender
            .try_send(ledger::model::Directive::Open(ledger::model::Open {
                date: chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
                account: "Assets:Filler".to_owned(),
                currencies: vec![],
                metadata: Default::default(),
            }))
            .expect("the channel must accept exactly one item");

        let schema = build_schema_with_service(
            Arc::clone(&ledger),
            TransactionBroadcast::new(),
            p2p::node::PeerRegistry::new(),
            Arc::new(security::signing::NoopSignatureProvider),
            true,
            Some(sender),
        );
        (dir, ledger, schema, receiver)
    }

    /// Wait until the mutation running in the background has persisted its
    /// write and parked in the gossip send.
    ///
    /// Succeeds only when the ledger lock is obtainable **and** the directive
    /// count has reached `expected` — i.e. the write landed and the lock was
    /// released around the blocking send. With L-18 unfixed the guard is never
    /// released, so every acquisition times out and this panics.
    async fn wait_until_write_landed_and_lock_free(ledger: &SharedLedger, expected: usize) {
        let mut ever_acquired = false;
        for _ in 0..200 {
            if let Ok(guard) = tokio::time::timeout(Duration::from_millis(25), ledger.write()).await
            {
                ever_acquired = true;
                if guard.directive_count() == expected {
                    return;
                }
            }
            tokio::task::yield_now().await;
        }
        panic!(
            "ledger never reached {expected} directives with the lock free \
             (lock was obtainable at some point: {ever_acquired}) — the mutation \
             is holding the write guard across its gossip send"
        );
    }

    #[tokio::test]
    async fn test_open_account_does_not_hold_the_write_lock_across_gossip() {
        // L-18 regression. `openAccount` used to `await` the bounded gossip
        // send while still holding the ledger write guard, so a wedged mesh (or
        // merely a gossip task slower than the API) parked every subsequent
        // GraphQL reader AND writer behind the `RwLock`. The mutation itself
        // never returns here — the send has nowhere to go — but the ledger must
        // be free the moment the write is persisted.
        let (_dir, ledger, schema, _receiver) = schema_with_a_full_gossip_channel();

        let mutation = tokio::spawn(async move {
            schema
                .execute(r#"mutation { openAccount(name: "Assets:Cash", date: "2024-01-01") }"#)
                .await
        });

        // The write must land and the lock must be free while the mutation is
        // still parked in its gossip send.
        wait_until_write_landed_and_lock_free(&ledger, 1).await;

        // A *reader* gets in too — the lock is genuinely released.
        assert!(
            tokio::time::timeout(Duration::from_millis(500), ledger.read())
                .await
                .is_ok(),
            "a reader must not be blocked behind the parked gossip send"
        );
        // And the mutation really is still parked: it is blocked in the gossip
        // send, not merely finished before the test looked.
        assert!(
            !mutation.is_finished(),
            "the gossip send must still be blocked — otherwise this proves nothing"
        );

        mutation.abort();
    }

    #[tokio::test]
    async fn test_close_account_does_not_hold_the_write_lock_across_gossip() {
        // Same shape for the other half of L-18.
        let (_dir, ledger, schema, _receiver) = schema_with_a_full_gossip_channel();

        // Open first, through the service directly, so the gossip slot is still
        // free for the close to block on.
        ledger
            .write()
            .await
            .open_account(
                "Assets:Cash".to_owned(),
                chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
                vec![],
            )
            .unwrap();

        let mutation = tokio::spawn(async move {
            schema
                .execute(r#"mutation { closeAccount(name: "Assets:Cash", date: "2024-06-01") }"#)
                .await
        });

        wait_until_write_landed_and_lock_free(&ledger, 2).await;
        assert!(!mutation.is_finished());

        mutation.abort();
    }

    #[tokio::test]
    async fn test_append_transaction_does_not_hold_the_write_lock_across_gossip() {
        // The path that was already correct, pinned so it stays that way — all
        // three mutations now run the identical drop-then-gossip sequence.
        let (_dir, ledger, schema, _receiver) = schema_with_a_full_gossip_channel();
        {
            let mut svc = ledger.write().await;
            let date = chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap();
            svc.open_account("Assets:Cash".to_owned(), date, vec![])
                .unwrap();
            svc.open_account("Equity:Opening".to_owned(), date, vec![])
                .unwrap();
        }

        let mutation = tokio::spawn(async move {
            schema
                .execute(
                    r#"mutation { appendTransaction(input: {
                        date: "2024-01-15",
                        narration: "Funding",
                        postings: [
                            { account: "Assets:Cash", amount: { number: "100", currency: "USD" } },
                            { account: "Equity:Opening", amount: { number: "-100", currency: "USD" } }
                        ]
                    }) { txid alreadyExisted } }"#,
                )
                .await
        });

        wait_until_write_landed_and_lock_free(&ledger, 3).await;
        assert!(!mutation.is_finished());

        mutation.abort();
    }

    // ─── T41: a duplicate append announces nothing ─────────────────────────

    /// A schema with a DRAINABLE gossip channel and a live broadcast handle, so
    /// a test can count what a mutation actually announced.
    fn schema_with_drainable_gossip() -> (
        tempfile::TempDir,
        SharedLedger,
        crate::graphql::AppSchema,
        TransactionBroadcast,
        tokio::sync::mpsc::Receiver<ledger::model::Directive>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let bean_path = dir.path().join("test.bean");
        std::fs::write(&bean_path, "").unwrap();
        let service = LedgerService::boot(&bean_path, "test-node".to_owned()).unwrap();
        let ledger: SharedLedger = Arc::new(RwLock::new(service));

        let (sender, receiver) = tokio::sync::mpsc::channel(64);
        let broadcast = TransactionBroadcast::new();
        let schema = build_schema_with_service(
            Arc::clone(&ledger),
            broadcast.clone(),
            p2p::node::PeerRegistry::new(),
            Arc::new(security::signing::NoopSignatureProvider),
            true,
            Some(sender),
        );
        (dir, ledger, schema, broadcast, receiver)
    }

    const FUNDING_MUTATION: &str = r#"mutation { appendTransaction(input: {
        date: "2024-01-15",
        narration: "Funding",
        postings: [
            { account: "Assets:Cash", amount: { number: "100", currency: "USD" } },
            { account: "Equity:Opening", amount: { number: "-100", currency: "USD" } }
        ]
    }) { txid alreadyExisted } }"#;

    /// M-10 follow-up: appending a body the DAG already holds must not publish a
    /// phantom "new transaction" to subscribers, and must not re-gossip the
    /// directive — whose envelope, under M-10, names whoever inserted it first.
    #[tokio::test]
    async fn duplicate_append_neither_broadcasts_nor_re_gossips() {
        let (_dir, ledger, schema, broadcast, mut gossip) = schema_with_drainable_gossip();
        {
            let mut svc = ledger.write().await;
            let date = chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap();
            svc.open_account("Assets:Cash".to_owned(), date, vec![])
                .unwrap();
            svc.open_account("Equity:Opening".to_owned(), date, vec![])
                .unwrap();
        }
        // Drain the two `open` announcements so only the appends are counted.
        let mut subscriber = broadcast.subscribe();
        while gossip.try_recv().is_ok() {}

        // First append: real, and it announces.
        let first = schema.execute(FUNDING_MUTATION).await;
        assert!(first.errors.is_empty(), "{:?}", first.errors);
        assert!(
            first.data.to_string().contains("alreadyExisted: false"),
            "the first append must be a fresh insert: {}",
            first.data
        );
        assert!(gossip.try_recv().is_ok(), "a real append must gossip");
        assert!(
            subscriber.try_recv().is_ok(),
            "a real append must reach subscribers"
        );

        // Second append of the identical body: idempotent, and silent.
        let second = schema.execute(FUNDING_MUTATION).await;
        assert!(second.errors.is_empty(), "{:?}", second.errors);
        assert!(
            second.data.to_string().contains("alreadyExisted: true"),
            "the second append must report the duplicate: {}",
            second.data
        );
        assert!(
            gossip.try_recv().is_err(),
            "a duplicate append must not re-gossip the directive"
        );
        assert!(
            subscriber.try_recv().is_err(),
            "a duplicate append must not publish a phantom transaction event"
        );

        // And the ledger is unchanged: two opens plus one transaction.
        assert_eq!(ledger.read().await.directive_count(), 3);
    }

    /// The open/close counterpart, pinned as the CURRENT behaviour rather than
    /// fixed: `openAccount` has no duplicate signal to suppress on, and its
    /// DAG-duplicate arm really is reachable by reopening a closed account with
    /// an identical body. See the comment at the `openAccount` gossip site.
    #[tokio::test]
    async fn duplicate_reopen_is_still_re_gossiped() {
        let (_dir, ledger, schema, _broadcast, mut gossip) = schema_with_drainable_gossip();

        let open = r#"mutation { openAccount(name: "Assets:Cash", date: "2024-01-01") }"#;
        assert!(schema.execute(open).await.errors.is_empty());
        assert!(schema
            .execute(r#"mutation { closeAccount(name: "Assets:Cash", date: "2024-06-01") }"#)
            .await
            .errors
            .is_empty());
        while gossip.try_recv().is_ok() {}
        let before = ledger.read().await.directive_count();

        // The identical `open` again: accepted (the account is closed now) and
        // a DAG duplicate (the content hash strips the envelope).
        let reopened = schema.execute(open).await;
        assert!(reopened.errors.is_empty(), "{:?}", reopened.errors);
        assert_eq!(
            ledger.read().await.directive_count(),
            before,
            "the reopen must really be a DAG duplicate — otherwise this pins nothing"
        );
        assert!(
            gossip.try_recv().is_ok(),
            "current behaviour: the duplicate reopen is still announced"
        );
    }

    // ─── T44: a stalled commit must not block reads ────────────────────────

    /// T44 goal (b): a slow fsync must not block GraphQL **reads**.
    ///
    /// The seam is `LedgerService::set_commit_observer`, which production never
    /// installs: it fires on the blocking thread at the head of
    /// `PendingCommit::commit`, before any I/O, so sleeping in it stands in for
    /// a disk that takes three quarters of a second to acknowledge an fsync.
    /// Everything else in the path is the real production code.
    ///
    /// Three things are asserted together, and the test is worthless without
    /// all three: the commit really is still in flight (otherwise there is no
    /// stall to be blocked by), a reader **and** a writer both get the ledger
    /// lock while it is, and the mutation still reports success with the
    /// directive genuinely on disk — T44 must not turn a durable ack into a
    /// fire-and-forget one.
    // Multi-threaded on purpose: `#[tokio::main]` gives production a
    // multi-threaded runtime, and on a current-thread one a blocking commit
    // parks the *only* worker, so the test could not even observe the stall it
    // is measuring. Two workers reproduce the shape that matters — one thread
    // in the write, another serving reads.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn t44_a_stalled_commit_blocks_neither_reads_nor_the_ledger_lock() {
        let dir = tempfile::tempdir().unwrap();
        let bean_path = dir.path().join("test.bean");
        std::fs::write(&bean_path, "").unwrap();
        let mut service = LedgerService::boot(&bean_path, "test-node".to_owned()).unwrap();
        service.set_commit_observer(Arc::new(|_kind, _bytes| {
            std::thread::sleep(Duration::from_millis(750));
        }));
        let ledger: SharedLedger = Arc::new(RwLock::new(service));

        let schema = build_schema_with_service(
            Arc::clone(&ledger),
            TransactionBroadcast::new(),
            p2p::node::PeerRegistry::new(),
            Arc::new(security::signing::NoopSignatureProvider),
            true,
            None,
        );

        let started = std::time::Instant::now();
        let mutation = tokio::spawn(async move {
            schema
                .execute(r#"mutation { openAccount(name: "Assets:Cash", date: "2024-01-01") }"#)
                .await
        });

        // Let the mutation reach its commit and park there.
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            !mutation.is_finished(),
            "the commit must still be stalled — otherwise this proves nothing"
        );

        // A reader gets in while the fsync is in flight. Before T44 the write
        // guard was held across the write and this timed out.
        let reader = tokio::time::timeout(Duration::from_millis(250), ledger.read()).await;
        assert!(
            reader.is_ok(),
            "a GraphQL read must not queue behind a stalled commit"
        );
        drop(reader);

        // And so does a writer: the ledger lock itself is genuinely free, it is
        // only the single-writer permit that the in-flight commit still holds.
        let writer = tokio::time::timeout(Duration::from_millis(250), ledger.write()).await;
        assert!(
            writer.is_ok(),
            "the ledger write lock must be released across the commit"
        );
        drop(writer);

        assert!(
            !mutation.is_finished(),
            "the stall must still be running when both locks were taken"
        );

        // The caller still awaits durability: success means it is on disk.
        let response = mutation.await.unwrap();
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        assert!(
            started.elapsed() >= Duration::from_millis(700),
            "the mutation must have waited for the stalled commit, not acked early"
        );
        assert_eq!(ledger.read().await.directive_count(), 1);
        assert!(
            std::fs::read_to_string(&bean_path)
                .unwrap()
                .contains("Assets:Cash"),
            "a successful mutation must be durable, not fire-and-forget"
        );
    }

    #[test]
    fn test_io_error_message_is_generic_and_hides_path() {
        // L3 regression: an I/O error must not surface the on-disk path to the
        // GraphQL caller.
        let secret_path = "/srv/private/ledger.bean.tmp";
        let error = ServiceError::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{secret_path}: permission denied"),
        ));
        let gql = service_error_to_graphql(error);
        assert_eq!(gql.message, "internal storage error");
        assert!(
            !gql.message.contains(secret_path),
            "GraphQL error must not leak the filesystem path"
        );
    }

    #[test]
    fn test_non_io_error_message_is_preserved() {
        // Non-I/O errors carry no sensitive data and stay actionable for callers.
        let error = ServiceError::InvalidInput {
            message: "both cost and price on posting".to_owned(),
        };
        let gql = service_error_to_graphql(error);
        assert_eq!(gql.message, "both cost and price on posting");
    }
}
