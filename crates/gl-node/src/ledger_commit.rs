//! Durable ledger writes that block neither the ledger lock nor the runtime
//! (T44).
//!
//! # The problem
//!
//! Every mutation used to serialize the whole `.bean`, write it and `fsync` it
//! **while holding the `RwLock` write guard, on a tokio worker thread**. Two
//! costs followed from that one line:
//!
//! * a slow fsync blocked every GraphQL **read** — readers queue behind the
//!   write guard, so one stalled disk turned a single append into a full API
//!   outage;
//! * the worker thread was parked in a syscall, so the runtime lost a thread
//!   for the duration rather than scheduling other work onto it.
//!
//! # The shape
//!
//! `ledger::service` now splits a persist into *prepare* (in-memory, cheap,
//! under the write lock) and *commit* (the write and the fsync, owning
//! everything it needs). This module holds the async choreography that joins
//! the two, in one place so all four write paths — the three GraphQL mutations,
//! the ALPN supply batch, the file-watcher reconcile, and the node's
//! start/stop compactions — run the identical sequence:
//!
//! ```text
//! let permit = acquire_write_permit(&ledger).await;   // single writer
//! let pending = { let mut svc = ledger.write().await; mutate(&mut svc); svc.prepare_commit()? };
//! commit_pending(&ledger, pending, permit).await?;    // spawn_blocking; owns the permit
//! ```
//!
//! # Why the permit exists, and why it is not the write lock
//!
//! The write lock cannot serialize the commit, because the whole point is that
//! the commit happens with the lock **released**. Without a second, coarser
//! lock two writers could prepare in one order and commit in another — and a
//! compaction commits a snapshot taken at *its* prepare and then deletes the
//! journal, so an append that slipped in between would be erased from disk
//! after its caller had already been told it was durable.
//!
//! So writers hold `LedgerService::commit_gate()` across the whole sequence.
//! It is a `tokio::sync::Mutex`, so a writer waiting on it yields rather than
//! blocking a worker; it is taken strictly **before** the ledger write lock,
//! never the reverse, so the two orders cannot deadlock; and **readers take
//! neither**, which is exactly the property T44 is about — a stalled fsync now
//! delays the next writer and nothing else.
//!
//! # Cancellation (H-11)
//!
//! Every one of those four paths is a future someone else can drop. The node's
//! own `TimeoutLayer` answers 408 and drops the inner service future; an
//! HTTP/2 `RST_STREAM` on the cleartext h2c port does the same on demand; a
//! panic unwinds through it. Before H-11 a drop anywhere between `prepare` and
//! the bookkeeping that follows the `await` was catastrophic and invisible: the
//! `spawn_blocking` write was *not* cancelled, so the bytes landed, but nothing
//! cleared `commit_in_flight` and nothing held the permit any more — so the
//! next writer sailed past the gate, hit `COMMIT_IN_FLIGHT`, and so did every
//! writer after it, for the life of the process. Reads and `/health` were
//! unaffected, so nothing surfaced it.
//!
//! Two changes make cancellation a non-event, and they are deliberately
//! independent:
//!
//! 1. `LedgerService`'s in-flight flag is owned by a guard that ships inside
//!    the `PendingCommit` (`ledger::service::CommitInFlightGuard`), so dropping
//!    the prepared commit — however — releases it. That covers a cancel
//!    *before* the work is handed off, a panic, and any early return a later
//!    change adds.
//! 2. [`commit_pending`] runs the hand-off on a task of its own and takes
//!    ownership of the [`WritePermit`]. Dropping the caller's future drops the
//!    `JoinHandle`, which detaches the task rather than cancelling it, so the
//!    commit still finishes, still folds its receipt back in, and still holds
//!    the single-writer permit while it does. **Cancelling a writer now only
//!    stops it waiting for the answer; it changes nothing about the write.**
//!
//! (2) is what makes (1) almost never fire in production, and it is the half
//! that matters for correctness rather than liveness. Without it a cancelled
//! caller released the permit while its own `spawn_blocking` was still writing,
//! so the *next* writer could take the gate and compact — deleting the journal
//! out from under a commit whose caller had been told nothing, which is exactly
//! the durability bug the gate exists to prevent (see `commit_gate`).
//!
//! T49 left a residual on this: its anti-entropy session deadline is enforced
//! at I/O boundaries and deliberately does **not** wrap the exchange future in
//! `timeout()`, because cancelling mid-commit was this bug. That constraint is
//! now lifted — dropping an exchange future can no longer leave a half-finished
//! commit behind — so T49's residual 3 can be closed by clamping the exchange
//! with a real `timeout()` whenever someone wants the tighter bound.
//!
//! The gate lives on the service rather than beside it so that every holder of
//! a `SharedLedger` reaches the same mutex by construction, with no extra
//! parameter to thread through `AntiEntropyHandler`, the GraphQL schema data
//! and `main`, and no way for one call site to be accidentally left
//! unserialized. `LedgerService::prepare_commit` refuses outright while a
//! commit is in flight, so a caller that forgets the permit gets a loud
//! `COMMIT_IN_FLIGHT` error rather than a silently interleaved write.

use ledger::service::{LedgerService, PendingCommit, ServiceError};
use tokio::sync::OwnedMutexGuard;

use crate::graphql::SharedLedger;

/// Proof that the holder is the single writer for this ledger.
///
/// Held from before the ledger write lock is taken until after the commit is
/// finished or recovered. Dropping it lets the next writer in.
///
/// H-11: it is *moved into* [`commit_pending`], not merely dropped after it, so
/// that the thing holding it for the second half is the commit itself rather
/// than a caller who might be cancelled. See the module docs.
pub(crate) struct WritePermit(#[allow(dead_code)] OwnedMutexGuard<()>);

/// Become the single writer for `ledger`.
///
/// Must be called with **no** ledger lock held: the read guard used to fetch
/// the gate is released before the gate itself is awaited, so a writer waiting
/// for the gate never holds a reader that a competing writer's `write()` would
/// have to wait for.
pub(crate) async fn acquire_write_permit(ledger: &SharedLedger) -> WritePermit {
    let gate = {
        let service = ledger.read().await;
        service.commit_gate()
    };
    WritePermit(gate.lock_owned().await)
}

/// Run a prepared commit off the ledger lock and off the runtime's worker
/// threads, then fold the result back in.
///
/// `None` means the service had nothing to write, which is a success.
///
/// Takes the [`WritePermit`] by value: the commit, not the caller, is what
/// holds the single-writer slot for the second half of the sequence, so every
/// call site ends at this line instead of at a `drop(permit)` it could forget.
///
/// On failure the ledger is reloaded from disk (L-13) so in-memory state never
/// stays ahead of the files, and the original error is returned to the caller —
/// a mutation that could not be made durable must fail, never ack.
///
/// # Cancellation-proof by detaching, not by cleaning up (H-11)
///
/// The whole hand-off runs inside a `tokio::spawn`, and this function only
/// awaits its `JoinHandle`. Dropping a `JoinHandle` **detaches** the task
/// rather than aborting it, so a caller whose future is dropped mid-commit —
/// the 408 `TimeoutLayer`, an HTTP/2 `RST_STREAM`, a `select!` losing a race —
/// stops waiting for the outcome and changes nothing else: the write completes,
/// `finish_commit` folds the receipt in, and the permit is released at the end
/// of the task rather than at the moment of the cancel.
///
/// That ordering is the point. `spawn_blocking` is not cancellable, so the
/// bytes were always going to land; what a cancel used to destroy was the
/// bookkeeping (`commit_in_flight` stuck `true` forever, wedging every write
/// path in the process) and the serialization (the permit released while the
/// write was still running, letting the next writer's compaction delete the
/// journal underneath it). Neither is reachable now.
///
/// It is still belt and braces: `PendingCommit` carries the in-flight guard, so
/// even if this task were aborted or the runtime torn down mid-commit, the flag
/// is released by the drop rather than left set.
pub(crate) async fn commit_pending(
    ledger: &SharedLedger,
    pending: Option<PendingCommit>,
    permit: WritePermit,
) -> Result<(), ServiceError> {
    let Some(pending) = pending else {
        // Nothing to write, so nothing to serialize against: release the slot
        // and let the next writer in immediately.
        drop(permit);
        return Ok(());
    };

    let ledger = std::sync::Arc::clone(ledger);
    let commit = tokio::spawn(async move {
        // The blocking half: one write plus one fsync, on a blocking-pool
        // thread, with no ledger lock held. `PendingCommit` owns its bytes and
        // paths and borrows nothing from the service, which is what makes this
        // legal.
        let outcome = tokio::task::spawn_blocking(move || pending.commit()).await;

        let result = match outcome {
            Ok(Ok(receipt)) => {
                ledger.write().await.finish_commit(receipt);
                Ok(())
            }
            Ok(Err(error)) => {
                ledger.write().await.recover_failed_commit();
                Err(error)
            }
            // The blocking task panicked or the runtime is shutting down. We
            // cannot know whether the write landed, so treat it exactly like a
            // failed commit: reload from disk, which is authoritative either
            // way.
            Err(join_error) => {
                ledger.write().await.recover_failed_commit();
                Err(ServiceError::Io(std::io::Error::other(join_error)))
            }
        };

        // Explicit, and explicitly last: the next writer must not be admitted
        // until this commit's bytes AND its bookkeeping are both done.
        drop(permit);
        result
    });

    match commit.await {
        Ok(result) => result,
        // Two ways here, both at the very end of a process's life: the commit
        // task panicked in its bookkeeping, or the runtime dropped it at
        // shutdown before it finished. The permit and the in-flight guard are
        // released by the unwind or the drop either way, so nothing is left
        // wedged; whether the bytes landed is genuinely unknown, which is what
        // an `Io` error says here, and the next boot reads whatever the files
        // actually hold.
        Err(join_error) => Err(ServiceError::Io(std::io::Error::other(join_error))),
    }
}

/// Prepare and run a full compaction: fold the journal back into the canonical
/// `.bean`.
///
/// Used at the node's deliberate compaction points — just after boot (so a
/// journal left by a crash does not linger) and at a clean shutdown (so the
/// file an operator inspects is the canonical one).
pub(crate) async fn compact(ledger: &SharedLedger) -> Result<(), ServiceError> {
    let permit = acquire_write_permit(ledger).await;
    let pending = {
        let mut service = ledger.write().await;
        // `?` here drops the permit on the way out, which is correct: a prepare
        // that failed left no commit to serialize against.
        prepare_or_recover(&mut service, true)?
    };
    commit_pending(ledger, pending, permit).await
}

/// `prepare_commit` / `prepare_compaction` with the L-13 recovery a failed
/// prepare needs.
///
/// A prepare can fail after it has already changed memory — adoption reconciles
/// a hand edit in before it serializes over it — so the reload belongs here and
/// not only on the commit path. `COMMIT_IN_FLIGHT` is the one exception: it
/// means another commit owns the files right now, nothing was written, and
/// re-booting under it would discard state it is about to make durable.
///
/// # H-11: the `CommitInFlight` re-raise stays, deliberately
///
/// This arm is what made the H-11 wedge *terminal* rather than merely annoying:
/// once a cancelled future had leaked the flag, every later write reached here
/// and was handed straight back out as an error, with nothing on any path left
/// to clear it. So it is fair to ask whether it should now recover instead —
/// `recover_failed_commit` does clear the flag, and that would have unwedged
/// the old bug automatically.
///
/// It should not, for three reasons, in order of weight:
///
/// * `recover_failed_commit` re-boots the service from disk. Doing that while
///   another commit genuinely owns the files discards in-memory state that
///   commit is about to make durable, at the exact moment two writers are
///   already interleaved. It turns "this one write is refused" into "the other
///   writer's acked directives are gone" — strictly worse, and silent.
/// * `COMMIT_IN_FLIGHT` is now a real diagnosis. With the in-flight flag owned
///   by a `Drop` guard and the permit owned by [`commit_pending`], a cancelled
///   or panicking caller can no longer produce it; the only remaining producer
///   is a writer that prepared without the permit, i.e. a genuine double
///   commit. Auto-recovering would mask precisely the bug worth seeing.
/// * The leak is fixed where it was, not where it showed up. Papering over a
///   stuck flag at the consumer would have left the two mechanisms that stick
///   it — the missing guard and the early-released permit — in place for the
///   next path that forgets them.
pub(crate) fn prepare_or_recover(
    service: &mut LedgerService,
    explicit_compaction: bool,
) -> Result<Option<PendingCommit>, ServiceError> {
    let prepared = if explicit_compaction {
        service.prepare_compaction()
    } else {
        service.prepare_commit()
    };
    match prepared {
        Ok(pending) => Ok(pending),
        Err(ServiceError::CommitInFlight) => Err(ServiceError::CommitInFlight),
        Err(error) => {
            service.recover_failed_commit();
            Err(error)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use ledger::service::{CommitKind, LedgerService};
    use tokio::sync::RwLock;

    use super::*;
    use crate::graphql::broadcast::TransactionBroadcast;
    use crate::graphql::build_schema_with_service;

    /// A live `SharedLedger` whose every commit runs `observe` first.
    ///
    /// `set_commit_observer` fires on the blocking thread at the head of
    /// `PendingCommit::commit`, before any I/O — the same seam T44's
    /// stalled-commit test uses. It is the only way to hold a commit open long
    /// enough for a test to cancel *inside* the window H-11 is about;
    /// everything else on the path is the real production code.
    fn ledger_with_commit_observer<F>(path: &Path, observe: F) -> SharedLedger
    where
        F: Fn(CommitKind, u64) + Send + Sync + 'static,
    {
        std::fs::write(path, "").unwrap();
        let mut service = LedgerService::boot(path, "h11-test".to_owned()).unwrap();
        service.set_commit_observer(Arc::new(observe));
        Arc::new(RwLock::new(service))
    }

    /// A ledger whose commits park for `stall`, plus the count of commits that
    /// have entered that stall.
    fn stalled_ledger(path: &Path, stall: Duration) -> (SharedLedger, Arc<AtomicUsize>) {
        let commits = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&commits);
        let ledger = ledger_with_commit_observer(path, move |_kind, _bytes| {
            counter.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(stall);
        });
        (ledger, commits)
    }

    /// One durable write, in the exact permit → lock → prepare → unlock →
    /// commit shape all four production write paths use.
    async fn open_account(ledger: &SharedLedger, name: &str, day: u32) -> Result<(), ServiceError> {
        let permit = acquire_write_permit(ledger).await;
        let pending = {
            let mut service = ledger.write().await;
            service.open_account_staged(
                name.to_owned(),
                chrono::NaiveDate::from_ymd_opt(2024, 1, day).unwrap(),
                Vec::new(),
                |_, _, _| None,
            )?;
            prepare_or_recover(&mut service, false)?
        };
        commit_pending(ledger, pending, permit).await
    }

    /// The headline H-11 regression: cancel a write mid-commit, and the NEXT
    /// write still succeeds.
    ///
    /// Cancellation in Rust is a dropped future, and `tokio::time::timeout`
    /// with a budget well inside the stall drops this one squarely between
    /// `prepare` (which sets the in-flight flag) and the `finish_commit` that
    /// used to be the only thing that cleared it. Before H-11 that left the
    /// flag `true` with nothing alive to clear it and the permit released, so
    /// every later write — all three GraphQL mutations, the ALPN supply batch,
    /// the file-watcher reconcile and the shutdown compaction — got
    /// `COMMIT_IN_FLIGHT` for the life of the process, while reads and
    /// `/health` stayed green.
    ///
    /// Multi-threaded on purpose, for the reason T44's stalled-commit test
    /// gives: production runs on a multi-threaded runtime, and the commit must
    /// be able to park a thread while the runtime keeps polling.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h11_a_write_cancelled_mid_commit_does_not_wedge_the_next_one() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h11-cancel.bean");
        let (ledger, commits) = stalled_ledger(&path, Duration::from_millis(600));

        // 150 ms is comfortably past the point where the commit has entered
        // the observer and comfortably short of the 600 ms it parks there, so
        // the drop lands squarely between `prepare` (which sets the in-flight
        // flag) and the bookkeeping that used to be the only thing clearing it
        // — the exact window a 408, an `RST_STREAM` or a lost `select!` race
        // hits in production. Both margins are wide on purpose: a loaded CI box
        // must not be able to turn this into a flake in either direction.
        let cancelled = tokio::time::timeout(
            Duration::from_millis(150),
            open_account(&ledger, "Assets:Cancelled", 1),
        )
        .await;

        assert!(
            cancelled.is_err(),
            "the write must still be inside its commit when the future is dropped"
        );
        assert_eq!(
            commits.load(Ordering::SeqCst),
            1,
            "the cancel must land AFTER prepare and INSIDE the commit — otherwise \
             this test pins nothing"
        );

        let next = open_account(&ledger, "Assets:Next", 2).await;
        assert!(
            next.is_ok(),
            "H-11: a write cancelled mid-commit must not wedge the next one, got {next:?}"
        );

        // And the cancelled write itself still landed and was still folded back
        // in: detaching the commit means the caller stops waiting for it, not
        // that the commit stops. Booting a second service over the same files
        // is the only authoritative check that both are durable.
        let reloaded = LedgerService::boot(&path, "h11-check".to_owned()).unwrap();
        assert_eq!(
            reloaded.directive_count(),
            2,
            "both the cancelled write and the one after it must be on disk"
        );
    }

    /// The 408 path shape specifically (H-11 trigger 1).
    ///
    /// The node installs `tower_http`'s `TimeoutLayer` on its HTTP stack, with
    /// a `requestTimeoutSeconds` that is legal all the way down to one second.
    /// When it fires it returns `Poll::Ready(Ok(408))` and **drops the inner
    /// service future** — that is the entire mechanism; nothing on the dropped
    /// path is given a chance to clean up. This reproduces it on the real
    /// GraphQL handler future, dropped the same way the layer would drop it,
    /// and asserts the very next request still writes.
    ///
    /// Distinct from the test above because the future being dropped is a
    /// different one: there it is `commit_pending`'s own, here it is the whole
    /// resolver stack wrapped around it, which is what a request timeout
    /// actually holds.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h11_a_408_request_timeout_does_not_wedge_later_mutations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h11-408.bean");
        let (ledger, commits) = stalled_ledger(&path, Duration::from_millis(600));

        let schema = build_schema_with_service(
            Arc::clone(&ledger),
            TransactionBroadcast::new(),
            p2p::node::PeerRegistry::new(),
            Arc::new(security::signing::NoopSignatureProvider),
            true,
            None,
        );

        let timed_out = tokio::time::timeout(
            Duration::from_millis(150),
            schema
                .execute(r#"mutation { openAccount(name: "Assets:Timeout", date: "2024-01-01") }"#),
        )
        .await;

        assert!(
            timed_out.is_err(),
            "the mutation must still be mid-commit when the timeout drops it"
        );
        assert_eq!(
            commits.load(Ordering::SeqCst),
            1,
            "the 408 must land inside the commit window — otherwise this test pins nothing"
        );

        let next = schema
            .execute(r#"mutation { openAccount(name: "Assets:After", date: "2024-01-02") }"#)
            .await;
        assert!(
            next.errors.is_empty(),
            "H-11: a 408'd mutation must not wedge the mutations after it, got {:?}",
            next.errors
        );
    }

    /// A panic in the commit window must not leave the flag set (H-11 trigger
    /// 3).
    ///
    /// Release builds run with `overflow-checks = true`, so a panic on a write
    /// path is not hypothetical, and an unwind is a cancellation like any
    /// other: the frame holding the prepared commit goes away without either
    /// clear ever being called.
    ///
    /// Two phases, because the flag can be lost on either side of the hand-off:
    ///
    /// 1. a panic with the `PendingCommit` still in hand — before the commit is
    ///    handed off at all, which only the `Drop` guard can cover;
    /// 2. a panic *inside* the commit, on the blocking thread, which
    ///    `spawn_blocking` turns into a `JoinError`.
    ///
    /// Both must end with the next write succeeding. The panic messages on
    /// stderr are expected output, not a failure.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h11_a_panic_in_the_commit_window_does_not_leave_the_flag_set() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h11-panic.bean");
        let commits = Arc::new(AtomicUsize::new(0));
        let panic_in_commit = Arc::new(AtomicBool::new(false));
        let counter = Arc::clone(&commits);
        let armed = Arc::clone(&panic_in_commit);
        let ledger = ledger_with_commit_observer(&path, move |_kind, _bytes| {
            counter.fetch_add(1, Ordering::SeqCst);
            if armed.load(Ordering::SeqCst) {
                panic!("deliberate panic inside the commit (H-11 test)");
            }
        });

        // ── Phase 1: the unwind carries the prepared commit away ───────────
        let panicking = tokio::spawn({
            let ledger = Arc::clone(&ledger);
            async move {
                let _permit = acquire_write_permit(&ledger).await;
                let _prepared = {
                    let mut service = ledger.write().await;
                    service
                        .open_account_staged(
                            "Assets:Panic".to_owned(),
                            chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
                            Vec::new(),
                            |_, _, _| None,
                        )
                        .unwrap();
                    prepare_or_recover(&mut service, false).unwrap()
                };
                panic!("deliberate panic holding a prepared commit (H-11 test)");
            }
        });
        let joined = panicking.await.expect_err("the task must have panicked");
        assert!(
            joined.is_panic(),
            "the task must have panicked, got {joined:?}"
        );
        assert_eq!(
            commits.load(Ordering::SeqCst),
            0,
            "the panic must land BEFORE the commit runs — the flag is set and \
             neither clear has been reached"
        );

        let after_unwind = open_account(&ledger, "Assets:AfterUnwind", 2).await;
        assert!(
            after_unwind.is_ok(),
            "H-11: a panic holding a prepared commit must not wedge later writes, \
             got {after_unwind:?}"
        );

        // ── Phase 2: the panic happens inside the commit itself ────────────
        panic_in_commit.store(true, Ordering::SeqCst);
        let panicked_commit = open_account(&ledger, "Assets:PanicInCommit", 3).await;
        assert!(
            panicked_commit.is_err(),
            "a commit that panicked must be reported as a failed write, never acked"
        );

        panic_in_commit.store(false, Ordering::SeqCst);
        let after_commit_panic = open_account(&ledger, "Assets:AfterCommitPanic", 4).await;
        assert!(
            after_commit_panic.is_ok(),
            "H-11: a panic inside the commit must not wedge later writes, got \
             {after_commit_panic:?}"
        );
    }
}
