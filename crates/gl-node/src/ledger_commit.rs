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
//! commit_pending(&ledger, pending).await?;            // spawn_blocking
//! drop(permit);
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
/// On failure the ledger is reloaded from disk (L-13) so in-memory state never
/// stays ahead of the files, and the original error is returned to the caller —
/// a mutation that could not be made durable must fail, never ack.
pub(crate) async fn commit_pending(
    ledger: &SharedLedger,
    pending: Option<PendingCommit>,
) -> Result<(), ServiceError> {
    let Some(pending) = pending else {
        return Ok(());
    };

    // The blocking half: one write plus one fsync, on a blocking-pool thread,
    // with no ledger lock held. `PendingCommit` owns its bytes and paths and
    // borrows nothing from the service, which is what makes this legal.
    let outcome = tokio::task::spawn_blocking(move || pending.commit()).await;

    match outcome {
        Ok(Ok(receipt)) => {
            ledger.write().await.finish_commit(receipt);
            Ok(())
        }
        Ok(Err(error)) => {
            ledger.write().await.recover_failed_commit();
            Err(error)
        }
        // The blocking task panicked or the runtime is shutting down. We cannot
        // know whether the write landed, so treat it exactly like a failed
        // commit: reload from disk, which is authoritative either way.
        Err(join_error) => {
            ledger.write().await.recover_failed_commit();
            Err(ServiceError::Io(std::io::Error::other(join_error)))
        }
    }
}

/// Prepare and run a full compaction: fold the journal back into the canonical
/// `.bean`.
///
/// Used at the node's deliberate compaction points — just after boot (so a
/// journal left by a crash does not linger) and at a clean shutdown (so the
/// file an operator inspects is the canonical one).
pub(crate) async fn compact(ledger: &SharedLedger) -> Result<(), ServiceError> {
    let _permit = acquire_write_permit(ledger).await;
    let pending = {
        let mut service = ledger.write().await;
        prepare_or_recover(&mut service, true)?
    };
    commit_pending(ledger, pending).await
}

/// `prepare_commit` / `prepare_compaction` with the L-13 recovery a failed
/// prepare needs.
///
/// A prepare can fail after it has already changed memory — adoption reconciles
/// a hand edit in before it serializes over it — so the reload belongs here and
/// not only on the commit path. `COMMIT_IN_FLIGHT` is the one exception: it
/// means another commit owns the files right now, nothing was written, and
/// re-booting under it would discard state it is about to make durable.
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
