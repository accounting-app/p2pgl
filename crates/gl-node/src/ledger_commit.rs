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
//! let mut svc = ledger.write().await;
//! mutate(&mut svc);
//! let (svc, pending, permit) = prepare_or_recover(&ledger, svc, false, permit).await?;
//! drop(svc);
//! commit_pending(&ledger, pending, permit).await?;    // spawn_blocking; owns the permit
//! ```
//!
//! Neither half rebuilds the ledger under its lock: a failed commit and a
//! failed prepare both reload off the lock while the permit is held (L-43,
//! M-39). At the size cap a mutation does not get that far:
//! [`refuse_if_local_write_cannot_fit`] refuses a write whose journal record
//! cannot fit before anything is staged, so it pays no reload (T77 / L-71) —
//! the check anti-entropy has made since T69.
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

use ledger::model::{Close, Directive, Event, Metadata, Open, Posting, Transaction};
use ledger::service::{
    LedgerService, PendingCommit, RecoveryReload, ServiceError, TransactionInput, ENVELOPE_KEYS,
    MAX_ECONOMIC_BEAN_LENGTH, MAX_LEDGER_FILE_BYTES,
};
use p2p::anti_entropy::RecordEstimate;
use security::signing::{SignableMessage, SignatureProvider};
use tokio::sync::{OwnedMutexGuard, RwLockWriteGuard};

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
    commit_pending_with_reload(ledger, pending, permit, RecoveryReload::load).await
}

/// [`commit_pending`], with the blocking half of the L-13 reload supplied by
/// the caller.
///
/// Production passes [`RecoveryReload::load`] and nothing else; the parameter
/// exists so a test can park the rebuild and observe what the rest of the node
/// can and cannot do while it runs (L-43). It is the same move as the
/// service's commit observer: one seam, everything around it the real code.
async fn commit_pending_with_reload<L>(
    ledger: &SharedLedger,
    pending: Option<PendingCommit>,
    permit: WritePermit,
    load: L,
) -> Result<(), ServiceError>
where
    L: FnOnce(&RecoveryReload) -> Result<LedgerService, ServiceError> + Send + 'static,
{
    let Some(pending) = pending else {
        // Nothing to write, so nothing to serialize against: release the slot
        // and let the next writer in immediately.
        drop(permit);
        return Ok(());
    };

    let ledger = std::sync::Arc::clone(ledger);
    let commit = crate::spawn_in_span(async move {
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
                recover_off_lock(&ledger, load).await;
                Err(error)
            }
            // The blocking task panicked or the runtime is shutting down. We
            // cannot know whether the write landed, so treat it exactly like a
            // failed commit: reload from disk, which is authoritative either
            // way.
            Err(join_error) => {
                recover_off_lock(&ledger, load).await;
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

/// Restore memory == disk after a failed commit without rebuilding the ledger
/// under its lock or on a runtime worker (L-43).
///
/// # The bug this closes
///
/// Both failure arms of [`commit_pending`] used to call
/// `ledger.write().await.recover_failed_commit()`, which runs
/// `LedgerService::boot` inline: up to a 64 MiB read, a parse, a DAG insert
/// per directive and a read-model build, **on a runtime worker with the write
/// guard held**. That is precisely the stall the module docs say T44 removed —
/// every GraphQL read queued behind a full-ledger rebuild — re-introduced once
/// per failed commit, and a failing disk fails every commit.
///
/// # The shape, and why it is safe
///
/// ```text
/// read lock  { reload = svc.begin_recovery() }        // O(1) snapshot of path + author
/// spawn_blocking { reloaded = load(&reload) }          // the boot — no lock, off the runtime
/// write lock { svc.finish_recovery(reload, reloaded) } // the swap (adopt_reloaded)
/// ```
///
/// Only ever called from inside [`commit_pending`]'s task or
/// [`prepare_or_recover`]'s recovery task, each of which owns the
/// [`WritePermit`] until after this returns — so for the whole rebuild no other
/// writer can stage, prepare, commit or reconcile. That is what makes a rebuild
/// read at one moment still correct to install at a later one: the files it
/// read are still the files, and nothing the swap discards was added in
/// between. Readers are not excluded, and see the pre-recovery memory while the
/// rebuild runs — exactly what they could already see for the whole duration
/// of the commit that failed, so no new state becomes observable.
///
/// `finish_recovery` backs the permit with a fingerprint check: if the service
/// moved anyway (a writer that skipped the permit), it discards the stale
/// rebuild and reloads synchronously, i.e. falls back to the pre-L-43
/// behaviour rather than installing something that could lose a durable write.
///
/// A panic in the rebuild (or the blocking pool going away at shutdown) is a
/// failed reload, reported and logged as one — memory is left as it is, which
/// is what a failed synchronous reload has always done. Before this change such
/// a panic unwound through a task holding the write guard.
async fn recover_off_lock<L>(ledger: &SharedLedger, load: L)
where
    L: FnOnce(&RecoveryReload) -> Result<LedgerService, ServiceError> + Send + 'static,
{
    let reload = ledger.read().await.begin_recovery();
    let snapshot = reload.clone();
    let reloaded = match tokio::task::spawn_blocking(move || load(&snapshot)).await {
        Ok(reloaded) => reloaded,
        Err(join_error) => Err(ServiceError::Io(std::io::Error::other(join_error))),
    };
    ledger.write().await.finish_recovery(reload, reloaded);
}

/// Prepare and run a full compaction: fold the journal back into the canonical
/// `.bean`.
///
/// Used at the node's deliberate compaction points — just after boot (so a
/// journal left by a crash does not linger) and at a clean shutdown (so the
/// file an operator inspects is the canonical one).
pub(crate) async fn compact(ledger: &SharedLedger) -> Result<(), ServiceError> {
    let permit = acquire_write_permit(ledger).await;
    let service = ledger.write().await;
    // A failed prepare consumed the permit (its recovery, if it needed one,
    // held it to the end), so `?` has nothing left to release.
    let (service, pending, permit) = prepare_or_recover(ledger, service, true, permit).await?;
    drop(service);
    commit_pending(ledger, pending, permit).await
}

/// `prepare_commit` / `prepare_compaction` with the L-13 recovery a failed
/// prepare needs — run **off** the ledger lock (M-39, R-20).
///
/// Takes the caller's write guard and [`WritePermit`] by value. On success
/// both are handed straight back with the prepared commit, so the caller keeps
/// reading the service under the same lock it staged under (the mutations look
/// up what they just inserted) and then drops the guard and hands the permit
/// to [`commit_pending`], exactly as before. On failure the guard is **dropped
/// before** any recovery runs, the permit goes to the recovery, and only the
/// error comes back.
///
/// # Cancellation (H-11), applied to the recovery
///
/// The synchronous form could not be cancelled mid-recovery: there was no
/// `await` in it. This one has three, so it gets [`commit_pending`]'s
/// treatment: the recovery runs on a task of its own that **owns the permit**,
/// and this function only awaits its `JoinHandle`. A caller dropped mid-reload
/// (a 408, an `RST_STREAM`, a lost `select!`) stops waiting; the rebuild still
/// finishes and installs, and the next writer is admitted only after it has.
/// Borrowing the permit instead would have let a cancel release the
/// single-writer slot with the failed batch still staged in memory and the
/// rebuild abandoned — memory ahead of disk, and the next writer's commit
/// writing a batch whose own write had failed.
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
///
/// # M-39 / R-20: the recovery is off the lock
///
/// Until T69 this function was synchronous and ran `recover_failed_commit` —
/// a full `LedgerService::boot`: up to a 64 MiB read, a parse, a DAG insert per
/// directive and a read-model build — inline, **under the caller's write
/// guard**, so every GraphQL read queued behind it. L-43 had moved the
/// commit-failure arm off the lock; this arm was left behind because it was
/// handed `&mut LedgerService` from inside a guard it could not release. Near
/// the size cap that became M-39: the append arm's projection refuses a peer's
/// batch deterministically, the batch is re-Wanted every tick, and each refusal
/// re-booted the ledger under the write lock — measured 3.65 s of write-lock
/// hold per tick per peer on a 64 MiB ledger, forever.
///
/// Now the guard is dropped and [`recover_off_lock`] runs the same
/// `begin_recovery` → `spawn_blocking` load → `finish_recovery` sequence the
/// commit path uses, while the caller's permit keeps every other writer out.
/// Readers proceed and, for the duration of the rebuild, see the staged but
/// never-durable batch — the same exposure they already had for the duration
/// of every commit (the lock is released between prepare and commit on the
/// success path), and it is rolled out by the install exactly as before.
///
/// # M-37(a): a `.bean` that does not parse is returned, not recovered from
///
/// The second exception. A prepare that fails with `ServiceError::Parse` is
/// the adoption refusing a hand-edited file it cannot read, and since H-14
/// that refusal happens **before** the adoption records anything — the hash,
/// the size, the `stat` marker and the canonical flag are all written only
/// once the text has parsed — so the prepare left memory exactly as the
/// caller staged it and the files untouched. There is nothing for a reload to
/// restore. What the reload *did* do was the finding: `boot` on that file
/// succeeded (L-45 salvages block by block) and loaded every parseable
/// hand-typed block raw — no I3, no body cap, no envelope stamp, no signature
/// — after which the very next write persisted and served it. The write stays
/// refused until the operator repairs the file, exactly as the README says;
/// the caller's staged batch stays in memory and is written by the first
/// commit after the repair (a retry of the same mutation dedups by content
/// id). `LedgerService::commit_inline` carries the same arm for the
/// synchronous callers.
pub(crate) async fn prepare_or_recover<'a>(
    ledger: &'a SharedLedger,
    service: RwLockWriteGuard<'a, LedgerService>,
    explicit_compaction: bool,
    permit: WritePermit,
) -> Result<Prepared<'a>, ServiceError> {
    prepare_or_recover_with_reload(
        ledger,
        service,
        explicit_compaction,
        permit,
        RecoveryReload::load,
    )
    .await
}

/// What a successful [`prepare_or_recover`] hands back: the caller's write
/// guard, the prepared commit (`None` = nothing to write) and the permit it
/// owes to [`commit_pending`].
pub(crate) type Prepared<'a> = (
    RwLockWriteGuard<'a, LedgerService>,
    Option<PendingCommit>,
    WritePermit,
);

/// [`prepare_or_recover`], with the blocking half of the reload supplied by the
/// caller — the same test seam as [`commit_pending_with_reload`] (L-43), so a
/// test can park the rebuild and observe the lock while it runs.
async fn prepare_or_recover_with_reload<'a, L>(
    ledger: &'a SharedLedger,
    mut service: RwLockWriteGuard<'a, LedgerService>,
    explicit_compaction: bool,
    permit: WritePermit,
    load: L,
) -> Result<Prepared<'a>, ServiceError>
where
    L: FnOnce(&RecoveryReload) -> Result<LedgerService, ServiceError> + Send + 'static,
{
    let prepared = if explicit_compaction {
        service.prepare_compaction()
    } else {
        service.prepare_commit()
    };
    match prepared {
        Ok(pending) => Ok((service, pending, permit)),
        Err(ServiceError::CommitInFlight) => Err(ServiceError::CommitInFlight),
        Err(error @ ServiceError::Parse(_)) => Err(error),
        // T86 / M-58: the L-80 refusal with nothing staged — nothing was
        // written and nothing needs rolling back, so no reload (one per
        // startup, shutdown and watcher compaction before T86, and the reload
        // on a file with hand lines lost the over-cap fact).
        Err(error) if service.prepare_refusal_needs_no_reload(&error) => Err(error),
        Err(error) => {
            // M-39: release the lock BEFORE the rebuild; the permit, moved into
            // the recovery task, is what keeps the files and the service still
            // for it (and outlives a cancelled caller — see above).
            drop(service);
            let ledger = std::sync::Arc::clone(ledger);
            let recovery = crate::spawn_in_span(async move {
                recover_off_lock(&ledger, load).await;
                drop(permit);
            });
            // A `JoinError` here is a panic in the recovery's own bookkeeping
            // or a runtime shutting down; either way the prepare's error is
            // still the answer, and the permit went with the task.
            let _ = recovery.await;
            Err(error)
        }
    }
}

/// A local write a GraphQL mutation is about to stage (T77 / L-71) — the
/// input, before any envelope exists.
pub(crate) enum LocalWrite<'a> {
    /// `appendTransaction`.
    Transaction(&'a TransactionInput),
    /// `openAccount`.
    Open {
        account: &'a str,
        date: chrono::NaiveDate,
        currencies: &'a [String],
    },
    /// `closeAccount`.
    Close {
        account: &'a str,
        date: chrono::NaiveDate,
    },
    /// `grantAccess`, `revokeAccess`, `renameUser`: an access record
    /// (`docs/build-log/002-users-and-roles`) — its action and own fields.
    Access {
        date: chrono::NaiveDate,
        action: &'a str,
        fields: &'a Metadata,
    },
}

/// Headroom at or above which no single local write can fail the append arm's
/// cap projection, so [`refuse_if_local_write_cannot_fit`] answers without
/// building anything (T77).
///
/// A local directive's economic form is capped at `MAX_ECONOMIC_BEAN_LENGTH`
/// before it is staged (L-02), and its envelope adds an author, a lamport, at
/// most `MAX_PARENTS` 64-hex parents and one signature — under 20 KiB — plus
/// a record header of under 100 bytes; twice the economic cap is past all of
/// it. Every write on a ledger not within 2 MiB of the cap pays two field
/// reads for this check.
const LOCAL_WRITE_FAST_PATH_HEADROOM: u64 = 2 * MAX_ECONOMIC_BEAN_LENGTH as u64;

/// Refuse a local write whose journal record cannot fit under the size cap,
/// BEFORE it is staged (T77 / L-71).
///
/// # The bug this closes
///
/// A mutation at the cap used to stage, fail its prepare's cap projection and
/// pay an L-13 reload — a full `LedgerService::boot` of up to 64 MiB, off the
/// lock since T69 but with the single-writer permit held throughout. An
/// API-key holder retrying a refused write therefore queued every other
/// writer, the file watcher, peer batches and the shutdown compaction behind
/// one full reload per attempt (3.65 s each on 305k directives); nine
/// concurrent retries gave honest mutations 408s. The peer path has refused
/// such batches before staging since T69; this is the same check for the
/// mutations.
///
/// # How
///
/// Called with the permit and the write lock held, immediately before the
/// `*_staged` call, so nothing moves between the answer and the stage. It
/// builds the directive the stage would store — the resolved transaction
/// (`LedgerService::validate_own_transaction`), the `open` / `close`, or the
/// access record (an `event`, its own fields beside it) — with the envelope the
/// stamp would give it: this node's author, the next lamport, for a
/// transaction EVERY head it may name as a parent (a superset of the at most
/// `MAX_PARENTS` the stamp picks, so never shorter), and the signature the
/// installed provider produces. Its exact share of a journal record
/// ([`RecordEstimate`]) against [`LedgerService::append_headroom`] then
/// decides. The refusal changes nothing — no clock movement, no stage, no
/// reload — and the caller drops the lock and the permit straight after it,
/// so a refused write holds the permit for this check and nothing more.
///
/// # When it does not decide
///
/// It answers `Ok` — leaving the prepare's projection as the authority, as
/// before — whenever it cannot predict the record exactly: the body is a
/// duplicate (the
/// stage records nothing), the input is invalid (the stage's own error is the
/// better answer), or the account is already open / not open. On a ledger
/// more than [`LOCAL_WRITE_FAST_PATH_HEADROOM`] from the cap it builds
/// nothing at all.
pub(crate) fn refuse_if_local_write_cannot_fit(
    service: &LedgerService,
    write: LocalWrite<'_>,
    entered_by: Option<&str>,
    signer: Option<&dyn SignatureProvider>,
) -> Result<(), ServiceError> {
    // T100 / M-74, decision (61): the headroom of the commit this write will
    // take — while a rewrite is pending, the cap minus the rewrite memory would
    // write now, not the file's size, which the rewrite (adopted lines'
    // envelopes, staged writes) can exceed.
    let headroom = service.write_headroom();
    // T93 / M-65, decision (43): at (or over) the cap nothing fits, whatever
    // is already staged.
    if headroom == 0 {
        return Err(ServiceError::ResourceLimitExceeded {
            message: format!(
                "the ledger is at its size cap (max {MAX_LEDGER_FILE_BYTES}); refused before \
                 staging, nothing changed. Archive or split the ledger to make room"
            ),
        });
    }
    // T100 / M-74: no "something else is staged" exemption any more — it
    // skipped the exact estimate whenever a write was stuck staged, so every
    // mutation after it was staged, rebuilt the ledger under the permit and
    // was refused for the cap anyway. The estimate is this write's own record,
    // which is exactly what it adds.
    if headroom >= LOCAL_WRITE_FAST_PATH_HEADROOM {
        return Ok(());
    }
    let Some(record) = local_write_record_bytes(service, write, entered_by, signer) else {
        return Ok(());
    };
    if record <= headroom {
        return Ok(());
    }
    Err(ServiceError::ResourceLimitExceeded {
        message: format!(
            "this write's journal record ({record} bytes) does not fit in the {headroom} bytes \
             left under the ledger size cap (max {MAX_LEDGER_FILE_BYTES}); refused before \
             staging, nothing changed. Archive or split the ledger to make room"
        ),
    })
}

/// The exact journal record `write` would become if staged now, or `None`
/// when that cannot be predicted (see [`refuse_if_local_write_cannot_fit`]).
fn local_write_record_bytes(
    service: &LedgerService,
    write: LocalWrite<'_>,
    entered_by: Option<&str>,
    signer: Option<&dyn SignatureProvider>,
) -> Option<u64> {
    let &[author_key, lamport_key, parents_key, signature_key, format_key] = ENVELOPE_KEYS else {
        return None;
    };
    let lamport = service.lamport_clock().saturating_add(1).to_string();
    let mut envelope = Metadata::new();
    envelope.insert(author_key.to_owned(), service.author_id().to_owned());
    envelope.insert(lamport_key.to_owned(), lamport.clone());
    // Step 4: a person's write carries `entered-by` in its body — in the id
    // and in the record — so it rides with the envelope into the metadata.
    if let Some(who) = entered_by {
        envelope.insert(ledger::access_record::ENTERED_BY.to_owned(), who.to_owned());
    }
    let (mut directive, is_transaction) = match write {
        LocalWrite::Transaction(input) => {
            let body = Transaction {
                date: input.date,
                flag: input.flag,
                payee: input.payee.clone(),
                narration: input.narration.clone(),
                tags: input.tags.clone(),
                links: input.links.clone(),
                postings: input
                    .postings
                    .iter()
                    .map(|posting| Posting {
                        account: posting.account.clone(),
                        amount: posting.amount.clone(),
                        cost: posting.cost.clone(),
                        price: posting.price.clone(),
                        metadata: Metadata::new(),
                    })
                    .collect(),
                metadata: Metadata::new(),
            };
            let resolved = service.validate_own_transaction(&body).ok()?;
            (Directive::Transaction(resolved), true)
        }
        LocalWrite::Open {
            account,
            date,
            currencies,
        } => {
            if service.accounts().is_open(account) {
                return None;
            }
            let open = Open {
                date,
                account: account.to_owned(),
                currencies: currencies.to_vec(),
                metadata: Metadata::new(),
            };
            (Directive::Open(open), false)
        }
        LocalWrite::Close { account, date } => {
            if !service.accounts().is_open(account) {
                return None;
            }
            let close = Close {
                date,
                account: account.to_owned(),
                metadata: Metadata::new(),
            };
            (Directive::Close(close), false)
        }
        LocalWrite::Access {
            date,
            action,
            fields,
        } => {
            let event = Event {
                date,
                event_type: ledger::access_record::ACCESS_EVENT_TYPE.to_owned(),
                description: action.to_owned(),
                metadata: fields.clone(),
            };
            (Directive::Event(event), false)
        }
    };
    // Format v2: a v2 node's write carries the marker, and a v2 id covers the
    // author and the marker — so they are on the record before its id is
    // computed, exactly as `stamp_identity` puts them there. Step 4: a
    // person's `entered-by` is in the id in both formats, so in v1 too the
    // record carries it before the id is computed (review I-1: without it the
    // id was the operator's body's, and a duplicate was judged by the wrong
    // record). A v1 id ignores the envelope keys that come along.
    let v2 = service.emit_format() == ledger::hash::RecordFormat::V2;
    if v2 {
        envelope.insert(format_key.to_owned(), ledger::hash::FORMAT_V2.to_owned());
    }
    if v2 || entered_by.is_some() {
        match &mut directive {
            Directive::Transaction(transaction) => transaction.metadata = envelope.clone(),
            Directive::Open(open) => open.metadata = envelope.clone(),
            Directive::Close(close) => close.metadata = envelope.clone(),
            // An event's own fields stay beside the envelope.
            Directive::Event(event) => event.metadata.extend(envelope.clone()),
            _ => return None,
        }
    }
    let content_id = LedgerService::content_id(&directive);
    if service.contains_directive(&content_id) {
        return None;
    }
    let parents = if is_transaction {
        let parents = service
            .dag()
            .heads_admissible_as_parents_of(&content_id)
            .join(",");
        envelope.insert(parents_key.to_owned(), parents.clone());
        parents
    } else {
        String::new()
    };
    if let Some(signature) = signer.and_then(|provider| {
        provider.sign(&SignableMessage {
            content_id: &content_id,
            is_transaction,
            parents: &parents,
            lamport: &lamport,
        })
    }) {
        envelope.insert(signature_key.to_owned(), signature);
    }
    match &mut directive {
        Directive::Transaction(transaction) => transaction.metadata = envelope,
        Directive::Open(open) => open.metadata = envelope,
        Directive::Close(close) => close.metadata = envelope,
        Directive::Event(event) => event.metadata.extend(envelope),
        _ => return None,
    }
    Some(
        RecordEstimate::new()
            .with(RecordEstimate::directive_bytes(&directive))
            .record_bytes(),
    )
}

/// A ledger within a chosen number of bytes of `MAX_LEDGER_FILE_BYTES`, in
/// the append-arm state a running node is in (M-39 test fixture).
#[cfg(test)]
pub(crate) mod near_cap {
    use std::path::Path;
    use std::sync::Arc;
    use std::time::Duration;

    use ledger::service::{LedgerService, MAX_LEDGER_FILE_BYTES};
    use tokio::sync::RwLock;

    use crate::graphql::SharedLedger;

    /// Boot a ledger whose canonical `.bean` is exactly
    /// `MAX_LEDGER_FILE_BYTES − headroom` bytes, compacted once so the next
    /// write takes the append arm, and return it with its
    /// `append_headroom() == headroom`.
    ///
    /// The bytes are leading `;` comment lines, 1 MiB each: the parser skips
    /// them per line, and a compaction writes them back verbatim, so the file
    /// is at the cap for the append projection without paying to parse,
    /// content-hash and index 64 MiB of directives (the `m35_*` fixture's
    /// trick; a fixture of real directives costs ~20 s per boot in a debug
    /// build). What is still paid per byte is the SHA-256 of the file, at boot,
    /// at the compaction and in every L-13 reload — which is exactly what makes
    /// a reload slow enough here to be observed from a concurrent reader.
    pub(crate) fn near_cap_ledger(path: &Path, headroom: u64) -> SharedLedger {
        near_cap_ledger_emitting(path, headroom, ledger::hash::RecordFormat::V1)
    }

    /// [`near_cap_ledger`] for a node that writes records in `format`.
    pub(crate) fn near_cap_ledger_emitting(
        path: &Path,
        headroom: u64,
        format: ledger::hash::RecordFormat,
    ) -> SharedLedger {
        const LINE: usize = 1 << 20;
        let target = usize::try_from(MAX_LEDGER_FILE_BYTES - headroom).unwrap();
        let mut text = String::with_capacity(target);
        let mut remaining = target;
        while remaining > 0 {
            // Every line is "; " + filler + "\n", so at least 3 bytes.
            let len = if remaining == LINE || remaining >= LINE + 3 {
                LINE
            } else {
                remaining
            };
            text.push_str("; ");
            text.extend(std::iter::repeat_n('x', len - 3));
            text.push('\n');
            remaining -= len;
        }
        std::fs::write(path, &text).unwrap();
        drop(text);
        let mut service =
            LedgerService::boot_emitting(path, "near-cap".to_owned(), format).unwrap();
        // Boot read a file it did not write, so the first commit would be a
        // compaction; take it here, as the node's startup compaction does.
        service.compact().unwrap();
        assert_eq!(service.canonical_bytes(), target as u64, "fixture size");
        assert_eq!(service.append_headroom(), headroom, "fixture headroom");
        Arc::new(RwLock::new(service))
    }

    /// Longest wait for a `read()` of `ledger`, sampled every few ms until
    /// `stop` fires — the "is the write lock ever held for long" probe.
    pub(crate) fn spawn_read_latency_probe(
        ledger: &SharedLedger,
    ) -> (
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<(Duration, usize)>,
    ) {
        let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
        let ledger = Arc::clone(ledger);
        let probe = tokio::spawn(async move {
            let mut worst = Duration::ZERO;
            let mut samples = 0usize;
            loop {
                let started = tokio::time::Instant::now();
                drop(ledger.read().await);
                worst = worst.max(started.elapsed());
                samples += 1;
                tokio::select! {
                    _ = &mut stop_rx => break,
                    () = tokio::time::sleep(Duration::from_millis(2)) => {}
                }
            }
            (worst, samples)
        });
        (stop_tx, probe)
    }
}

#[cfg(test)]
mod tests {
    use crate::graphql::ExecuteAsOperator;
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
        let mut service = ledger.write().await;
        service.open_account_staged(
            name.to_owned(),
            chrono::NaiveDate::from_ymd_opt(2024, 1, day).unwrap(),
            Vec::new(),
            |_, _, _| None,
        )?;
        let (service, pending, permit) = prepare_or_recover(ledger, service, false, permit).await?;
        drop(service);
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
            schema.execute_as_operator(
                r#"mutation { openAccount(name: "Assets:Timeout", date: "2024-01-01") }"#,
            ),
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
            .execute_as_operator(
                r#"mutation { openAccount(name: "Assets:After", date: "2024-01-02") }"#,
            )
            .await;
        assert!(
            next.errors.is_empty(),
            "H-11: a 408'd mutation must not wedge the mutations after it, got {:?}",
            next.errors
        );
    }

    /// L-43: a failed commit's L-13 rebuild runs with NO ledger lock held, no
    /// other writer interleaves with it, and it still ends memory == disk.
    ///
    /// The rebuild is parked through `commit_pending_with_reload`'s seam — the
    /// only non-production piece; the failure, the permit, the locks and the
    /// swap are all the real path. While it is parked the test proves three
    /// things in turn:
    ///
    /// 1. the ledger's write lock is FREE — before L-43 the rebuild ran inside
    ///    `ledger.write().await.recover_failed_commit()`, so every reader
    ///    queued behind a full-ledger boot;
    /// 2. a second writer is nonetheless held off, and has written nothing,
    ///    because the recovering task still owns the single-writer permit;
    /// 3. once released, memory == disk: the failed write is gone from memory,
    ///    the durable one before it and the queued one after it are both in
    ///    memory and on disk.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn l43_a_failed_commit_rebuilds_off_the_lock_and_no_writer_interleaves() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("l43-recovery.bean");
        let fail_next_commit = Arc::new(AtomicBool::new(false));
        let armed = Arc::clone(&fail_next_commit);
        let ledger = ledger_with_commit_observer(&path, move |_kind, _bytes| {
            if armed.swap(false, Ordering::SeqCst) {
                panic!("deliberate commit failure (L-43 test)");
            }
        });

        open_account(&ledger, "Assets:Durable", 1).await.unwrap();

        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        fail_next_commit.store(true, Ordering::SeqCst);
        let failing = tokio::spawn({
            let ledger = Arc::clone(&ledger);
            async move {
                let permit = acquire_write_permit(&ledger).await;
                let mut service = ledger.write().await;
                service
                    .open_account_staged(
                        "Assets:Failed".to_owned(),
                        chrono::NaiveDate::from_ymd_opt(2024, 1, 2).unwrap(),
                        Vec::new(),
                        |_, _, _| None,
                    )
                    .unwrap();
                let (service, pending, permit) =
                    prepare_or_recover(&ledger, service, false, permit)
                        .await
                        .unwrap();
                drop(service);
                commit_pending_with_reload(&ledger, pending, permit, move |reload| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    reload.load()
                })
                .await
            }
        });

        tokio::time::timeout(Duration::from_secs(30), entered_rx)
            .await
            .expect("the failed commit must reach its rebuild")
            .unwrap();

        // ── 1. The rebuild holds no ledger lock ────────────────────────────
        {
            let guard = ledger
                .try_write()
                .expect("L-43: the ledger lock must be free while the rebuild runs");
            assert!(
                guard.accounts().is_open("Assets:Failed"),
                "mid-rebuild, readers see the pre-recovery memory — exactly what they saw \
                 during the commit that failed"
            );
        }

        // ── 2. ...but the permit still excludes every other writer ─────────
        let second = tokio::spawn({
            let ledger = Arc::clone(&ledger);
            async move { open_account(&ledger, "Assets:Second", 3).await }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !second.is_finished(),
            "L-43: a writer must not interleave with an in-progress recovery"
        );
        let on_disk = LedgerService::boot(&path, "l43-probe".to_owned()).unwrap();
        assert!(
            !on_disk.accounts().is_open("Assets:Second"),
            "the queued writer must not have written anything while the rebuild ran"
        );

        // ── 3. Release: memory == disk, and nothing was lost ───────────────
        release_tx.send(()).unwrap();
        let failed = failing.await.unwrap();
        assert!(failed.is_err(), "a failed commit must never be acked");
        second
            .await
            .unwrap()
            .expect("the queued writer runs once the recovery is done");

        let memory = ledger.read().await;
        let disk = LedgerService::boot(&path, "l43-check".to_owned()).unwrap();
        let mut memory_ids = memory.dag().content_ids();
        let mut disk_ids = disk.dag().content_ids();
        memory_ids.sort_unstable();
        disk_ids.sort_unstable();
        assert_eq!(memory_ids, disk_ids, "L-13: memory must equal disk");
        assert!(memory.accounts().is_open("Assets:Durable"));
        assert!(memory.accounts().is_open("Assets:Second"));
        assert!(
            !memory.accounts().is_open("Assets:Failed"),
            "the undurable write must have been rolled out of memory"
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
                let permit = acquire_write_permit(&ledger).await;
                let mut service = ledger.write().await;
                service
                    .open_account_staged(
                        "Assets:Panic".to_owned(),
                        chrono::NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
                        Vec::new(),
                        |_, _, _| None,
                    )
                    .unwrap();
                let (service, _prepared, _permit) =
                    prepare_or_recover(&ledger, service, false, permit)
                        .await
                        .unwrap();
                drop(service);
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

    /// M-37(a): a prepare refused because the `.bean` does not parse returns
    /// `PARSE_ERROR` and does NOT reload. The staged write stays in memory,
    /// awaiting the repair; the broken file is untouched; and — the finding —
    /// nothing from the broken file is loaded raw.
    ///
    /// Bug-catch: remove the `Parse` arm from `prepare_or_recover` and the
    /// reload runs: the staged open is rolled out of memory.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn m37a_a_prepare_refused_by_an_unparsable_file_does_not_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m37a.bean");
        let ledger = ledger_with_commit_observer(&path, |_kind, _bytes| {});
        open_account(&ledger, "Assets:Durable", 1).await.unwrap();

        // A hand edit the parser refuses, plus a valid hand-typed open that a
        // recovery boot would have loaded raw.
        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push_str("\n2024-02-01 open Assets:Typed USD\n\n2024-03-03 open\n");
        std::fs::write(&path, &content).unwrap();

        let permit = acquire_write_permit(&ledger).await;
        let mut service = ledger.write().await;
        service
            .open_account_staged(
                "Assets:Staged".to_owned(),
                chrono::NaiveDate::from_ymd_opt(2024, 1, 2).unwrap(),
                Vec::new(),
                |_, _, _| None,
            )
            .unwrap();
        let Err(error) = prepare_or_recover(&ledger, service, false, permit).await else {
            panic!("a broken file refuses the prepare");
        };
        assert_eq!(error.error_code(), "PARSE_ERROR");

        let service = ledger.read().await;
        assert!(
            service.accounts().is_open("Assets:Staged"),
            "M-37(a): no reload ran — the staged write is still in memory, awaiting the repair"
        );
        assert_eq!(service.uncommitted_count(), 1);
        assert!(
            !service.accounts().is_open("Assets:Typed"),
            "M-37(a): nothing from the broken file was loaded raw"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            content,
            "the broken file is untouched"
        );
    }

    /// H-15 through the watcher-shaped path: the `.bean` is removed under the
    /// node, `reconcile_file_staged` reports nothing to reconcile and arms a
    /// compaction, and the commit the watcher drives recreates the file from
    /// memory with every directive in it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn h15_a_removed_bean_is_recreated_by_the_watcher_shaped_reconcile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h15.bean");
        let ledger = ledger_with_commit_observer(&path, |_kind, _bytes| {});
        open_account(&ledger, "Assets:One", 1).await.unwrap();
        open_account(&ledger, "Assets:Two", 2).await.unwrap();
        std::fs::remove_file(&path).unwrap();

        let permit = acquire_write_permit(&ledger).await;
        let mut service = ledger.write().await;
        let result = service
            .reconcile_file_staged()
            .expect("H-15: a missing file is nothing to reconcile, not an error");
        assert_eq!((result.new_directives, result.rejected), (0, 0));
        assert!(
            service.compaction_pending(),
            "the watcher must be told to drive the commit that recreates the file"
        );
        let (service, prepared, permit) = prepare_or_recover(&ledger, service, true, permit)
            .await
            .unwrap();
        drop(service);
        commit_pending(&ledger, prepared, permit).await.unwrap();

        assert!(path.exists(), "the compaction recreated the file");
        let on_disk = LedgerService::boot(&path, "h15-check".to_owned()).unwrap();
        assert_eq!(on_disk.directive_count(), 2);
        assert!(on_disk.accounts().is_open("Assets:One"));
        assert!(on_disk.accounts().is_open("Assets:Two"));
        assert_eq!(ledger.read().await.directive_count(), 2);
    }

    /// M-39 / R-20: a prepare refused at the size cap rebuilds the ledger with
    /// NO lock held, while the permit still keeps every other writer out —
    /// the L-43 shape, now on the prepare-failure arm too.
    ///
    /// The rebuild is parked through `prepare_or_recover_with_reload`'s seam;
    /// the cap, the refusal, the permit, the locks and the install are the
    /// real path.
    ///
    /// Bug-catch: make the failure arm call `service.recover_failed_commit()`
    /// under the guard again (the pre-T69 body) and the parked loader is never
    /// reached — the test times out waiting for it — and `try_write` would
    /// fail for the whole rebuild.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn m39_a_prepare_refused_at_the_cap_rebuilds_off_the_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m39-prepare.bean");
        let ledger = near_cap::near_cap_ledger(&path, 64);

        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let failing = tokio::spawn({
            let ledger = Arc::clone(&ledger);
            async move {
                let permit = acquire_write_permit(&ledger).await;
                let mut service = ledger.write().await;
                service
                    .open_account_staged(
                        "Assets:Over".to_owned(),
                        chrono::NaiveDate::from_ymd_opt(2024, 1, 2).unwrap(),
                        Vec::new(),
                        |_, _, _| None,
                    )
                    .unwrap();
                let prepared = prepare_or_recover_with_reload(
                    &ledger,
                    service,
                    false,
                    permit,
                    move |reload| {
                        entered_tx.send(()).unwrap();
                        release_rx.recv().unwrap();
                        reload.load()
                    },
                )
                .await;
                prepared.err().map(|error| error.error_code())
            }
        });

        tokio::time::timeout(Duration::from_secs(120), entered_rx)
            .await
            .expect("the refused prepare must reach its rebuild")
            .unwrap();

        // ── 1. The rebuild holds no ledger lock ────────────────────────────
        {
            let guard = ledger
                .try_write()
                .expect("M-39: the ledger lock must be free while the rebuild runs");
            assert!(
                guard.accounts().is_open("Assets:Over"),
                "mid-rebuild, readers see the staged batch the install will roll out"
            );
        }

        // ── 2. ...but the permit still excludes every other writer ─────────
        let second = tokio::spawn({
            let ledger = Arc::clone(&ledger);
            async move { open_account(&ledger, "Assets:Second", 3).await }
        });
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            !second.is_finished(),
            "M-39: a writer must not interleave with an in-progress recovery"
        );

        // ── 3. Release: refused, rolled back, and the node still compacts ──
        release_tx.send(()).unwrap();
        assert_eq!(
            failing.await.unwrap(),
            Some("RESOURCE_LIMIT_EXCEEDED"),
            "a write that cannot fit is refused, never acked"
        );
        let second = second.await.unwrap();
        assert_eq!(
            second.map_err(|error| error.error_code()),
            Err("RESOURCE_LIMIT_EXCEEDED"),
            "the queued writer does not fit either"
        );
        {
            let service = ledger.read().await;
            assert!(!service.accounts().is_open("Assets:Over"));
            assert!(!service.accounts().is_open("Assets:Second"));
            assert_eq!(service.uncommitted_count(), 0, "memory == disk again");
            assert_eq!(service.append_headroom(), 64);
        }
        compact(&ledger)
            .await
            .expect("near the cap the node still accepts a compaction");
    }

    /// M-39 / R-20 through the real GraphQL mutation: a write refused at the
    /// cap never holds the write lock long, so a concurrent reader never waits
    /// more than 100 ms — measured with a timed `read()` probe across the
    /// whole mutation.
    ///
    /// Since T77 (L-71) the mutation is refused BEFORE staging and pays no
    /// reload at all (`l71_refused_writes_at_the_cap_reload_nothing_…` pins
    /// that); this test still guards the lock hold on that path. The
    /// reload-off-the-lock half is pinned by
    /// `m39_a_prepare_refused_at_the_cap_rebuilds_off_the_lock`.
    ///
    /// Bug-catch (pre-T77): the pre-T69 synchronous body
    /// (`service.recover_failed_commit()` under the guard) and the probe's
    /// worst wait is the whole reload.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn m39_a_mutation_refused_at_the_cap_does_not_hold_the_lock_across_its_reload() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m39-mutation.bean");
        let ledger = near_cap::near_cap_ledger(&path, 64);
        let schema = build_schema_with_service(
            Arc::clone(&ledger),
            TransactionBroadcast::new(),
            p2p::node::PeerRegistry::new(),
            Arc::new(security::signing::NoopSignatureProvider),
            true,
            None,
        );

        let (stop, probe) = near_cap::spawn_read_latency_probe(&ledger);
        let started = std::time::Instant::now();
        let response = schema
            .execute_as_operator(
                r#"mutation { openAccount(name: "Assets:Over", date: "2024-01-01") }"#,
            )
            .await;
        let mutation_took = started.elapsed();
        stop.send(()).unwrap();
        let (worst_read_wait, samples) = probe.await.unwrap();

        let codes: Vec<String> = response
            .errors
            .iter()
            .filter_map(|error| {
                error
                    .extensions
                    .as_ref()
                    .and_then(|ext| ext.get("code"))
                    .map(|code| code.to_string())
            })
            .collect();
        assert!(
            codes
                .iter()
                .any(|code| code.contains("RESOURCE_LIMIT_EXCEEDED")),
            "the write must be refused at the cap, got {:?}",
            response.errors
        );
        eprintln!(
            "m39 mutation: refused + reloaded in {mutation_took:?}; worst read wait \
             {worst_read_wait:?} over {samples} samples"
        );
        assert!(
            worst_read_wait < Duration::from_millis(100),
            "M-39: a reader waited {worst_read_wait:?} during a refused write's reload \
             ({mutation_took:?} total)"
        );
        let service = ledger.read().await;
        assert!(!service.accounts().is_open("Assets:Over"), "rolled back");
        assert_eq!(service.uncommitted_count(), 0);
    }

    // ── T77 / L-71: the mutations' pre-stage headroom check ─────────────

    fn day(day: u32) -> chrono::NaiveDate {
        chrono::NaiveDate::from_ymd_opt(2024, 1, day).unwrap()
    }

    /// `appendTransaction` of a 5 USD lunch with a `narration_len`-byte
    /// narration, dated January `day`.
    fn lunch_mutation(narration_len: usize, day: u32) -> String {
        format!(
            r#"mutation {{ appendTransaction(input: {{ date: "2024-01-{day:02}" flag: "*"
                narration: "{}" postings: [
                    {{ account: "Assets:Cash", amount: {{ number: "-5", currency: "USD" }} }},
                    {{ account: "Expenses:Food", amount: {{ number: "5", currency: "USD" }} }}
                ] }}) {{ txid alreadyExisted }} }}"#,
            "n".repeat(narration_len)
        )
    }

    fn error_codes(response: &async_graphql::Response) -> Vec<String> {
        response
            .errors
            .iter()
            .filter_map(|error| {
                error
                    .extensions
                    .as_ref()
                    .and_then(|ext| ext.get("code"))
                    .map(|code| code.to_string())
            })
            .collect()
    }

    /// L-71 KEY TEST — `x3probe cap 4`, through the real GraphQL mutations.
    /// ~880 bytes below the cap, an API-key holder retries a write whose
    /// record cannot fit (a 2,000-byte narration) four times while an honest
    /// writer keeps taking the single-writer permit. Every attempt is refused
    /// with `RESOURCE_LIMIT_EXCEEDED`, NONE pays an L-13 reload (no
    /// "reload installed" line), the permit is never held long enough to make
    /// the honest writer wait 10 ms, and an honest ~250-byte `openAccount`
    /// then succeeds.
    ///
    /// Before T77 each attempt staged, failed its prepare and reloaded the
    /// 64 MiB ledger with the permit held — 0.5–2.6 s per attempt in the
    /// audit's run, an honest open waiting 814 ms behind four of them.
    ///
    /// Bug-catch: remove the `refuse_if_local_write_cannot_fit` call from
    /// `appendTransaction` — four reload lines, and a permit wait of whole
    /// reloads.
    /// L-80 (T82): on a ledger whose canonical form is over the cap — the
    /// file itself is under it — every write needs a compaction that cannot
    /// be written. Before T82 each mutation was admitted by the pre-stage
    /// check (the append headroom looked fine), staged, failed in
    /// `persist_atomically`, and paid a full reload with the permit held; now
    /// `append_headroom` is 0 and the mutation is refused before staging,
    /// with the cap's error code and no reload.
    #[tokio::test]
    async fn l80_writes_on_an_over_cap_canonical_ledger_are_refused_before_staging() {
        let (guard, raw, _filtered) = crate::anti_entropy_alpn::tests::capture_logs();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("l80.bean");
        let line = format!(";{}\n", "x".repeat((1 << 20) - 2));
        let content = line.repeat(63) + &format!(";{}\n", "x".repeat((1 << 20) - 64));
        assert!(content.len() as u64 <= ledger::service::MAX_LEDGER_FILE_BYTES);
        std::fs::write(&path, content).unwrap();
        let service = LedgerService::boot(&path, "l80".to_owned()).unwrap();
        assert_eq!(service.append_headroom(), 0, "premise: over the cap");
        let ledger: SharedLedger = Arc::new(tokio::sync::RwLock::new(service));
        let schema = build_schema_with_service(
            Arc::clone(&ledger),
            TransactionBroadcast::new(),
            p2p::node::PeerRegistry::new(),
            Arc::new(security::signing::NoopSignatureProvider),
            true,
            None,
        );
        for attempt in 0..3 {
            let response = schema
                .execute_as_operator(format!(
                    r#"mutation {{ openAccount(name: "Assets:A{attempt}", date: "2024-01-05") }}"#
                ))
                .await;
            assert_eq!(
                error_codes(&response),
                vec!["\"RESOURCE_LIMIT_EXCEEDED\"".to_owned()],
                "{:?}",
                response.errors
            );
        }
        drop(guard);
        assert_eq!(
            raw.text().matches("reload installed").count(),
            0,
            "a refused write must not reload:\n{}",
            raw.text()
        );
        assert_eq!(ledger.read().await.directive_count(), 0, "nothing staged");
    }

    /// M-58 (T86, decision (21)): the L-80 test above, in gl-node's real
    /// order on the shape the README names — hand-typed lines whose envelopes
    /// push the canonical form over the cap — and with the startup compaction
    /// run FIRST, as `main.rs` runs it. Before T86 that compaction's refusal
    /// was answered with a reload, the reload (whose operator input the L-81
    /// keep emptied) never measured the fact, and every mutation after it
    /// was admitted, staged, failed in the write and reloaded again (D1's
    /// real-binary run: four reloads, `408`s). Now the compaction is refused
    /// with no reload and every mutation is refused before staging.
    ///
    /// Bug-catch: drop the `prepare_refusal_needs_no_reload` arm from
    /// `prepare_or_recover_with_reload` and the compaction reloads (and, with
    /// the re-measure also gone, the mutations stage and reload).
    #[tokio::test]
    async fn m58_after_the_refused_startup_compaction_writes_are_still_refused_before_staging() {
        let (guard, raw, _filtered) = crate::anti_entropy_alpn::tests::capture_logs();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("m58.bean");
        let cap = ledger::service::MAX_LEDGER_FILE_BYTES as usize;
        let line = format!("; {}\n", "x".repeat((1 << 20) - 3));
        let hand = "2024-01-02 open Assets:HandA USD\n\n2024-01-02 open Assets:HandB USD\n\n\
                    2024-01-02 open Assets:HandC USD\n";
        let used = line.len() * 63 + hand.len() + 1;
        let last = format!("; {}\n", "x".repeat(cap - used - 3 - 60));
        let content = format!("{}{last}{hand}", line.repeat(63));
        assert!(content.len() <= cap);
        std::fs::write(&path, content).unwrap();
        let mut service = LedgerService::boot(&path, "m58".to_owned()).unwrap();
        assert_eq!(service.finalize_operator_input(), 3, "gl-node's order");
        assert_eq!(service.append_headroom(), 0, "premise: over the cap");
        let ledger: SharedLedger = Arc::new(tokio::sync::RwLock::new(service));

        let compacted = compact(&ledger).await;
        assert!(
            matches!(compacted, Err(ServiceError::ResourceLimitExceeded { .. })),
            "{compacted:?}"
        );
        assert_eq!(ledger.read().await.append_headroom(), 0, "the fact holds");

        let schema = build_schema_with_service(
            Arc::clone(&ledger),
            TransactionBroadcast::new(),
            p2p::node::PeerRegistry::new(),
            Arc::new(security::signing::NoopSignatureProvider),
            true,
            None,
        );
        for attempt in 0..3 {
            let response = schema
                .execute_as_operator(format!(
                    r#"mutation {{ openAccount(name: "Assets:A{attempt}", date: "2024-01-05") }}"#
                ))
                .await;
            assert_eq!(
                error_codes(&response),
                vec!["\"RESOURCE_LIMIT_EXCEEDED\"".to_owned()],
                "{:?}",
                response.errors
            );
        }
        drop(guard);
        assert_eq!(
            raw.text().matches("reload installed").count(),
            0,
            "neither the refused compaction nor a refused write reloads:\n{}",
            raw.text()
        );
        assert_eq!(ledger.read().await.directive_count(), 3, "nothing staged");

        // T93 / M-65, decision (43): with a write already staged (a library
        // caller's, or one a refused install kept), the pre-stage refusal used
        // to step aside — every mutation then staged, rebuilt the ledger under
        // the permit and was refused for the cap anyway. Over the cap nothing
        // fits, so it refuses whatever is staged.
        ledger
            .write()
            .await
            .open_account_staged(
                "Assets:Staged".to_owned(),
                chrono::NaiveDate::from_ymd_opt(2024, 1, 5).unwrap(),
                vec![],
                |_, _, _| None,
            )
            .expect("a library stage");
        assert_eq!(ledger.read().await.uncommitted_count(), 1, "premise");
        let response = schema
            .execute_as_operator(
                r#"mutation { openAccount(name: "Assets:AfterStage", date: "2024-01-05") }"#,
            )
            .await;
        assert_eq!(
            error_codes(&response),
            vec!["\"RESOURCE_LIMIT_EXCEEDED\"".to_owned()],
            "{:?}",
            response.errors
        );
        assert_eq!(
            ledger.read().await.uncommitted_count(),
            1,
            "refused before staging"
        );
    }

    #[tokio::test]
    async fn l71_refused_writes_at_the_cap_reload_nothing_and_never_hold_the_permit() {
        let (guard, raw, _filtered) = crate::anti_entropy_alpn::tests::capture_logs();
        let dir = tempfile::tempdir().unwrap();
        let ledger = near_cap::near_cap_ledger(&dir.path().join("l71.bean"), 1200);
        {
            let mut service = ledger.write().await;
            service
                .open_account("Assets:Cash".into(), day(1), vec![])
                .unwrap();
            service
                .open_account("Expenses:Food".into(), day(1), vec![])
                .unwrap();
        }
        let headroom = ledger.read().await.append_headroom();
        let schema = build_schema_with_service(
            Arc::clone(&ledger),
            TransactionBroadcast::new(),
            p2p::node::PeerRegistry::new(),
            Arc::new(security::signing::NoopSignatureProvider),
            true,
            None,
        );

        let done = Arc::new(AtomicBool::new(false));
        let honest = tokio::spawn({
            let ledger = Arc::clone(&ledger);
            let done = Arc::clone(&done);
            async move {
                let mut worst = Duration::ZERO;
                let mut samples = 0usize;
                while !done.load(Ordering::SeqCst) {
                    let started = std::time::Instant::now();
                    let permit = acquire_write_permit(&ledger).await;
                    worst = worst.max(started.elapsed());
                    samples += 1;
                    drop(permit);
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                (worst, samples)
            }
        });
        let mut refusals = Vec::new();
        let started = std::time::Instant::now();
        for attempt in 0..4 {
            let response = schema
                .execute_as_operator(lunch_mutation(2000, 2 + attempt))
                .await;
            refusals.push((error_codes(&response), format!("{:?}", response.errors)));
            tokio::task::yield_now().await;
        }
        let attacker_took = started.elapsed();
        done.store(true, Ordering::SeqCst);
        let (worst_wait, samples) = honest.await.unwrap();
        let opened = schema
            .execute_as_operator(
                r#"mutation { openAccount(name: "Assets:Honest", date: "2024-01-05") }"#,
            )
            .await;
        drop(guard);

        eprintln!(
            "l71: headroom {headroom} B; 4 refused attempts in {attacker_took:?}; worst permit \
             wait {worst_wait:?} over {samples} samples"
        );
        let reloads = raw.text().matches("reload installed").count();
        assert_eq!(
            reloads,
            0,
            "a refused write must not reload:\n{}",
            raw.text()
        );
        assert!(
            worst_wait < Duration::from_millis(10),
            "an honest writer waited {worst_wait:?} for the permit"
        );
        for (codes, errors) in &refusals {
            assert!(
                codes
                    .iter()
                    .any(|code| code.contains("RESOURCE_LIMIT_EXCEEDED")),
                "refused at the cap: {errors}"
            );
            assert!(errors.contains("refused before staging"), "{errors}");
        }
        assert!(opened.errors.is_empty(), "{:?}", opened.errors);
        let service = ledger.read().await;
        assert!(service.accounts().is_open("Assets:Honest"));
        assert_eq!(service.uncommitted_count(), 0);
    }

    /// T77 / L-71: the pre-stage estimate is the record the stage produces —
    /// for a transaction naming several heads, an `open`, and a `close`, each
    /// signed by a real Ed25519 key, the first two a person's (`entered-by`)
    /// — so the check never refuses a write that would fit, and a write it
    /// admits never fails the projection.
    ///
    /// Bug-catch: estimate without the signature (or without the parents, or
    /// without `entered-by`) and the estimate falls short of the staged record.
    #[test]
    fn l71_the_pre_stage_estimate_is_the_staged_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("estimate.bean");
        std::fs::write(&path, "").unwrap();
        let mut service = LedgerService::boot(&path, "a".repeat(64)).unwrap();
        let signer =
            security::signing::PeerKeySignatureProvider::from_bytes(&[7u8; 32], "mesh".to_owned());
        let sign = |is_transaction: bool| {
            let signer = &signer;
            move |id: &str, parents: &str, lamport: &str| {
                signer.sign(&SignableMessage {
                    content_id: id,
                    is_transaction,
                    parents,
                    lamport,
                })
            }
        };
        let record_of = |service: &LedgerService, id: &str| {
            RecordEstimate::new()
                .with(RecordEstimate::directive_bytes(
                    service.get_directive(id).unwrap(),
                ))
                .record_bytes()
        };
        for account in ["Assets:Cash", "Expenses:Food"] {
            service
                .open_account_signing(account.into(), day(1), vec!["USD".into()], sign(false))
                .unwrap();
        }
        // Several heads for the next transaction to name.
        for index in 0..3 {
            let mut input = lunch_input(10 + index, 2);
            input.narration = Some(format!("head {index}"));
            service.append_transaction(input).unwrap();
        }

        let input = lunch_input(300, 3);
        // Step 4: a person's write carries `entered-by`; the estimate counts it.
        let person = Some("u_000000000000000a");
        let predicted = local_write_record_bytes(
            &service,
            LocalWrite::Transaction(&input),
            person,
            Some(&signer),
        )
        .expect("predictable");
        let id = service
            .append_transaction_staged_by(input, person, sign(true))
            .unwrap()
            .txid;
        assert!(
            service
                .get_directive(&id)
                .unwrap()
                .metadata()
                .contains_key("openledger-signature"),
            "the fixture signs"
        );
        assert_eq!(predicted, record_of(&service, &id), "transaction");
        service.persist_or_reload().unwrap();

        // Review I-1: the operator's entry has the bare body's id; a person's
        // identical entry is a different record, which the estimate must
        // build — and the person's own retry is the duplicate it skips.
        let input = lunch_input(40, 6);
        service.append_transaction(input.clone()).unwrap();
        let predicted = local_write_record_bytes(
            &service,
            LocalWrite::Transaction(&input),
            person,
            Some(&signer),
        )
        .expect("a new record, not the operator's");
        let id = service
            .append_transaction_staged_by(input.clone(), person, sign(true))
            .unwrap()
            .txid;
        assert_eq!(predicted, record_of(&service, &id), "beside the operator's");
        assert_eq!(
            local_write_record_bytes(
                &service,
                LocalWrite::Transaction(&input),
                person,
                Some(&signer)
            ),
            None,
            "the person's retry is the duplicate"
        );
        service.persist_or_reload().unwrap();

        let currencies = vec!["USD".to_owned(), "EUR".to_owned()];
        let predicted = local_write_record_bytes(
            &service,
            LocalWrite::Open {
                account: "Assets:Bank",
                date: day(4),
                currencies: &currencies,
            },
            person,
            Some(&signer),
        )
        .expect("predictable");
        let id = service
            .open_account_staged_by(
                "Assets:Bank".into(),
                day(4),
                currencies,
                person,
                sign(false),
            )
            .unwrap();
        assert_eq!(predicted, record_of(&service, &id), "open");
        service.persist_or_reload().unwrap();

        let predicted = local_write_record_bytes(
            &service,
            LocalWrite::Close {
                account: "Assets:Bank",
                date: day(5),
            },
            None,
            Some(&signer),
        )
        .expect("predictable");
        let id = service
            .close_account_staged("Assets:Bank".into(), day(5), sign(false))
            .unwrap();
        assert_eq!(predicted, record_of(&service, &id), "close");
    }

    fn lunch_input(narration_len: usize, on: u32) -> ledger::service::TransactionInput {
        use ledger::model::{Amount, Flag};
        use ledger::service::PostingInput;
        let posting = |account: &str, number: i64| PostingInput {
            account: account.to_owned(),
            amount: Some(Amount {
                number: rust_decimal::Decimal::from(number),
                currency: "USD".to_owned(),
            }),
            cost: None,
            price: None,
        };
        ledger::service::TransactionInput {
            date: day(on),
            flag: Flag::Complete,
            payee: None,
            narration: Some("n".repeat(narration_len)),
            tags: Vec::new(),
            links: Vec::new(),
            postings: vec![posting("Assets:Cash", -5), posting("Expenses:Food", 5)],
        }
    }

    /// A ledger of `total` bytes of leading comments, with Cash and Food open
    /// and compacted — A4's fixture for a canonical form near the cap.
    fn m74_base(path: &std::path::Path, total: usize) -> LedgerService {
        let line = format!("; {}\n", "x".repeat((1 << 20) - 3));
        let last_len = total - line.len() * 63;
        let last = format!("; {}\n", "x".repeat(last_len - 3));
        std::fs::write(path, format!("{}{last}", line.repeat(63))).unwrap();
        let mut service = LedgerService::boot(path, "m74".to_owned()).unwrap();
        service.finalize_operator_input();
        for account in ["Assets:Cash", "Expenses:Food"] {
            service
                .open_account(account.to_owned(), day(1), vec![])
                .unwrap();
        }
        service.compact().unwrap();
        service
    }

    /// `n` hand-typed transactions, as an operator appends them under a
    /// running node.
    fn m74_hand_lines(n: usize) -> String {
        (0..n)
            .map(|index| {
                format!(
                    "\n2024-01-26 * \"Hand\" \"typed while running {index:02}\"\n  \
                     Assets:Cash  -5 USD\n  Expenses:Food  5 USD\n"
                )
            })
            .collect()
    }

    /// T100 / M-74 (audit 0927, A4-1), decision (61): an operator's hand edit
    /// under a running node leaves the ledger's canonical form — with the
    /// envelopes this node gives the typed lines — just over the cap while
    /// the file itself is under it. The first mutation adopts the edit inside
    /// its `prepare` and is refused as a resource limit, with the one reload
    /// that rolls its staged write back; every mutation after it is refused
    /// before staging, in milliseconds, with no further reload, and the
    /// running balance is the balance after a restart. At `a5313a1` the
    /// compaction arm measured nothing unless the over-cap fact was already
    /// set, `persist_atomically` refused the text as an I/O error, the fact was
    /// never set, and every mutation paid a full reload for an `IO_ERROR`.
    ///
    /// Bug-catch: drop the compaction arm's length check and the mutations are
    /// `IO_ERROR`s, each with a reload.
    #[tokio::test]
    async fn m74_a_rewrite_over_the_cap_refuses_every_mutation_before_staging() {
        let (guard, raw, _filtered) = crate::anti_entropy_alpn::tests::capture_logs();
        let dir = tempfile::tempdir().unwrap();
        let cap = ledger::service::MAX_LEDGER_FILE_BYTES as usize;
        let hand = 40;
        let calibration = dir.path().join("calibration.bean");
        let base = cap - 60_000;
        let canonical = {
            let mut svc = m74_base(&calibration, base);
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&calibration)
                .unwrap();
            std::io::Write::write_all(&mut file, m74_hand_lines(hand).as_bytes()).unwrap();
            svc.reconcile_file().unwrap();
            svc.canonical_bytes() as usize
        };
        let path = dir.path().join("m74.bean");
        let service = m74_base(&path, base + (cap - 60 - canonical));
        let ledger: SharedLedger = Arc::new(tokio::sync::RwLock::new(service));
        {
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            std::io::Write::write_all(&mut file, m74_hand_lines(hand).as_bytes()).unwrap();
        }
        assert!(
            std::fs::metadata(&path).unwrap().len() <= cap as u64,
            "premise: the file is under the cap"
        );
        let schema = build_schema_with_service(
            Arc::clone(&ledger),
            TransactionBroadcast::new(),
            p2p::node::PeerRegistry::new(),
            Arc::new(security::signing::NoopSignatureProvider),
            true,
            None,
        );
        let cash = |svc: &LedgerService| {
            svc.read_model()
                .account_balance("Assets:Cash", None)
                .and_then(|entry| entry.balances.get("USD").map(|d| d.to_string()))
        };
        let mut outcomes = Vec::new();
        for attempt in 0..4u32 {
            let response = schema
                .execute_as_operator(lunch_mutation(10, 10 + attempt))
                .await;
            outcomes.push((
                error_codes(&response),
                raw.text().matches("reload installed").count(),
            ));
        }
        let running = cash(&*ledger.read().await);
        drop(guard);
        drop(schema);
        let ledger = Arc::try_unwrap(ledger).ok().unwrap().into_inner();
        drop(ledger);
        let restarted = cash(&LedgerService::boot(&path, "m74".to_owned()).unwrap());
        for (attempt, (codes, _)) in outcomes.iter().enumerate() {
            assert_eq!(
                codes,
                &vec!["\"RESOURCE_LIMIT_EXCEEDED\"".to_owned()],
                "mutation {attempt}: {outcomes:?}"
            );
        }
        assert!(
            outcomes
                .iter()
                .all(|(_, reloads)| *reloads == outcomes[0].1)
                && outcomes[0].1 <= 1,
            "at most the first mutation reloads: {outcomes:?}"
        );
        assert_eq!(
            running, restarted,
            "the running balance is the restarted one"
        );
    }
}
