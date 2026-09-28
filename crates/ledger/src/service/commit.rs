//! The two-phase durable commit (T44): the commit types, the commit gate and
//! headroom, `prepare` / `finish_commit`, and the compaction text.

use super::*;

/// What a [`PendingCommit`] will do to the files (T44).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitKind {
    /// Frame the staged directives as one journal record, append it, fsync.
    /// O(staged bytes) — the canonical `.bean` is not touched at all.
    Append,
    /// Rewrite the canonical `.bean` from memory (temp + fsync + rename) and
    /// delete the journal. O(ledger).
    Compact,
}

/// Observer invoked at the head of [`PendingCommit::commit`], on the blocking
/// thread, before any I/O — **a test seam**.
///
/// Production never installs one: `set_commit_observer` is called from tests
/// only, and the commit path pays a single `Option` check. Tests use it two
/// ways: to record the bytes each commit actually writes (the O(1) proof), and
/// to stall a commit in flight so a concurrent GraphQL read can be shown to
/// complete anyway (the reads-not-blocked proof).
pub type CommitObserver = std::sync::Arc<dyn Fn(CommitKind, u64) + Send + Sync>;

// ─── Two-phase durable commit (T44) ──────────────────────────────────────────

/// The `commit_in_flight` value meaning "no commit is outstanding" (H-11).
///
/// Zero is never a real commit generation: [`LedgerService::prepare`]
/// increments the counter *before* it stamps the flag, so the first commit of a
/// process is generation 1 and the sentinel can never collide with one.
pub(super) const IDLE_COMMIT_GENERATION: u64 = 0;

/// How many missing ids a refused L-13 rebuild names in its log line (M-46).
/// The count is always logged; the sample is for the operator to grep for.
pub(super) const RECOVERY_MISSING_SAMPLE: usize = 8;

/// The RAII owner of [`LedgerService`]'s in-flight flag (H-11).
///
/// # The bug this closes
///
/// The flag used to be a plain `bool`, set synchronously inside `prepare` and
/// cleared only by [`LedgerService::finish_commit`] or
/// [`LedgerService::recover_failed_commit`] — both of which the node layer
/// reaches only **after an `await`**, and neither of which had a `Drop` guard
/// behind it. Anything that dropped the caller's future inside that window left
/// the flag `true` with nothing alive to clear it, and there were three
/// unexotic ways to do exactly that: the node's own request `TimeoutLayer`
/// (which answers 408 and drops the inner service future — legal down to a
/// one-second budget), an HTTP/2 `RST_STREAM` on the cleartext h2c port, and a
/// panic anywhere on the path.
///
/// The `spawn_blocking` half is **not** cancelled by any of those, so the bytes
/// still landed on disk; only the bookkeeping was lost. Every later `prepare`
/// then returned [`ServiceError::CommitInFlight`] **for the life of the
/// process** — the three GraphQL mutations, the ALPN supply batch (so peer
/// replication silently stopped being persisted), the file-watcher reconcile
/// and the shutdown compaction, all dead at once, while reads and `/health`
/// stayed green and reported nothing.
///
/// # The invariant it establishes
///
/// The flag is an `AtomicU64` behind an `Arc`, and **constructing this guard is
/// the only thing that sets it**. The guard is a private field of
/// [`PendingCommit`] — the one and only handle to an outstanding commit, and
/// the one and only thing `prepare` hands back — so *every* way out of a
/// `prepare` that set the flag drops the guard:
///
/// * the commit runs: [`PendingCommit::commit`] takes `self`, so the guard is
///   dropped as it returns, on whatever thread performed the write;
/// * the commit never runs: the `PendingCommit` is dropped by a cancelled
///   future, an early return added later, or a test that simply forgets it;
/// * the commit panics: the guard is dropped by the unwind.
///
/// There is no path that can leave `prepare` having set the flag and then fail
/// to clear it, short of `mem::forget`. That is deliberately a property of the
/// *type* rather than of the caller's discipline, which is the same move
/// [`PendingCommit`] already makes for "the commit cannot race the ledger".
///
/// # Why a generation-stamped compare-exchange rather than a plain store
///
/// The guard releases the flag only if the flag still names *its* commit. A
/// guard dropped late therefore cannot clear a flag belonging to a later
/// commit. That ordering cannot arise while callers honour the single-writer
/// gate — which is precisely why it is worth enforcing here, since this guard's
/// whole job is to survive the caller that does not.
pub(super) struct CommitInFlightGuard {
    pub(super) slot: std::sync::Arc<std::sync::atomic::AtomicU64>,
    pub(super) generation: u64,
}

impl CommitInFlightGuard {
    /// Claim `slot` for `generation`.
    ///
    /// Called from [`LedgerService::prepare`] only, immediately after the
    /// refusal check, so that setting the flag and creating its owner are one
    /// step with nothing between them that could return early.
    pub(super) fn arm(
        slot: &std::sync::Arc<std::sync::atomic::AtomicU64>,
        generation: u64,
    ) -> Self {
        slot.store(generation, std::sync::atomic::Ordering::Release);
        CommitInFlightGuard {
            slot: std::sync::Arc::clone(slot),
            generation,
        }
    }
}

impl Drop for CommitInFlightGuard {
    fn drop(&mut self) {
        // A failed exchange is the normal case, not an error: `finish_commit`
        // or `recover_failed_commit` has already released the flag on the happy
        // paths. Either way this guard has nothing left to release.
        let _ = self.slot.compare_exchange(
            self.generation,
            IDLE_COMMIT_GENERATION,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Relaxed,
        );
    }
}

/// A durable write that has been *prepared* in memory and not yet performed.
///
/// # Why persistence is split in two
///
/// Before T44 a mutation serialized, wrote and fsynced the whole `.bean` while
/// holding the ledger write lock, on a tokio worker thread. A slow fsync
/// therefore blocked every GraphQL **read** behind the `RwLock` and parked a
/// runtime worker for the duration. Splitting the write gives the node layer
/// the shape it needs:
///
/// ```text
/// write lock { mutate; prepare_commit() }   // in-memory + serialize, cheap
/// drop(lock)
/// spawn_blocking { pending.commit() }       // the write + the fsync
/// write lock { finish_commit(receipt) }     // bookkeeping
///        └── on failure: recover_failed_commit()   (L-13)
/// ```
///
/// [`PendingCommit`] owns everything the I/O needs — paths and bytes, no
/// borrow of the service — so it is `Send + 'static` and can be moved into
/// `spawn_blocking`. It deliberately holds **no** handle back to the
/// `LedgerService`: the only way a commit can affect in-memory state is through
/// the [`CommitReceipt`] the caller feeds to `finish_commit`, which is what
/// makes "the commit cannot race the ledger" a property of the types rather
/// than of the caller's discipline.
///
/// Synchronous callers (the ledger's own tests, `reconcile_file`, any library
/// user that does not care) never see this: [`LedgerService::persist_or_reload`]
/// and [`LedgerService::compact`] still do prepare + commit + finish in one
/// call, inline, exactly as before.
pub struct PendingCommit {
    pub(super) generation: u64,
    pub(super) kind: CommitKind,
    pub(super) ledger_path: PathBuf,
    pub(super) journal_path: PathBuf,
    /// [`CommitKind::Compact`] only: the full canonical file text.
    pub(super) canonical: String,
    /// [`CommitKind::Append`] only: the framed journal record.
    pub(super) record: String,
    /// [`CommitKind::Compact`] only: rename the journal to a `.torn-*`
    /// sidecar instead of deleting it, because the boot that loaded it dropped
    /// a torn tail (M-43), or a later L-13 reload saw one or failed (M-49).
    pub(super) retire_torn_journal: bool,
    pub(super) observer: Option<CommitObserver>,
    /// Releases the service's in-flight flag however this value ends its life
    /// (H-11). Never read; the whole point is the `Drop`. See
    /// [`CommitInFlightGuard`] for why it lives *here* rather than beside the
    /// flag it owns: this is the value that a cancelled, early-returning or
    /// panicking caller drops.
    #[allow(dead_code)]
    pub(super) in_flight: CommitInFlightGuard,
}

impl std::fmt::Debug for PendingCommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the ledger contents.
        f.debug_struct("PendingCommit")
            .field("generation", &self.generation)
            .field("kind", &self.kind)
            .field("bytes_to_write", &self.bytes_to_write())
            .finish()
    }
}

impl PendingCommit {
    /// Whether this commit appends a journal record or rewrites the `.bean`.
    pub fn kind(&self) -> CommitKind {
        self.kind
    }

    /// Bytes this commit will write. `O(directive)` for an append; `O(ledger)`
    /// for a compaction — which is the whole difference T44 buys, made
    /// observable without a test seam.
    pub fn bytes_to_write(&self) -> u64 {
        match self.kind {
            CommitKind::Append => self.record.len() as u64,
            CommitKind::Compact => self.canonical.len() as u64,
        }
    }

    /// Perform the write and the fsync. **Blocking** — call it from
    /// `spawn_blocking` (or from a synchronous context), never on a runtime
    /// worker thread while a lock is held.
    ///
    /// A compaction writes the canonical file first and only then deletes the
    /// journal. A crash in between leaves both on disk, holding overlapping
    /// directives — which boot unions and the DAG's G-Set dedups by content id,
    /// so the crash window is safe by construction rather than by recovery
    /// logic. The reverse order would have a window in which neither file holds
    /// the directives.
    pub fn commit(self) -> Result<CommitReceipt, ServiceError> {
        if let Some(ref observe) = self.observer {
            observe(self.kind, self.bytes_to_write());
        }
        match self.kind {
            CommitKind::Compact => {
                persist_atomically(&self.ledger_path, &self.canonical)?;
                if self.retire_torn_journal {
                    // M-43: the records boot could read are now in the
                    // `.bean`; the bytes it dropped as torn are kept.
                    if let Some(sidecar) = crate::journal::retire_torn_journal(&self.journal_path)?
                    {
                        warn!(
                            journal = %self.journal_path.display(),
                            sidecar = %sidecar.display(),
                            "ledger commit journal folded into the .bean and kept as a \
                             sidecar, not deleted, because a boot or an L-13 reload found its \
                             tail torn or could not read it; no boot reads the sidecar — \
                             inspect it, then remove it (M-43, M-49)"
                        );
                    }
                } else {
                    crate::journal::remove_journal(&self.journal_path)?;
                }
                Ok(CommitReceipt {
                    generation: self.generation,
                    kind: self.kind,
                    bytes_written: self.canonical.len() as u64,
                    // Hashing the canonical text is O(ledger); doing it here
                    // keeps it off the write lock with the rest of the cost.
                    canonical_hash: Some(file_content_hash(&self.canonical)),
                    canonical_bytes: Some(self.canonical.len() as u64),
                    canonical_marker: FileMarker::of(&self.ledger_path),
                    journal_bytes: 0,
                })
            }
            CommitKind::Append => {
                let (journal_bytes, _created) =
                    crate::journal::append_record(&self.journal_path, &self.record)?;
                Ok(CommitReceipt {
                    generation: self.generation,
                    kind: self.kind,
                    bytes_written: self.record.len() as u64,
                    // The canonical file was not touched, so nothing about it
                    // changes: no new hash, no new size, no new marker.
                    canonical_hash: None,
                    canonical_bytes: None,
                    canonical_marker: None,
                    journal_bytes,
                })
            }
        }
    }
}

/// What a completed [`PendingCommit`] tells the service about the files.
///
/// The only channel from the off-lock commit back into in-memory state; it
/// carries a generation so [`LedgerService::finish_commit`] can refuse a
/// receipt that does not belong to the commit it is waiting for.
#[derive(Debug, Clone)]
pub struct CommitReceipt {
    pub(super) generation: u64,
    pub(super) kind: CommitKind,
    pub(super) bytes_written: u64,
    pub(super) canonical_hash: Option<String>,
    pub(super) canonical_bytes: Option<u64>,
    pub(super) canonical_marker: Option<FileMarker>,
    pub(super) journal_bytes: u64,
}

impl CommitReceipt {
    /// Whether the commit appended to the journal or rewrote the `.bean`.
    pub fn kind(&self) -> CommitKind {
        self.kind
    }

    /// Bytes actually written by this commit.
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

/// An L-13 reload-from-disk, captured under the ledger lock so that the
/// expensive part can run off it (L-43).
///
/// # The bug this closes
///
/// T44 moved the commit's write and fsync off the write lock and off the
/// runtime. Its failure path did not follow: `recover_failed_commit` rebuilt
/// the whole service with [`LedgerService::boot`] — up to a 64 MiB read, a
/// parse, a DAG insert per directive and a `ReadModel::build` — synchronously,
/// on a runtime worker, **with the write guard held**. So every failed commit
/// (ENOSPC, EIO, a read-only remount) re-introduced exactly the full-ledger
/// stall of every GraphQL read that T44 exists to remove, once per failure.
///
/// # The shape
///
/// ```text
/// permit held throughout
/// read lock  { reload = svc.begin_recovery() }       // O(1)
/// spawn_blocking { reloaded = reload.load() }         // the boot; no lock
/// write lock { svc.finish_recovery(reload, reloaded) } // the swap
/// ```
///
/// Everything the load needs is owned here (a path and an author id), so it is
/// `Send + 'static` and holds no borrow of the service — the same property
/// [`PendingCommit`] relies on for the commit itself.
///
/// # Why the permit, not the lock, is what keeps it correct
///
/// A rebuild is only a faithful "memory := disk" if the files do not change
/// between the read and the swap, and if nothing the swap would discard was
/// added to memory in the meantime. The single-writer permit guarantees both:
/// every write path in `gl-node` holds it across stage → prepare → commit →
/// finish, and the recovery runs inside that same span. Readers are not
/// excluded and need not be: during the rebuild they see the pre-recovery
/// memory, which is what they could already see for the whole duration of the
/// commit that failed.
///
/// The fingerprint is the belt to that pair of braces: a caller that mutates
/// the service without the permit moves at least one of its fields, and
/// [`LedgerService::finish_recovery`] then discards the stale rebuild and
/// reloads synchronously instead of installing it.
#[derive(Debug, Clone)]
pub struct RecoveryReload {
    pub(super) file_path: PathBuf,
    pub(super) author_id: String,
    pub(super) fingerprint: RecoveryFingerprint,
}

impl RecoveryReload {
    /// Rebuild a service from the files on disk. **Blocking** — the whole
    /// point of the type is that this runs on a blocking thread with no ledger
    /// lock held (L-43).
    ///
    /// H-15: a rebuild is a *reload*, and a reload never creates the `.bean`.
    /// The service being recovered had a file; if it is gone now, rebuilding
    /// an empty ledger and installing it over memory is exactly the loss this
    /// mode exists to refuse — see [`BootMode::Reload`].
    pub fn load(&self) -> Result<LedgerService, ServiceError> {
        LedgerService::boot_with(
            self.file_path.clone(),
            self.author_id.clone(),
            BootMode::Reload,
        )
    }
}

/// Why [`LedgerService::boot_with`] is being asked to read the files (H-15).
///
/// The one thing the mode changes is what an **absent** `.bean` means:
///
/// * [`Self::Fresh`] — a process start. No file and no journal is a new ledger
///   and the file is created (§3.3). No file but a journal beside it is not:
///   a journal only ever exists next to a `.bean` past the compaction
///   threshold, so this shape is a ledger whose `.bean` was removed or renamed
///   out from under it, and starting an empty ledger there would fold the
///   journal's records into a file holding nothing else. Refused, naming both
///   files.
/// * [`Self::Reload`] — an L-13 recovery of a service that already holds the
///   ledger in memory. An absent file is refused outright: before this mode
///   existed, `mv ledger.bean ledger.bak` under a running node made the next
///   failed commit's reload *create an empty file* and install it over the
///   complete in-memory DAG, with nothing logged on the way.
///
/// The `.lock` sidecar is deliberately NOT a signal. `gl-node` takes it before
/// `boot` runs (M-17), so from the node's point of view "the lock exists" is
/// true on every first boot of a brand-new ledger and discriminates nothing;
/// a library caller takes no lock at all. The journal and the mode are the two
/// facts boot can actually stand on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BootMode {
    /// A process start: an absent `.bean` with no journal beside it is created.
    Fresh,
    /// An L-13 rebuild of a live service: an absent `.bean` is an error.
    Reload,
}

/// The service state an L-13 rebuild would discard, reduced to counters
/// (L-43).
///
/// A tripwire, not the guarantee — the permit is the guarantee. Every kind of
/// write moves at least one of these: a local write bumps the Lamport clock and
/// stages a pending id; a peer ingest adds a directive; any prepare, and so any
/// commit, bumps the generation; a reconcile adopts directives or moves the
/// counter or the quarantine. The DAG is grow-only between reloads, so counts
/// suffice and no content comparison is needed. (The one write it can miss is
/// a second `stamp_signature` on an already-forced service, which changes a
/// directive's metadata and nothing countable — and which, like everything
/// else, is only reachable here by a caller ignoring the permit.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct RecoveryFingerprint {
    pub(super) commit_generation: u64,
    pub(super) lamport_clock: u64,
    pub(super) directive_count: usize,
    pub(super) pending: usize,
    pub(super) quarantined: usize,
    pub(super) quarantined_text: usize,
    pub(super) external_reconcile_count: u64,
    pub(super) force_compaction: bool,
    /// H-13: a `finalize_operator_input` drains this without touching any
    /// other counter, so it needs its own entry.
    pub(super) unsigned_operator_input: usize,
    /// M-46: a reconcile adds here, not to `pending`.
    pub(super) adopted_from_file: usize,
}

impl LedgerService {
    // ── Persistence (T44: two-phase, append-only) ────────────────────────

    /// The process-wide single-writer gate for this ledger (T44 invariant 7).
    ///
    /// # What it protects
    ///
    /// Commits now happen **outside** the ledger write lock, so without a gate
    /// two writers could prepare in one order and commit in another. Appends
    /// alone would survive that (journal order is arrival order and boot sorts
    /// the union), but a compaction would not: it writes a snapshot taken at
    /// *its* prepare and then deletes the journal, so a concurrent append that
    /// landed in between would be erased from disk after its caller had already
    /// been told the write was durable. That is a durability bug, not a
    /// performance one.
    ///
    /// # The contract
    ///
    /// An async caller takes this mutex **before** the ledger write lock and
    /// holds it until the commit is finished or recovered:
    ///
    /// ```text
    /// let gate = ledger.read().await.commit_gate();   // guard dropped here
    /// let _permit = gate.lock().await;                // single writer from now on
    /// let pending = { ledger.write().await; mutate; prepare_commit() };
    /// let receipt = spawn_blocking(|| pending.commit()).await?;
    /// ledger.write().await.finish_commit(receipt);
    /// ```
    ///
    /// The ordering is one-way — permit, then write lock, never the reverse —
    /// so the two locks cannot deadlock. Readers take neither, which is the
    /// entire point: a stalled fsync now delays the next writer and nothing
    /// else.
    ///
    /// [`Self::prepare_commit`] refuses while a commit is in flight, so a
    /// caller that skips the gate gets [`ServiceError::CommitInFlight`] rather
    /// than an interleaved write. The gate makes that refusal unreachable; it
    /// is the belt to the gate's braces, not the mechanism.
    ///
    /// Since H-11 that refusal means what it says. The flag can no longer be
    /// *left* set by a cancelled or panicking caller — [`CommitInFlightGuard`]
    /// releases it on every such path — so `CommitInFlight` now carries exactly
    /// one diagnosis: someone prepared a commit without holding this gate.
    ///
    /// The gate survives an L-13 reload (see [`Self::recover_failed_commit`]):
    /// replacing it would hand the next writer a *different* mutex and silently
    /// undo the serialization for as long as the old permit was held.
    pub fn commit_gate(&self) -> std::sync::Arc<tokio::sync::Mutex<()>> {
        std::sync::Arc::clone(&self.commit_gate)
    }

    /// Install the commit observer. **Test seam** — see [`CommitObserver`].
    pub fn set_commit_observer(&mut self, observer: CommitObserver) {
        self.commit_observer = Some(observer);
    }

    /// Bytes currently held in the commit journal on disk (T44).
    ///
    /// `0` on any ledger small enough that every commit compacts — which is
    /// what makes this a usable signal that the append-only path is in play.
    pub fn journal_bytes(&self) -> u64 {
        self.canonical_journal_bytes
    }

    /// Byte length of the canonical `.bean` as this service last wrote or read
    /// it (T44).
    pub fn canonical_bytes(&self) -> u64 {
        self.canonical_bytes
    }

    /// How many more bytes of journal record a commit may add before
    /// `prepare`'s cap projection refuses it (M-39, T69).
    ///
    /// `MAX_LEDGER_FILE_BYTES − canonical − journal`, saturating at zero: the
    /// exact left-hand side of the append arm's refusal, so a batch whose
    /// record is larger than this is **known** to fail its prepare. A caller
    /// that can estimate a batch before staging it (anti-entropy, which holds
    /// the `Supply` entries) asks here first and defers the batch instead of
    /// staging it, failing the prepare, and paying an L-13 reload to roll it
    /// back — which near the cap it would otherwise do once per tick per peer,
    /// forever.
    ///
    /// Conservative in both of the ways that matter. The compaction arm is
    /// bounded by the same number (the compacted file is at most canonical +
    /// journal + the staged bytes, and `persist_atomically` refuses past the
    /// cap). `canonical_bytes` is what this service last wrote or read, so a
    /// hand edit since then is not reflected: one that shrank the file only
    /// makes this pessimistic, and one that grew it is still refused by the
    /// prepare that adopts it — it is just not predicted here. O(1): two field
    /// reads.
    pub fn append_headroom(&self) -> u64 {
        // T82 / L-80: over the cap, no write fits — each needs a compaction
        // that cannot be written. 0 makes every pre-stage check refuse.
        if self.canonical_over_cap {
            return 0;
        }
        MAX_LEDGER_FILE_BYTES
            .saturating_sub(self.canonical_bytes)
            .saturating_sub(self.canonical_journal_bytes)
    }

    /// The bytes a write can add before the next commit passes the file cap
    /// (T100 / M-74, decision (61)): [`Self::append_headroom`], except while
    /// the next commit will be a full rewrite — a line adopted from the file
    /// awaiting its canonical spelling, a forced compaction, a file changed
    /// under the node — when it is the cap minus the length of the rewrite
    /// memory would write now (envelopes of the adopted lines and staged
    /// writes included). `append_headroom` reads the file's size, which the
    /// rewrite can exceed: `gl-node`'s pre-stage gate let such a write
    /// through, the compaction's text was over the cap, and each mutation and
    /// each peer batch paid a full reload for an `IO_ERROR`. O(1) unless a
    /// rewrite is pending; then one pass over the ledger, which the rewrite
    /// that follows pays anyway.
    pub fn write_headroom(&self) -> u64 {
        let append = self.append_headroom();
        let rewrites = self.force_compaction
            || !self.canonical_is_current
            || !self.adopted_from_file.is_empty();
        if append == 0 || !rewrites {
            return append;
        }
        MAX_LEDGER_FILE_BYTES.saturating_sub(self.compaction_text_len())
    }

    /// The commit journal's path (`<ledger>.bean.journal`).
    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    /// How many directives this node STAGED — its own writes and peer
    /// arrivals — that no commit has written to either file yet.
    ///
    /// Non-zero only between a staged mutation and its commit. Directives
    /// adopted from the `.bean` (boot's operator input, a live reconcile) are
    /// not counted: the file already holds them, in the operator's spelling,
    /// and the compaction that re-spells them canonically is reported by
    /// [`Self::compaction_pending`] instead (M-46). So this is 0 right after
    /// any boot, operator input or not.
    /// Whether a `prepare` refusal leaves nothing an L-13 reload could repair
    /// (T86 / M-58, decision (21)), beyond the two arms every caller already
    /// exempts (`CommitInFlight`, `Parse`).
    ///
    /// `prepare`'s compaction arm refuses with `ResourceLimitExceeded` while
    /// the canonical form is over the file cap (L-80). Nothing was written;
    /// what the refusal's adopt-before-persist took in came from the file, so
    /// memory is exactly what a rebuild would derive. Before T86 both commit
    /// drivers answered it with a full reload anyway — one per startup,
    /// shutdown and watcher compaction — and that reload, on a file with hand
    /// lines, lost the over-cap fact itself, so every write after it staged,
    /// failed and reloaded again. When records ARE staged the reload still
    /// runs: it is what rolls them back, and it re-measures the fact.
    pub fn prepare_refusal_needs_no_reload(&self, error: &ServiceError) -> bool {
        matches!(error, ServiceError::ResourceLimitExceeded { .. })
            && self.canonical_over_cap
            && self.pending_ids.is_empty()
    }

    pub fn uncommitted_count(&self) -> usize {
        self.pending_ids.len()
    }

    /// Prepare the durable write for everything staged since the last commit.
    ///
    /// Returns `None` when there is genuinely nothing to do: nothing staged, no
    /// forced compaction outstanding, and the canonical file on disk is exactly
    /// what this service last wrote. (Before T44 a no-op persist rewrote the
    /// file with identical bytes; skipping that is the only behavioural
    /// difference, and it is invisible to anything that reads the file.)
    ///
    /// # Which commit it prepares
    ///
    /// An **append** — one framed journal record, `O(staged)` — unless one of
    /// these forces a **compaction**:
    ///
    /// * the canonical file is below [`COMPACTION_MIN_CANONICAL_BYTES`], where
    ///   the rewrite is cheaper than the sidecar it would avoid;
    /// * the journal would reach half the canonical file's size, the
    ///   ratio-triggered fold-back that keeps the amortised cost constant;
    /// * something changed the `.bean` underneath us (the `stat` probe), so
    ///   T35's adopt-before-overwrite has to run;
    /// * the canonical file has not been written by this service yet, so it may
    ///   not be in canonical form at all (see `canonical_is_current`);
    /// * a forced compaction is outstanding — an in-place signature stamp, a
    ///   reconcile that must delete refused entries, or a torn journal tail.
    ///
    /// # Single-writer contract
    ///
    /// Exactly one commit may be outstanding per service. A second prepare
    /// before the first is finished or recovered returns
    /// [`ServiceError::CommitInFlight`] — see [`Self::commit_gate`] for how the
    /// node layer makes that unreachable.
    ///
    /// "Outstanding" is owned by the returned [`PendingCommit`] rather than by
    /// the caller's discipline (H-11): the flag is set by arming a
    /// [`CommitInFlightGuard`] that rides inside it, so dropping the
    /// `PendingCommit` — by cancelling the future that holds it, by returning
    /// early, or by unwinding through a panic — releases the flag. Before H-11
    /// the two clears both lived after an `await` in the node layer, and a
    /// request timeout or an `RST_STREAM` in that window wedged every write
    /// path in the process permanently.
    pub fn prepare_commit(&mut self) -> Result<Option<PendingCommit>, ServiceError> {
        self.prepare(false)
    }

    /// Prepare a full canonical rewrite, whatever the threshold says (T44).
    ///
    /// Used at the deliberate compaction points — process start, process stop,
    /// and after a reconcile — and by [`Self::compact`]. Always returns
    /// `Some`: a compaction asked for explicitly is never optimised away, since
    /// its caller wants the journal gone, not merely the state durable.
    pub fn prepare_compaction(&mut self) -> Result<Option<PendingCommit>, ServiceError> {
        self.prepare(true)
    }

    pub(super) fn prepare(
        &mut self,
        explicit_compaction: bool,
    ) -> Result<Option<PendingCommit>, ServiceError> {
        if self
            .commit_in_flight
            .load(std::sync::atomic::Ordering::Acquire)
            != IDLE_COMMIT_GENERATION
        {
            // Unreachable in this workspace since H-11: the flag is released by
            // a `Drop` that cancellation, an early return and a panic all run,
            // and the node layer holds `commit_gate` from before this call
            // until the commit is finished, so a second writer waits on the
            // gate instead of arriving here. Reaching it therefore means a
            // caller wrote without the permit — a real double-commit, which is
            // exactly what this refusal is for, and worth a log line because it
            // is no longer something a dropped future can fake.
            error!(
                "refusing to prepare a ledger commit while another is in flight; the \
                 single-writer contract on LedgerService::commit_gate was violated"
            );
            return Err(ServiceError::CommitInFlight);
        }

        // The O(1) hand-edit probe. It runs on every prepare, including the
        // append path — an append does not rewrite the `.bean` and so cannot
        // erase an edit, but noticing early means the edit is adopted at the
        // next write instead of waiting for the next compaction.
        let file_changed = self.canonical_file_changed_on_disk();
        // M-46: file-adopted ids are not in `pending_ids`, so they cannot
        // reach disk through an append record — and an append could not
        // re-spell a raw line anyway. Every adoption path also arms
        // `force_compaction` or clears `canonical_is_current`; this term makes
        // "adopted ⇒ the next commit rewrites" hold by construction.
        let must_rewrite = explicit_compaction
            || self.force_compaction
            || file_changed
            || !self.canonical_is_current
            || !self.adopted_from_file.is_empty();

        if self.pending_ids.is_empty() && !must_rewrite {
            return Ok(None);
        }

        // Only the ratio arm needs the staged bytes, and it is the only arm
        // that does not already know it is compacting — so a small ledger (the
        // pre-T44 shape) pays nothing at all for the journal machinery.
        let mut compact = must_rewrite || self.canonical_bytes < COMPACTION_MIN_CANONICAL_BYTES;
        let mut record = String::new();
        if !compact {
            record = crate::journal::record_bytes(&self.pending_block());
            compact = (self.canonical_journal_bytes + record.len() as u64)
                .saturating_mul(COMPACTION_JOURNAL_RATIO)
                >= self.canonical_bytes;
        }

        let (kind, canonical, record) = if compact {
            // H-13: operator input boot adopted must carry its final envelope
            // before the rewrite that puts it on disk canonically. `gl-node`
            // has already done this by the time it compacts; this is the
            // library caller's path, where a service with no signer installed
            // writes the entries unsigned — as a reconcile without a signer
            // always has. A no-op once the set is drained.
            self.finalize_operator_input();
            // L-30 / L-12: this is the write that would erase a hand edit, so
            // this is where the exact check belongs — re-read, re-hash, and
            // reconcile the edit in before serializing over it.
            //
            // M-19: unconditional, and deliberately not configurable. See
            // `adopt_external_edits` for the argument; the short version is
            // that this call is reachable only from the write that is about to
            // overwrite the operator's bytes, so there is no "off" that means
            // "ignore the edit" — only one that means "destroy it silently".
            // `gl-node` used to advertise `externalFileEdits: "disabled"` as
            // that switch; the setting is gone (it never reached this line).
            self.adopt_external_edits()?;
            // H-08: DAG ∪ quarantine, not the DAG alone. This is the single
            // production write that replaces the whole `.bean`, so it is the
            // single place where "boot skipped it" could turn into "it is gone".
            // L-45 adds the third term — the blocks that never parsed.
            let text = self.compaction_text();
            // T82 / L-80, T100 / M-74 (decision (61)): refuse a text the write
            // would refuse anyway — as a resource limit, so `gl-node` backs
            // the peer off and reports the cap, instead of an I/O error and a
            // reload — and keep the fact current either way. Before T100 this
            // was measured only while the fact was already set, and a rewrite
            // whose adopted envelopes pushed it over the cap reached
            // `persist_atomically`, which refused it as `InvalidData`.
            let length = text.len() as u64;
            self.canonical_over_cap = length > MAX_LEDGER_FILE_BYTES;
            if self.canonical_over_cap {
                return Err(ServiceError::ResourceLimitExceeded {
                    message: format!(
                        "the canonical form of this ledger is {length} bytes, over the file cap \
                         of {MAX_LEDGER_FILE_BYTES}: every write fails until the file is made \
                         smaller (L-64, L-80)"
                    ),
                });
            }
            (CommitKind::Compact, text, String::new())
        } else {
            // T27's "reject an over-cap write BEFORE any state changes" applies
            // to the append path too, and has to be re-derived here because the
            // file the cap bounds is not the one being written. The compacted
            // file is at most canonical + journal + this record (the journal's
            // record headers are counted, so the bound is conservative), and
            // that is what must stay under `MAX_LEDGER_FILE_BYTES`.
            let projected = self
                .canonical_bytes
                .saturating_add(self.canonical_journal_bytes)
                .saturating_add(record.len() as u64);
            if projected > MAX_LEDGER_FILE_BYTES {
                return Err(ServiceError::ResourceLimitExceeded {
                    message: format!(
                        "ledger plus journal would reach {projected} bytes (max {MAX_LEDGER_FILE_BYTES})"
                    ),
                });
            }
            (CommitKind::Append, String::new(), record)
        };

        self.commit_generation = self.commit_generation.saturating_add(1);
        // H-11: the flag is SET by arming the guard and released by dropping
        // it, and the guard ships inside the `PendingCommit` below. From here
        // on there is no way to return without one or the other happening.
        let in_flight = CommitInFlightGuard::arm(&self.commit_in_flight, self.commit_generation);
        Ok(Some(PendingCommit {
            generation: self.commit_generation,
            kind,
            ledger_path: self.file_path.clone(),
            journal_path: self.journal_path.clone(),
            retire_torn_journal: kind == CommitKind::Compact && self.journal_torn_at_boot,
            canonical,
            record,
            observer: self.commit_observer.clone(),
            in_flight,
        }))
    }

    /// Everything a full rewrite of the `.bean` must contain (H-08).
    ///
    /// The DAG's directives — the ledger proper — **plus** every quarantined
    /// record the DAG has not since acquired. Without the second half a
    /// compaction is a destructive operation on any file boot could not fully
    /// load: it serializes what is in memory over what is on disk, and what
    /// boot refused was never in memory. See [`Self::quarantined`].
    ///
    /// The `dag.get` filter is what makes the set a union rather than a
    /// concatenation. A quarantined id can legitimately turn up in the DAG
    /// later — anti-entropy supplying the same economic body with sane
    /// parents, or a reconcile adopting the operator's repair, both of which
    /// keep the content id because the envelope is outside the hash. Writing
    /// both copies would put one content id on two different lines of the file,
    /// which the next boot would silently collapse back to one (the G-Set
    /// dedups) but which no other part of this crate expects to see.
    ///
    /// `O(quarantine)` on top of the rewrite it feeds, and the quarantine is
    /// empty on every well-formed ledger, so a normal compaction pays one
    /// `is_empty` check.
    /// The exact text a full rewrite of the `.bean` must contain (H-08, L-45).
    ///
    /// `full_file_serialize(DAG ∪ quarantine)` — the canonical ledger — with
    /// the raw text of every block boot could not parse spliced onto the tail.
    ///
    /// The tail is verbatim and unsorted, which is the only thing it can be:
    /// this node cannot read those blocks, so it cannot order them by date,
    /// cannot canonicalise them, and must not rewrite them. It is appended
    /// rather than interleaved so that the canonical region above it is
    /// byte-for-byte what `full_file_serialize` would produce on its own —
    /// every existing determinism assertion (T27's batch-vs-per-entry,
    /// T29's byte-identical convergence) is therefore untouched on every file
    /// that has no unparsable blocks, and on a file that does, they compare
    /// regions this node did not author anyway.
    ///
    /// Blank-line separated like every other directive in the file, so the next
    /// boot's [`split_ledger_blocks`] sees exactly the blocks this one did and
    /// the set is a fixed point across restarts.
    ///
    /// Empty quarantines on both halves — the normal case — make this literally
    /// `full_file_serialize(dag.directives(), leading_comments)`.
    pub(super) fn compaction_text(&self) -> String {
        let directives = self.compaction_directives();
        let mut text = full_file_serialize(&directives, &self.leading_comments);
        for block in &self.quarantined_text {
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(block);
            if !text.ends_with('\n') {
                text.push('\n');
            }
        }
        text
    }

    /// `self.compaction_text().len()`, without building the text (L-64, T78).
    ///
    /// The canonical file is the leading comments (`; <comment>\n` each), the
    /// directives each serialised exactly as `full_file_serialize` spells one
    /// — a directive's text does not depend on its neighbours or its position
    /// — joined by one blank-line `\n` (also before the first one when there
    /// are comments), then the quarantined text blocks as
    /// [`Self::compaction_text`] appends them. The sum is order-free, so the
    /// canonical sort and the clone of every directive are skipped.
    /// `t78_compaction_text_len_is_the_length_of_compaction_text` pins it to
    /// the real text.
    pub(super) fn compaction_text_len(&self) -> u64 {
        let mut total: u64 = self
            .leading_comments
            .iter()
            .map(|comment| comment.len() as u64 + 3)
            .sum();
        let mut directives: u64 = 0;
        for directive in self
            .dag
            .directives()
            .into_iter()
            .chain(self.live_quarantine().map(|(_, directive)| directive))
            .chain(self.live_typed_quarantine())
        {
            total += full_file_serialize(std::slice::from_ref(directive), &[]).len() as u64;
            directives += 1;
        }
        if directives > 0 {
            total += if self.leading_comments.is_empty() {
                directives - 1
            } else {
                directives
            };
        }
        for block in &self.quarantined_text {
            let was_empty = total == 0;
            if !was_empty {
                total += 1;
            }
            total += block.len() as u64;
            let ends_with_newline = if block.is_empty() {
                !was_empty
            } else {
                block.ends_with('\n')
            };
            if !ends_with_newline {
                total += 1;
            }
        }
        total
    }

    pub(super) fn compaction_directives(&self) -> Vec<Directive> {
        let mut directives: Vec<Directive> = self.dag.directives().into_iter().cloned().collect();
        if self.quarantined.is_empty() && self.quarantined_typed.is_empty() {
            return directives;
        }
        directives.extend(
            self.live_quarantine()
                .map(|(_, directive)| directive.clone()),
        );
        directives.extend(self.live_typed_quarantine().cloned());
        directives
    }

    /// The typed spellings held beside an enveloped copy (T99 / L-145), while
    /// the DAG holds neither.
    pub(super) fn live_typed_quarantine(&self) -> impl Iterator<Item = &Directive> + '_ {
        self.quarantined_typed
            .iter()
            .filter(|(content_id, _)| self.dag.get(content_id.as_str()).is_none())
            .map(|(_, directive)| directive)
    }

    /// The quarantined entries that are still the file's only copy of their
    /// record (H-08).
    ///
    /// The single definition of "live", shared by the write path
    /// ([`Self::compaction_directives`]) and the two operator-facing views
    /// ([`Self::quarantined_count`], [`Self::quarantined_ids`]), so the count an
    /// operator reads can never disagree with what the next rewrite does. That
    /// matters because a quarantined id can enter the DAG through a path that
    /// does no pruning — a peer serving the same economic body — and a count
    /// that kept reporting it would send an operator looking for damage that has
    /// already healed.
    pub(super) fn live_quarantine(&self) -> impl Iterator<Item = (&str, &Directive)> + '_ {
        self.quarantined
            .iter()
            .filter(|(content_id, _)| self.dag.get(content_id.as_str()).is_none())
            .map(|(content_id, directive)| (content_id.as_str(), directive))
    }

    /// Free quarantined entries the DAG now holds (H-08).
    ///
    /// A repaired `openledger-parents` does not change the content id — that is
    /// the whole premise of L-17 — so an operator's fix, or a peer's copy of
    /// the same body, arrives as a perfectly ordinary insert under the *same*
    /// id the quarantine is keyed by. Once the DAG has it, the file's copy IS
    /// the DAG's copy and the quarantine entry is a stale clone.
    ///
    /// Correctness does not depend on this running: [`Self::live_quarantine`]
    /// applies the same predicate on every read, so an entry the DAG has
    /// acquired is already invisible to the write path and to the counts. This
    /// is the memory half — it drops the clone at the one place that can make
    /// the condition true in bulk, [`Self::reconcile_content`], rather than
    /// carrying a duplicate of every repaired directive until the next reboot.
    pub(super) fn release_quarantined_now_in_dag(&mut self) {
        if self.quarantined.is_empty() {
            return;
        }
        let dag = &self.dag;
        self.quarantined
            .retain(|content_id, _| dag.get(content_id).is_none());
    }

    /// How many records the file holds that the DAG deliberately does not
    /// (H-08, L-45).
    ///
    /// Zero on every well-formed ledger. Non-zero is an operator signal, not a
    /// data-loss one: the records are still in the `.bean` and every rewrite
    /// puts them back — but they are invisible to reports, balances and peers
    /// until the file is repaired and the node restarted.
    ///
    /// Counts **both** halves of the quarantine: the directives boot parsed and
    /// refused ([`Self::quarantined`]) and the blocks it could not parse at all
    /// ([`Self::quarantined_text`]). `gl-node`'s startup banner reads this
    /// number, and a count that silently omitted half the held-back records
    /// would be the same false-assurance defect this series keeps finding.
    /// [`Self::quarantined_ids`] can only name the first half — an unparsable
    /// block has no content id, by definition — so the two can legitimately
    /// disagree in length; the per-block `warn!` boot emits carries the line
    /// numbers.
    pub fn quarantined_count(&self) -> usize {
        self.live_quarantine().count() + self.quarantined_text.len()
    }

    /// How many file blocks this node could not parse and is holding verbatim
    /// (L-45).
    pub fn unparsable_block_count(&self) -> usize {
        self.quarantined_text.len()
    }

    /// Content ids of the quarantined *directives*, in id order (H-08).
    ///
    /// Not the unparsable blocks — see [`Self::quarantined_count`].
    pub fn quarantined_ids(&self) -> Vec<&str> {
        self.live_quarantine().map(|(id, _)| id).collect()
    }

    /// The first `limit` of [`Self::quarantined_ids`], in id order, and how
    /// many there are in all — one pass, no list longer than `limit` built
    /// (T88 / L-103: the GraphQL `verify` field, which returned every id).
    pub fn quarantined_ids_capped(&self, limit: usize) -> (Vec<String>, usize) {
        let mut listed = Vec::new();
        let mut total = 0usize;
        for (id, _) in self.live_quarantine() {
            if listed.len() < limit {
                listed.push(id.to_owned());
            }
            total += 1;
        }
        (listed, total)
    }

    /// Canonical text of the directives staged since the last commit.
    ///
    /// `O(staged)`, not `O(ledger)` — this is the whole of T44's goal (a). The
    /// ids are resolved against the DAG rather than kept as cloned directives,
    /// so an in-place change (a signature stamp) can never be written stale;
    /// the one shape that cannot express — re-writing a directive already on
    /// disk — is what `force_compaction` exists for.
    ///
    /// The block is emitted by the same `full_file_serialize` a compaction
    /// uses, so a record's bytes are exactly the bytes those directives will
    /// occupy in the canonical file once folded in.
    pub(super) fn pending_block(&self) -> String {
        let directives: Vec<Directive> = self
            .pending_ids
            .iter()
            .filter_map(|id| self.dag.get(id).cloned())
            .collect();
        full_file_serialize(&directives, &[])
    }

    /// Has anything touched the `.bean` since this service last wrote or read
    /// it? One `stat`, no read (T44).
    ///
    /// Conservative in the direction that costs nothing: an unreadable file, or
    /// a service with no recorded marker, answers "yes" and escalates to a
    /// compaction, which runs the exact hash check.
    pub(super) fn canonical_file_changed_on_disk(&self) -> bool {
        match (FileMarker::of(&self.file_path), self.canonical_marker) {
            (Some(current), Some(recorded)) => current != recorded,
            _ => true,
        }
    }

    /// Release the in-flight flag from the service side (H-11).
    ///
    /// The *expected* release — the commit reached a conclusion this service
    /// knows about. [`CommitInFlightGuard`]'s `Drop` is the backstop for every
    /// path that does not, and the two are safe to run in either order: this
    /// one stores the idle sentinel, and the guard's compare-exchange then
    /// finds the flag already idle and does nothing.
    ///
    /// An unconditional store rather than a generation check, because both
    /// callers are the service deciding that *its* outstanding commit is over.
    pub(super) fn release_commit_in_flight(&mut self) {
        self.commit_in_flight
            .store(IDLE_COMMIT_GENERATION, std::sync::atomic::Ordering::Release);
    }

    /// Fold a completed commit back into in-memory bookkeeping (T44).
    ///
    /// Takes the ledger write lock at the call site; does no I/O.
    pub fn finish_commit(&mut self, receipt: CommitReceipt) {
        if receipt.generation != self.commit_generation {
            // Unreachable under the single-writer contract: the generation only
            // advances in `prepare`, and `prepare` refuses while a commit is in
            // flight. Reaching it means a caller finished a commit this service
            // is not waiting for, so the receipt describes files in a state
            // this service cannot reason about — refuse it rather than write
            // its numbers over the ones belonging to the live commit.
            error!(
                receipt_generation = receipt.generation,
                service_generation = self.commit_generation,
                "ignoring a ledger commit receipt from a different commit generation; \
                 the single-writer contract on LedgerService::commit_gate was violated"
            );
            return;
        }
        self.release_commit_in_flight();
        self.force_compaction = false;
        self.pending_ids.clear();
        self.canonical_journal_bytes = receipt.journal_bytes;
        if let Some(hash) = receipt.canonical_hash {
            // L-30: the file now says exactly this.
            self.last_file_hash = hash;
        }
        if let Some(bytes) = receipt.canonical_bytes {
            self.canonical_bytes = bytes;
        }
        if receipt.kind == CommitKind::Compact {
            // M-43: the torn journal, if there was one, is a sidecar now.
            self.journal_torn_at_boot = false;
            // M-46: the rewrite spelled every file-adopted line canonically.
            self.adopted_from_file.clear();
            self.canonical_marker = receipt.canonical_marker;
            // The `.bean` now holds exactly the bytes this service wrote.
            self.canonical_is_current = true;
            // T82 / L-80: and they fit — `persist_atomically` wrote them.
            self.canonical_over_cap = false;
        }
    }
}

impl LedgerService {
    /// Adopt an out-of-band hand edit before a full-file persist overwrites it
    /// (L-30 / L-12).
    ///
    /// A persist rewrites the whole `.bean` from in-memory state, so anything a
    /// human typed into the file since the last write is simply gone — no error,
    /// no log line, no trace. The T30 sidecar `flock` keeps a second `gl-node`
    /// off the file but does nothing about `vim`. So: re-read the file, hash it,
    /// and compare against [`Self::last_file_hash`]. Equal is the normal case and
    /// costs one read. Different means someone edited it, and the edit is
    /// reconciled into memory *first*, so the persist that follows writes the
    /// merged state instead of clobbering it.
    ///
    /// Failures are deliberately NOT swallowed:
    /// - an unreadable / oversized file returns the IO error, which
    ///   [`Self::persist_or_reload`] then treats exactly like a failed write;
    /// - a file that no longer parses returns the parse error, after a `warn!`
    ///   that prints every parse failure. The persist is abandoned rather than
    ///   canonicalised over a file a human is mid-way through editing — a broken
    ///   hand edit blocks writes until it is repaired, which is recoverable,
    ///   whereas overwriting it is not.
    ///
    /// Entries that parse but fail validation are surfaced by
    /// [`Self::reconcile_content`] and then dropped by the canonical re-persist
    /// — with one exception, [`Self::quarantined`]: a record boot refused is
    /// refused here again for the same reason, and is written back by the
    /// re-persist rather than dropped (H-08).
    ///
    /// # Not configurable, by design (M-19)
    ///
    /// `gl-node` shipped `externalFileEdits: "enabled" | "disabled"`, defaulted
    /// it to `"disabled"`, and the README said adoption "requires
    /// `"externalFileEdits": "enabled"`". No such gate ever existed on this
    /// path: the value's only reader gated the node's file *watcher*. That was
    /// false assurance, and the fix was to delete the setting rather than to
    /// honour it, because neither reading of "honour it" is a behaviour worth
    /// shipping:
    ///
    /// * **Skip the adoption.** The compaction still rewrites the whole file
    ///   from memory, so the operator's edit is not *ignored*, it is
    ///   *destroyed* — with no error, no log line and no trace. That is exactly
    ///   the L-30 defect this function exists to close, re-armed and made the
    ///   default.
    /// * **Refuse the write.** Fail-closed on any changed file wedges every
    ///   write on a node whose `.bean` was edited at all, by default, and the
    ///   only way out is an operator who knows to restart the node.
    ///
    /// Both also strand the quarantine. A record boot refused (H-08) or a block
    /// that never parsed (L-45) LEAVES quarantine by being repaired in the file
    /// and re-derived here — that is what [`Self::reconcile_content`] means by
    /// "the raw-text analogue of `release_quarantined_now_in_dag`". With
    /// adoption disabled, the repair is never read: T47/T51's quarantined
    /// records would be retained verbatim on every rewrite, forever, with no
    /// operator action able to release them.
    ///
    /// What the operator does control is the node's *proactive* half — whether
    /// it polls the file and folds an edit in within 250 ms instead of at the
    /// next rewrite. That is `gl-node`'s `watchLedgerFile`, which is named for
    /// what it does.
    ///
    /// # T44: called from the compaction path only
    ///
    /// This is `O(file)` — a read, a hash, and on a mismatch a full reconcile —
    /// and since T44 it runs where the `O(file)` cost already lives: inside the
    /// compaction branch of [`Self::prepare_commit`], which is the only branch
    /// that rewrites the `.bean` and therefore the only one that could erase an
    /// edit. An append leaves the canonical file untouched, so a hand edit made
    /// before it is still on disk afterwards, and boot unions the two files.
    /// The `stat` probe in `prepare` escalates to a compaction the moment the
    /// file's size or mtime moves, so in practice an edit is still adopted at
    /// the very next write — what changed is only that the adoption is no
    /// longer *unconditionally* re-read on every single write.
    ///
    /// # An absent file is nothing to adopt (H-15)
    ///
    /// `rm`/`mv` of the `.bean` under a running node used to fail this read
    /// with `NotFound`, which failed the prepare, which ran the L-13 reload,
    /// which `boot`ed an **empty** file and installed it over the complete
    /// in-memory ledger — the cheapest total loss in the series. There is
    /// nothing on disk to adopt and nothing on disk to lose, so the answer is
    /// `Ok` with a loud warning, and the compaction this call precedes
    /// recreates the file from memory with every directive in it.
    ///
    /// # Baseline only what parsed (H-14)
    ///
    /// The `stat` marker and the byte count are re-baselined on the
    /// identical-bytes path only. On a real edit [`Self::reconcile_content`]
    /// records them — after the parse, together with the hash — so a file
    /// that does not parse is re-detected as foreign by the very next
    /// `prepare` instead of being mistaken for "what we last read".
    pub(super) fn adopt_external_edits(&mut self) -> Result<(), ServiceError> {
        let content = match read_ledger_file(&self.file_path) {
            Ok(content) => content,
            Err(ServiceError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                warn!(
                    file = %self.file_path.display(),
                    directives = self.dag.len(),
                    "ledger file is MISSING on disk — removed or renamed while this node was \
                     running. Nothing to adopt; the compaction that follows recreates it from \
                     memory with every directive in it (H-15)"
                );
                self.canonical_marker = None;
                self.canonical_bytes = 0;
                self.canonical_is_current = false;
                return Ok(());
            }
            Err(error) => return Err(error),
        };
        if file_content_hash(&content) == self.last_file_hash {
            // Re-baseline the cheap probe from the same read, so an editor that
            // merely touched the mtime does not escalate every later append.
            self.canonical_marker = FileMarker::of(&self.file_path);
            self.canonical_bytes = content.len() as u64;
            return Ok(());
        }

        self.external_reconcile_count = self.external_reconcile_count.saturating_add(1);
        warn!(
            file = %self.file_path.display(),
            "ledger file changed on disk since this node last wrote it; adopting the \
             external edit before persisting so the persist does not overwrite it (L-30)"
        );

        let result = self.reconcile_content(&content)?;
        warn!(
            adopted = result.new_directives,
            duplicates = result.duplicates,
            rejected = result.rejected,
            "external ledger-file edit reconciled ahead of persist"
        );
        Ok(())
    }

    /// Persist the ledger, restoring memory==disk if the persist fails (L-13).
    ///
    /// The 64 MiB cap and every IO error are surfaced by [`Self::persist`] only
    /// *after* the in-memory DAG has already been mutated by the caller. A
    /// failed persist would therefore leave memory ahead of disk: reads would
    /// serve directives that are not on disk, and the next boot would silently
    /// drop them.
    ///
    /// Because [`persist_atomically`] writes to a sibling `.tmp` and then
    /// renames, a failed persist leaves the previous `.bean` file fully intact —
    /// it is the last good, fully consistent state. So on failure we discard the
    /// unpersisted in-memory mutations by reconstructing the entire service from
    /// that on-disk file via [`Self::boot`] (which fully derives dag, account
    /// state, read model, Lamport clock, and leading comments from the file plus
    /// the author id — the service holds no other, non-derived state). The
    /// original persist error is always returned; the batch that could not be
    /// written is dropped from memory and anti-entropy simply re-pulls it later.
    ///
    /// If the reload *itself* fails (e.g. the file became unreadable), memory is
    /// left as-is and a combined error is logged — there is no better on-disk
    /// state to fall back to — but the original persist error is still returned.
    ///
    /// ## Concurrent hand edits (L-30) — best-effort, not a lock
    ///
    /// Before writing, [`Self::adopt_external_edits`] re-reads and re-hashes the
    /// file and reconciles anything a human changed, so a hand edit made while
    /// the node runs is merged in rather than silently destroyed. This is
    /// **best-effort and explicitly racy**:
    ///
    /// - the T30 sidecar `flock` excludes other `gl-node` processes, not text
    ///   editors, so there is no mutual exclusion with the writer being guarded
    ///   against;
    /// - an edit that lands in the window between the hash check and the
    ///   `rename` is still lost, and nothing here detects it;
    /// - an editor that rewrites the file via its own temp+rename can swap the
    ///   inode after the read, with the same outcome.
    ///
    /// It closes the wide hole (an edit made minutes before the next persist)
    /// and does not pretend to close the narrow one. Editing a `.bean` that a
    /// running node owns is still unsupported; stop the node first.
    ///
    /// ## The commit journal (T44)
    ///
    /// The journal is **node-private**: hand-editing it is unsupported and will
    /// fail closed on its per-record hash. There is nothing to adopt from it —
    /// it holds only directives this node itself wrote.
    pub fn persist_or_reload(&mut self) -> Result<(), ServiceError> {
        self.commit_inline(false)
    }

    /// Fold the journal back into the canonical `.bean`, synchronously (T44).
    ///
    /// The explicit compaction point: a node calls it once after boot (so a
    /// crash-window journal does not linger) and once at a clean shutdown (so
    /// the file an operator looks at is the canonical one). Reconcile uses it
    /// too, because canonicalising the file is the entire point there.
    ///
    /// Like [`Self::persist_or_reload`], a failure restores memory == disk.
    pub fn compact(&mut self) -> Result<(), ServiceError> {
        self.commit_inline(true)
    }

    /// prepare + commit + finish, inline — the one-call form for synchronous
    /// callers (T44).
    ///
    /// The blocking write happens on the calling thread with whatever lock the
    /// caller holds still held; that is exactly the pre-T44 behaviour, and it
    /// is why the node layer uses the two-phase form on its async paths
    /// instead.
    pub(super) fn commit_inline(&mut self, explicit_compaction: bool) -> Result<(), ServiceError> {
        let prepared = if explicit_compaction {
            self.prepare_compaction()
        } else {
            self.prepare_commit()
        };
        let commit_error = match prepared {
            Ok(None) => return Ok(()),
            Ok(Some(pending)) => match pending.commit() {
                Ok(receipt) => {
                    self.finish_commit(receipt);
                    return Ok(());
                }
                Err(error) => error,
            },
            // A refusal to prepare *because another commit is in flight* must
            // not trigger the L-13 reload: the other commit owns the files, and
            // re-booting under it would discard state it is about to make
            // durable. Nothing was written, nothing is ahead of disk.
            Err(ServiceError::CommitInFlight) => return Err(ServiceError::CommitInFlight),
            // M-37(a): a `.bean` that does not parse is refused by the
            // adoption BEFORE anything about it is recorded (H-14), so the
            // prepare left memory exactly as the caller staged it and the
            // files untouched. Reloading here bought nothing and cost the
            // finding: `boot` on that file loaded every parseable hand-typed
            // block raw, bypassing every reconcile check and the signature.
            // The write stays refused until the operator repairs the file;
            // the staged batch stays in memory and is written by the first
            // commit after the repair (see `prepare_or_recover` in `gl-node`
            // for the same arm and the same argument).
            Err(error @ ServiceError::Parse(_)) => return Err(error),
            // T86 / M-58: the L-80 refusal, with nothing staged — see
            // `prepare_refusal_needs_no_reload`.
            Err(error) if self.prepare_refusal_needs_no_reload(&error) => return Err(error),
            Err(error) => error,
        };

        // L-13. `prepare` may already have mutated memory (adoption reconciles
        // a hand edit in before it serializes), so the reload runs on both the
        // prepare-failed and the commit-failed path.
        self.recover_failed_commit();
        Err(commit_error)
    }
}
