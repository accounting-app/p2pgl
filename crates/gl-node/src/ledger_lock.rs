//! Inter-process exclusivity on the ledger file (M-17).
//!
//! Two `gl-node` processes pointed at one `.bean` each hold an independent
//! in-memory DAG and rewrite the *whole* file on every persist, so the later
//! writer silently discards the other's directives. That is not a hypothetical:
//! it was the documented dev flow (three peer configs on one `test-ledger.bean`,
//! see `scripts/peer.txt`), and the same gap hits production on restart overlap
//! or two containers sharing a volume.
//!
//! The fix is an exclusive advisory lock on a `<ledgerPath>.lock` sidecar,
//! taken once per process at startup and held for the lifetime of the process.
//! A second instance fails closed with a message naming the path.
//!
//! # Why the lock lives in `main`, not in `LedgerService::boot`
//!
//! Putting it in the library's `boot` looks tidier and is wrong. T27's
//! [`ledger::service::LedgerService::persist_or_reload`] recovers from a failed
//! persist by rebuilding the service from disk — `*self = LedgerService::boot(…)`
//! on the *same* path. flock-style locks are attached to the open file
//! description, so they conflict between two descriptors even inside one
//! process: a lock owned by `boot` would refuse its own reload and turn every
//! recoverable persist failure into a hard boot failure. Library and test users
//! also legitimately boot many services (on distinct temp files) in one process.
//!
//! A process-level lock in `main` covers the real threat — two *processes* on
//! one ledger — while leaving the library unlocked.
//!
//! # Bonus: it makes the stale-temp cleanup in `persist_atomically` safe
//!
//! `persist_atomically` recovers from `AlreadyExists` on `<name>.tmp` by
//! unlinking it and retrying. Without a process lock that could delete a
//! *sibling* process's in-flight temp. With this lock held no sibling can be
//! mid-persist on this ledger, so any temp encountered is our own crashed
//! leftover. (Library users that do not take the lock keep the old exposure —
//! documented at that call site.)

use std::fs::{File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

/// Suffix appended to the ledger file name to form the lock sidecar.
const LOCK_SUFFIX: &str = ".lock";

/// Guard proving this process holds the exclusive lock on a ledger file.
///
/// The lock lives as long as the guard: dropping it (or closing the process,
/// gracefully or not) releases it, because the OS drops advisory locks with the
/// file descriptor. A crash therefore never wedges the ledger — there is no
/// stale lock to clear by hand, and the sidecar file itself is inert (it is
/// never written to, and being left behind means nothing).
#[derive(Debug)]
pub struct LedgerLock {
    /// Held purely for its lock; released on drop with the descriptor.
    _file: File,
    path: PathBuf,
}

impl LedgerLock {
    /// Path of the lock sidecar this guard holds.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Path of the lock sidecar for `ledger_path`: the ledger file name plus `.lock`.
fn lock_path_for(ledger_path: &Path) -> Result<PathBuf, String> {
    let file_name = ledger_path.file_name().ok_or_else(|| {
        format!(
            "ledger path {} has no file name — cannot derive a lock file",
            ledger_path.display()
        )
    })?;
    Ok(ledger_path.with_file_name(format!("{}{LOCK_SUFFIX}", file_name.to_string_lossy())))
}

/// Take the exclusive advisory lock on `ledger_path`, failing closed (M-17).
///
/// The lock is taken on the `<ledgerPath>.lock` sidecar rather than on the
/// ledger itself, so it is independent of how the ledger is rewritten:
/// `persist_atomically` replaces the `.bean` by `rename`, which would leave a
/// lock held on the *old*, now-unlinked inode. The sidecar is never written to
/// and carries no data — it exists only to be locked — so it needs no content
/// and is safe to create.
///
/// Returns `Err` with an operator-readable message when another `gl-node`
/// instance already holds the ledger, or when the sidecar cannot be opened.
pub fn acquire(ledger_path: &Path) -> Result<LedgerLock, String> {
    let lock_path = lock_path_for(ledger_path)?;

    let mut options = OpenOptions::new();
    // Read + write: Windows refuses to lock a handle without write access, and
    // the file is only ever opened, never read or written.
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let file = options.open(&lock_path).map_err(|error| {
        format!(
            "failed to open ledger lock file {}: {error}",
            lock_path.display()
        )
    })?;

    match file.try_lock() {
        Ok(()) => Ok(LedgerLock {
            _file: file,
            path: lock_path,
        }),
        Err(TryLockError::WouldBlock) => Err(format!(
            "ledger {} is already locked via {}: another gl-node instance is running on this ledger. \
             Two nodes on one .bean silently discard each other's directives (M-17) — \
             stop the other instance or give this one its own ledgerPath",
            ledger_path.display(),
            lock_path.display()
        )),
        Err(TryLockError::Error(error)) => Err(format!(
            "failed to lock ledger lock file {}: {error}",
            lock_path.display()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh path locks cleanly and the sidecar is created next to the ledger.
    #[test]
    fn acquire_creates_sidecar_and_succeeds() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = temp_dir.path().join("ledger.bean");

        let guard = acquire(&ledger_path).expect("fresh ledger path must lock");

        assert_eq!(guard.path(), temp_dir.path().join("ledger.bean.lock"));
        assert!(guard.path().exists(), "the lock sidecar must be created");
    }

    /// The lock is on the sidecar, so the ledger file itself need not exist yet
    /// — `main` takes the lock before it creates an empty `.bean`.
    #[test]
    fn acquire_does_not_require_the_ledger_file_to_exist() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = temp_dir.path().join("absent.bean");

        let guard = acquire(&ledger_path).expect("absent ledger must still lock");

        assert!(
            !ledger_path.exists(),
            "acquire must not create the ledger file itself"
        );
        assert!(guard.path().exists(), "only the sidecar is created");
    }

    /// M-17: while the first guard is held, a second acquire on the same ledger
    /// is refused. flock-style locks conflict across file descriptors even
    /// within one process, so this second `acquire` — a second `open` — is a
    /// faithful stand-in for a second gl-node process.
    #[test]
    fn second_acquire_is_refused_while_the_first_is_held() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = temp_dir.path().join("contended.bean");

        let _first = acquire(&ledger_path).expect("first acquire must succeed");

        let second = acquire(&ledger_path);
        let error = second.expect_err("a second instance must not get the same ledger");
        assert!(
            error.contains("already locked"),
            "contention must be reported as contention, got: {error}"
        );
        assert!(
            error.contains("another gl-node instance"),
            "the message must explain what is holding the ledger, got: {error}"
        );
    }

    /// The contention error names both the ledger and the lock file, so an
    /// operator can act on it without reading the source.
    #[test]
    fn contention_error_names_the_paths() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = temp_dir.path().join("named.bean");

        let _first = acquire(&ledger_path).expect("first acquire must succeed");
        let error = acquire(&ledger_path).expect_err("second acquire must fail");

        assert!(
            error.contains(&ledger_path.display().to_string()),
            "error must name the ledger path, got: {error}"
        );
        assert!(
            error.contains("named.bean.lock"),
            "error must name the lock file, got: {error}"
        );
    }

    /// Dropping the guard releases the lock — a restarted node reacquires it,
    /// and a crashed process leaves nothing to clean up by hand.
    #[test]
    fn lock_is_released_when_the_guard_is_dropped() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = temp_dir.path().join("restart.bean");

        let first = acquire(&ledger_path).expect("first acquire must succeed");
        assert!(
            acquire(&ledger_path).is_err(),
            "contended while the guard lives"
        );

        drop(first);

        let _second = acquire(&ledger_path).expect("a released ledger must lock again");
    }

    /// Distinct ledgers lock independently — the three-peer dev flow works once
    /// each peer config has its own `ledgerPath`.
    #[test]
    fn distinct_ledgers_lock_independently() {
        let temp_dir = tempfile::tempdir().expect("temp dir");

        let _zero = acquire(&temp_dir.path().join("peer-0.bean")).expect("peer 0 locks");
        let _one = acquire(&temp_dir.path().join("peer-1.bean")).expect("peer 1 locks");
        let _two = acquire(&temp_dir.path().join("peer-2.bean")).expect("peer 2 locks");
    }

    /// A path with no file name cannot yield a sidecar; report it rather than
    /// silently running unlocked.
    #[test]
    fn path_without_a_file_name_is_rejected() {
        let error = acquire(Path::new("/")).expect_err("a root path has no file name");
        assert!(
            error.contains("no file name"),
            "got unexpected error: {error}"
        );
    }
}
