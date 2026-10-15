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
//! taken when the node starts the ledger and held for as long as it runs it.
//! A second instance fails closed with a message naming the path.
//!
//! # Why the lock lives in the node (`ledger_runtime::start`), not in `LedgerService::boot`
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
//! A lock the node takes covers the real threat — two *processes* on
//! one ledger — while leaving the library unlocked.
//!
//! # Bonus: it makes the stale-temp sweep at boot safe
//!
//! Since T67 (L-57) `persist_atomically` writes to a fresh
//! `<name>.tmp.<pid>.<nonce>` per call and never unlinks what it finds; boot
//! sweeps the `<name>.tmp*` leftovers of crashed rewrites once, at process
//! start. Without a process lock that sweep could delete a *sibling* process's
//! in-flight temp. `ledger_runtime::start` takes this lock before it boots, so no sibling can be
//! mid-persist on this ledger and every temp the sweep finds is a crashed
//! leftover. (Library users that do not take the lock keep that exposure —
//! documented at the sweep.)

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
///
/// # What is locked (L-59, T67)
///
/// The sidecar is opened through [`ledger::journal::open_checked`] as a
/// node-private file: never through a symlink (`lstat` refusal, then
/// `O_NOFOLLOW`), never blocking (`O_NONBLOCK`), and only if the handle is a
/// regular file owned by this uid with one link and mode 0600. The old
/// `create(true)` open followed a symlink at `<ledger>.bean.lock`, so the flock
/// landed on the link's TARGET — re-pointing the link between two starts
/// admitted two nodes onto one ledger (the M-17 silent-loss shape), and a FIFO
/// target blocked the start.
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

    let file = ledger::journal::open_checked(
        &lock_path,
        &options,
        ledger::journal::FileTrust::NodePrivate,
        "ledger lock file",
    )
    .map_err(|error| format!("failed to open the ledger lock: {error}"))?
    .file;

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
    /// — the node takes the lock before it creates an empty `.bean`.
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

    /// L-59: a symlink at `<ledger>.bean.lock` used to be followed, so the
    /// flock landed on the link's TARGET (B8 `lock-symlink`). `acquire` now
    /// refuses it, the link is left as it was, and the target is not locked.
    ///
    /// Bug-catch: open the sidecar with plain `OpenOptions::open` again and
    /// `acquire` succeeds with the target locked.
    #[cfg(unix)]
    #[test]
    fn l59_acquire_refuses_a_symlinked_lock_and_leaves_the_target_unlocked() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = temp_dir.path().join("ledger.bean");
        let victim = temp_dir.path().join("victim-file");
        std::fs::write(&victim, "").unwrap();
        std::os::unix::fs::symlink(&victim, temp_dir.path().join("ledger.bean.lock")).unwrap();

        let error = acquire(&ledger_path).expect_err("a symlinked lock must be refused");
        assert!(error.contains("symbolic link"), "{error}");
        let probe = File::open(&victim).unwrap();
        probe
            .try_lock()
            .expect("L-59: the symlink's target must not be locked");
        assert!(
            std::fs::symlink_metadata(temp_dir.path().join("ledger.bean.lock"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    /// M-36's shape at the lock: a FIFO at the sidecar path is refused at
    /// once rather than blocking the start (an `O_RDWR` open of a FIFO does
    /// not block on Linux, but nothing was ever going to lock it usefully).
    #[cfg(unix)]
    #[test]
    fn t67_acquire_refuses_a_fifo_lock_without_blocking() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = temp_dir.path().join("ledger.bean");
        let status = std::process::Command::new("mkfifo")
            .arg(temp_dir.path().join("ledger.bean.lock"))
            .status()
            .unwrap();
        assert!(status.success());
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(acquire(&ledger_path).map(|_| ()));
        });
        let outcome = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("M-36: acquire blocked on a FIFO");
        let error = outcome.expect_err("a FIFO is not a lock file");
        assert!(error.contains("not a regular file"), "{error}");
    }

    /// L-58's rule for the lock sidecar: a pre-planted world-readable or
    /// hard-linked sidecar is not one this node created, and is refused.
    #[cfg(unix)]
    #[test]
    fn t67_acquire_refuses_a_planted_or_hard_linked_lock_file() {
        use std::os::unix::fs::PermissionsExt;
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ledger_path = temp_dir.path().join("ledger.bean");
        let lock_path = temp_dir.path().join("ledger.bean.lock");
        std::fs::write(&lock_path, "").unwrap();
        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = acquire(&ledger_path).expect_err("0644 is not a node-private file");
        assert!(error.contains("overly permissive"), "{error}");

        std::fs::set_permissions(&lock_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&lock_path, temp_dir.path().join("second-name")).unwrap();
        let error = acquire(&ledger_path).expect_err("a second name is refused");
        assert!(error.contains("hard links"), "{error}");
    }
}
