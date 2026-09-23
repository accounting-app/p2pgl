//! File watcher — detects external `.bean` edits and triggers reconciliation.
//!
//! Monitors the ledger's `.bean` file for modifications. When a change is
//! detected, the watcher re-reads the file and diff-merges any new directives
//! into the DAG via the union merge path (same as remote gossip).
//!
//! This is the §3.3 "adopted edits" pathway (CT-12).

use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};

/// Configuration for the file watcher.
#[derive(Debug, Clone)]
pub struct FileWatcherConfig {
    /// Path to the `.bean` file.
    pub file_path: PathBuf,
    /// How often to poll for changes.
    pub poll_interval: Duration,
    /// Whether to poll the file at all.
    ///
    /// M-19: renamed from `external_edits_enabled`, which was the same false
    /// assurance as `gl-node`'s `externalFileEdits` and for the same reason —
    /// nothing gates whether an external edit is *accepted*
    /// (`LedgerService::adopt_external_edits` says why), only whether this
    /// watcher goes looking for one.
    pub watch_enabled: bool,
}

impl Default for FileWatcherConfig {
    fn default() -> Self {
        FileWatcherConfig {
            file_path: PathBuf::from("ledger.bean"),
            poll_interval: Duration::from_millis(1000),
            watch_enabled: false,
        }
    }
}

/// File change detection result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileChangeKind {
    /// File was modified (content hash, size, or mtime changed).
    Modified,
    /// File was created (didn't exist before).
    Created,
    /// File was deleted.
    Deleted,
    /// No change detected.
    Unchanged,
}

/// Tracks the last-known state of the `.bean` file for change detection.
#[derive(Debug, Clone)]
pub struct FileState {
    /// Last known file size.
    pub size: Option<u64>,
    /// Last known modification time.
    pub modified: Option<std::time::SystemTime>,
    /// SHA-256 of the file contents, when the file exists and was readable.
    ///
    /// This is the authoritative change signal: an edit that preserves both
    /// size and mtime (e.g. an in-place rewrite within one coarse mtime tick)
    /// still changes the hash, so it is not misclassified as `Unchanged` (L7).
    pub content_hash: Option<[u8; 32]>,
}

impl FileState {
    /// Create from a file path. Absent size/hash mean the file doesn't exist
    /// (or could not be read).
    ///
    /// # The size cap (M-29)
    ///
    /// `stat` first, and **do not read** a file larger than
    /// [`crate::service::MAX_LEDGER_FILE_BYTES`]. The old comment here claimed the read was
    /// bounded because "the ledger file is size-capped" — but the cap lives in
    /// `read_ledger_file`, which is a different function that this one does not
    /// call, and nothing stops a file on this path from being any size at all.
    /// The watcher polls four times a second on a tokio worker, so an oversized
    /// `.bean` — a bad `cat >>`, a runaway process, a hostile mount — meant an
    /// unbounded read into memory on a runtime thread, 4 Hz, forever.
    ///
    /// An over-cap file still reports its `size` and `modified`, so
    /// [`Self::detect_change`] falls back to those and still classifies it as a
    /// change. The reconcile that follows is the one that must refuse it, and
    /// it does: `read_ledger_file` returns `ResourceLimitExceeded` and the
    /// watcher logs it. Hiding the change here instead would be worse — the
    /// operator would get silence rather than the error that names the cap.
    ///
    /// # What is read (T67, M-36)
    ///
    /// Only a regular file (or a symlink to one — the `.bean` policy in
    /// [`crate::journal::FileTrust::OperatorLedger`]), opened without blocking
    /// and read through a cap enforced by the read itself. A FIFO at the path
    /// used to pass the `stat` cap at length 0 and then block this runtime
    /// worker in `read`, or stream past the cap. Anything that is not a regular
    /// file is reported like an over-cap one — size and mtime, no hash — so the
    /// change is still seen and the reconcile's `read_ledger_file` is the one
    /// that refuses it by name.
    pub fn from_path(path: &Path) -> Self {
        let Ok(metadata) = std::fs::metadata(path) else {
            return FileState {
                size: None,
                modified: None,
                content_hash: None,
            };
        };
        let modified = metadata.modified().ok();
        if !metadata.is_file() || metadata.len() > crate::service::MAX_LEDGER_FILE_BYTES {
            return FileState {
                size: Some(metadata.len()),
                modified,
                content_hash: None,
            };
        }
        // Read once and derive both size and hash from the same bytes so they
        // stay consistent. The handle's `fstat` and the capped read bound it.
        let read = crate::journal::open_checked(
            path,
            std::fs::OpenOptions::new().read(true),
            crate::journal::FileTrust::OperatorLedger,
            "ledger file",
        )
        .and_then(|checked| {
            crate::journal::read_to_end_capped(
                &checked.file,
                checked.metadata.len(),
                crate::service::MAX_LEDGER_FILE_BYTES,
            )
        });
        match read {
            Ok(bytes) => {
                let digest = Sha256::digest(&bytes);
                let mut content_hash = [0u8; 32];
                content_hash.copy_from_slice(&digest);
                FileState {
                    size: Some(bytes.len() as u64),
                    modified,
                    content_hash: Some(content_hash),
                }
            }
            Err(_) => FileState {
                size: None,
                modified: None,
                content_hash: None,
            },
        }
    }

    /// The polled content hash as lowercase hex — the spelling
    /// `LedgerService` records for the canonical file (M-29).
    ///
    /// `None` when the file was absent, unreadable, or over the cap, all of
    /// which mean "cannot claim this is our own write".
    ///
    /// The digest is taken over the file's raw bytes while the service hashes
    /// the BOM-stripped text (L-28), so the two agree exactly when there is no
    /// BOM — which is always true of a file this node wrote, since the
    /// serializer never emits one. A BOM'd file therefore compares unequal and
    /// is treated as an external edit, which is the safe direction: the
    /// self-write check below it is an optimisation, and
    /// `reconcile_file_staged` re-checks with the service's own hash.
    pub fn content_hash_hex(&self) -> Option<String> {
        self.content_hash
            .map(|digest| digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }

    /// Check if the file has changed compared to a previous state.
    pub fn detect_change(&self, previous: &FileState) -> FileChangeKind {
        match (&self.size, &previous.size) {
            (None, None) => FileChangeKind::Unchanged,
            (Some(_), None) => FileChangeKind::Created,
            (None, Some(_)) => FileChangeKind::Deleted,
            (Some(new_size), Some(old_size)) => {
                // When both content hashes are known, they are authoritative:
                // equal hash means the bytes are identical regardless of size or
                // mtime; a differing hash is a modification even if size and
                // mtime are unchanged (L7).
                if let (Some(new_hash), Some(old_hash)) =
                    (&self.content_hash, &previous.content_hash)
                {
                    return if new_hash == old_hash {
                        FileChangeKind::Unchanged
                    } else {
                        FileChangeKind::Modified
                    };
                }
                // Fallback (a hash was unavailable): size + mtime.
                if new_size != old_size {
                    return FileChangeKind::Modified;
                }
                match (&self.modified, &previous.modified) {
                    (Some(new_time), Some(old_time)) if new_time != old_time => {
                        FileChangeKind::Modified
                    }
                    _ => FileChangeKind::Unchanged,
                }
            }
        }
    }
}

/// How many polls may go by without re-reading an unchanged-looking file
/// (M-42, T69). At the node's 250 ms cadence, 40 polls is 10 s.
///
/// # The trade
///
/// A [`FilePoller`] re-reads and re-hashes the file only when its `stat`
/// identity ([`StatKey`]: size, mtime, and on Unix ctime, inode and device)
/// has changed, when the last read was *racy* (the file had been modified
/// within [`RACY_WINDOW`] of that read, so a rewrite inside the same timestamp
/// granule could follow it unseen), or once every `FULL_READ_EVERY` polls
/// regardless. The last is the backstop for the one case the other two cannot
/// see: a rewrite that keeps the size, lands in the same timestamp granule as
/// the previous write, and whose mtime *and* ctime still read as older than
/// the racy window — in practice a filesystem whose clock is behind this
/// host's (a network mount). Such an edit is still detected, at most
/// `FULL_READ_EVERY` polls (≈10 s) late, instead of within one poll; every
/// other edit is detected at the next poll exactly as before.
///
/// What it buys: an unchanged 59 MiB `.bean` is read once per 10 s instead of
/// four times a second — measured 215.8 ms of read + SHA-256 per poll before
/// (86 % of a core, forever), one `stat` per poll after.
pub const FULL_READ_EVERY: u32 = 40;

/// How recent a file's mtime may be, relative to the moment it was read, for
/// that read to be treated as racy and repeated at the next poll (M-42).
///
/// Two seconds covers the coarsest timestamp granularity in use (FAT's 2 s;
/// HFS+ and ext3 are 1 s): an edit that lands in the same granule as the
/// previous one, after we read it, is otherwise invisible to `stat`. The cost
/// is a few extra reads right after a write — the node's own compactions and
/// an operator's saves — never on a file at rest.
pub const RACY_WINDOW: std::time::Duration = std::time::Duration::from_secs(2);

/// The `stat` identity of the `.bean`, compared poll to poll to decide whether
/// the file has to be re-read (M-42).
///
/// Size and mtime alone miss an edit that preserves both (L7), which is why
/// the watcher hashed on every poll. On Unix the ctime is included too: it is
/// set by the kernel on every write and cannot be restored by `utimes`, so a
/// same-size rewrite followed by `touch -d <old mtime>` still changes the key.
/// Inode and device catch a replace-by-rename (an editor's save, or this
/// node's own `persist_atomically`) even when every timestamp matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatKey {
    len: u64,
    modified: Option<std::time::SystemTime>,
    /// `(ctime seconds, ctime nanoseconds, inode, device)`; `None` off Unix.
    unix: Option<(i64, i64, u64, u64)>,
}

impl StatKey {
    /// The key for `metadata`.
    pub fn of(metadata: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        let unix = {
            use std::os::unix::fs::MetadataExt;
            Some((
                metadata.ctime(),
                metadata.ctime_nsec(),
                metadata.ino(),
                metadata.dev(),
            ))
        };
        #[cfg(not(unix))]
        let unix = None;
        StatKey {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            unix,
        }
    }

    /// Was a read taken at `read_at` racy — could a same-granule rewrite
    /// follow it without changing this key? See [`RACY_WINDOW`].
    ///
    /// An mtime in the future (a skewed clock) is racy; no mtime at all is
    /// not — the `FULL_READ_EVERY` backstop covers that platform.
    fn is_racy_at(&self, read_at: std::time::SystemTime) -> bool {
        match self.modified {
            Some(modified) => match read_at.duration_since(modified) {
                Ok(age) => age < RACY_WINDOW,
                Err(_) => true,
            },
            None => false,
        }
    }
}

/// A stateful poller over one file: [`FileState::from_path`], but reading and
/// hashing the file only when it may have changed (M-42, T69).
///
/// # The bug this closes
///
/// The node's watcher called `FileState::from_path` every 250 ms, and every
/// call read and SHA-256'd the whole `.bean` whether or not anything had
/// changed: 215.8 ms per poll on a 59 MiB ledger in a release build (86 % of a
/// core, 240 MiB/s hashed, forever), on a runtime worker, with the interval's
/// default `Burst` catch-up running polls back to back once one poll took
/// longer than the period (4.17 s per poll in a debug build).
///
/// # The shape
///
/// `stat` every poll; read + hash only when the [`StatKey`] changed, the last
/// read was racy, or [`FULL_READ_EVERY`] polls have passed since the last
/// read. Otherwise the previous [`FileState`] is returned as is, which
/// [`FileState::detect_change`] classifies as `Unchanged` (equal hashes). The
/// read itself is T67's: `journal::open_checked` + `read_to_end_capped`, via
/// `from_path`, unchanged. The poller is `Send` and owns no runtime resources,
/// so a caller can move it into `spawn_blocking` for each poll (the node does).
#[derive(Debug)]
pub struct FilePoller {
    path: PathBuf,
    full_read_every: u32,
    last: Option<(StatKey, FileState)>,
    polls_since_read: u32,
    racy: bool,
    reads: u64,
}

impl FilePoller {
    /// A poller over `path` with the production backstop, [`FULL_READ_EVERY`].
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::with_full_read_every(path, FULL_READ_EVERY)
    }

    /// A poller that re-reads at least every `full_read_every` polls (a value
    /// of 0 or 1 reads on every poll, which is the pre-M-42 behaviour).
    pub fn with_full_read_every(path: impl Into<PathBuf>, full_read_every: u32) -> Self {
        FilePoller {
            path: path.into(),
            full_read_every: full_read_every.max(1),
            last: None,
            polls_since_read: 0,
            racy: false,
            reads: 0,
        }
    }

    /// The file's state now, reading it only if it may have changed.
    pub fn poll(&mut self) -> FileState {
        match std::fs::metadata(&self.path) {
            Ok(metadata) => {
                self.poll_with_key(StatKey::of(&metadata), std::time::SystemTime::now())
            }
            Err(_) => {
                // Absent (or not even stat-able): nothing to read, and the
                // next time it is there it must be read.
                self.last = None;
                FileState {
                    size: None,
                    modified: None,
                    content_hash: None,
                }
            }
        }
    }

    /// How many times this poller has read the file (a full
    /// [`FileState::from_path`]). For tests and diagnostics.
    pub fn reads(&self) -> u64 {
        self.reads
    }

    /// [`Self::poll`] with the `stat` result and the clock supplied — the seam
    /// that lets a test hold the key still across a real rewrite, which no
    /// filesystem will do on demand.
    fn poll_with_key(&mut self, key: StatKey, now: std::time::SystemTime) -> FileState {
        if let Some((last_key, state)) = &self.last {
            let due = self.polls_since_read.saturating_add(1) >= self.full_read_every;
            if *last_key == key && !self.racy && !due {
                self.polls_since_read += 1;
                return state.clone();
            }
        }
        // The key was taken BEFORE this read, so an edit racing the read
        // leaves the stored key older than the file and the next poll reads
        // again — the safe direction.
        let state = FileState::from_path(&self.path);
        self.reads = self.reads.saturating_add(1);
        self.polls_since_read = 0;
        self.racy = key.is_racy_at(now);
        self.last = Some((key, state.clone()));
        state
    }
}

/// A file watcher handle (for cancellation).
///
/// The actual watching loop is spawned as a background task. This handle
/// can be used to stop the watcher.
#[derive(Debug)]
pub struct FileWatcherHandle {
    cancel: tokio::sync::watch::Sender<bool>,
}

impl FileWatcherHandle {
    /// Create a new watcher handle and its cancellation channel.
    pub fn new() -> (Self, tokio::sync::watch::Receiver<bool>) {
        let (tx, rx) = tokio::sync::watch::channel(false);
        (FileWatcherHandle { cancel: tx }, rx)
    }

    /// Stop the watcher.
    pub fn stop(&self) {
        let _ = self.cancel.send(true);
    }
}

impl Default for FileWatcherHandle {
    fn default() -> Self {
        Self::new().0
    }
}

/// Result of processing a file change.
#[derive(Debug, Clone)]
pub struct ReconcileResult {
    /// Number of new directives found in the external edit.
    pub new_directives: usize,
    /// Number of directives that were duplicates (already in DAG).
    pub duplicates: usize,
    /// Number of directives that failed validation.
    pub rejected: usize,
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_state_nonexistent() {
        let state = FileState::from_path(Path::new("/nonexistent/file.bean"));
        assert!(state.size.is_none());
        assert!(state.modified.is_none());
    }

    #[test]
    fn test_detect_change_unchanged() {
        let state = FileState {
            size: Some(100),
            modified: None,
            content_hash: None,
        };
        assert_eq!(state.detect_change(&state), FileChangeKind::Unchanged);
    }

    #[test]
    fn test_detect_change_created() {
        let old = FileState {
            size: None,
            modified: None,
            content_hash: None,
        };
        let new = FileState {
            size: Some(100),
            modified: None,
            content_hash: None,
        };
        assert_eq!(new.detect_change(&old), FileChangeKind::Created);
    }

    #[test]
    fn test_detect_change_deleted() {
        let old = FileState {
            size: Some(100),
            modified: None,
            content_hash: None,
        };
        let new = FileState {
            size: None,
            modified: None,
            content_hash: None,
        };
        assert_eq!(new.detect_change(&old), FileChangeKind::Deleted);
    }

    #[test]
    fn test_detect_change_size() {
        let old = FileState {
            size: Some(100),
            modified: None,
            content_hash: None,
        };
        let new = FileState {
            size: Some(200),
            modified: None,
            content_hash: None,
        };
        assert_eq!(new.detect_change(&old), FileChangeKind::Modified);
    }

    #[test]
    fn test_detect_change_mtime() {
        use std::time::{Duration, SystemTime};
        let t1 = SystemTime::now();
        let t2 = t1 + Duration::from_secs(1);
        let old = FileState {
            size: Some(100),
            modified: Some(t1),
            content_hash: None,
        };
        let new = FileState {
            size: Some(100),
            modified: Some(t2),
            content_hash: None,
        };
        assert_eq!(new.detect_change(&old), FileChangeKind::Modified);
    }

    #[test]
    fn test_detect_change_same_size_and_mtime_but_different_content() {
        // L7 regression: an in-place edit that preserves both size and mtime
        // (same coarse tick) must still be detected via the content hash.
        use std::time::SystemTime;
        let now = SystemTime::now();
        let old = FileState {
            size: Some(100),
            modified: Some(now),
            content_hash: Some([1u8; 32]),
        };
        let new = FileState {
            size: Some(100),
            modified: Some(now),
            content_hash: Some([2u8; 32]),
        };
        assert_eq!(new.detect_change(&old), FileChangeKind::Modified);
    }

    #[test]
    fn test_detect_change_identical_content_is_unchanged() {
        // Identical hash means identical bytes — unchanged even if mtime moved.
        use std::time::{Duration, SystemTime};
        let t1 = SystemTime::now();
        let old = FileState {
            size: Some(100),
            modified: Some(t1),
            content_hash: Some([9u8; 32]),
        };
        let new = FileState {
            size: Some(100),
            modified: Some(t1 + Duration::from_secs(5)),
            content_hash: Some([9u8; 32]),
        };
        assert_eq!(new.detect_change(&old), FileChangeKind::Unchanged);
    }

    #[test]
    fn test_from_path_detects_same_length_rewrite() {
        // End-to-end: overwrite a file with same-length different content and
        // confirm the state comparison flags a modification.
        let path = std::env::temp_dir().join(format!(
            "openledger-watcher-{}.bean",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "AAAA").unwrap();
        let before = FileState::from_path(&path);
        std::fs::write(&path, "BBBB").unwrap(); // same length, different bytes
        let after = FileState::from_path(&path);
        assert_eq!(after.detect_change(&before), FileChangeKind::Modified);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn test_default_config() {
        let config = FileWatcherConfig::default();
        assert!(!config.watch_enabled);
        assert_eq!(config.poll_interval, Duration::from_millis(1000));
    }

    #[test]
    fn test_watcher_handle_cancel() {
        let (handle, rx) = FileWatcherHandle::new();
        assert!(!*rx.borrow());
        handle.stop();
        assert!(rx.has_changed().unwrap());
    }

    #[test]
    fn test_reconcile_result_default() {
        let result = ReconcileResult {
            new_directives: 5,
            duplicates: 2,
            rejected: 1,
        };
        assert_eq!(result.new_directives, 5);
        assert_eq!(result.duplicates, 2);
        assert_eq!(result.rejected, 1);
    }

    /// M-29: a file past the ledger cap is `stat`ed and NOT read.
    ///
    /// `set_len` makes a sparse file, so this costs no disk: what is being
    /// asserted is that `from_path` never called `read`, which the absent
    /// content hash proves — a read would have produced one.
    #[test]
    fn m29_an_over_cap_file_is_not_read_into_memory() {
        let path = std::env::temp_dir().join(format!(
            "openledger-watcher-cap-{}.bean",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(crate::service::MAX_LEDGER_FILE_BYTES + 1)
            .unwrap();
        drop(file);

        let state = FileState::from_path(&path);
        assert_eq!(
            state.size,
            Some(crate::service::MAX_LEDGER_FILE_BYTES + 1),
            "the size still comes from the stat, so the change is still visible"
        );
        assert!(
            state.content_hash.is_none(),
            "M-29: an over-cap file must not be read on a runtime worker at 4 Hz"
        );
        assert!(state.modified.is_some());
        assert!(
            state.content_hash_hex().is_none(),
            "and it can never be mistaken for the node's own write"
        );

        // It is still a change, so the reconcile that follows is the one that
        // refuses it — with the error that names the cap.
        assert_eq!(
            state.detect_change(&FileState {
                size: Some(10),
                modified: None,
                content_hash: None,
            }),
            FileChangeKind::Modified
        );

        std::fs::remove_file(&path).ok();
    }

    /// M-29: a normal file is read, and its hash is offered in the spelling the
    /// service records.
    #[test]
    fn m29_content_hash_hex_is_lowercase_sha256_of_the_file() {
        let path = std::env::temp_dir().join(format!(
            "openledger-watcher-hash-{}.bean",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, "abc").unwrap();
        let state = FileState::from_path(&path);
        assert_eq!(
            state.content_hash_hex().unwrap(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::remove_file(&path).ok();
    }

    /// M-36: the watcher polls `from_path` on a runtime worker four times a
    /// second. A FIFO at the `.bean` passed the `stat` cap at length 0 and then
    /// blocked that worker in `std::fs::read`. It now returns at once, with no
    /// hash (the reconcile's `read_ledger_file` names the refusal).
    ///
    /// Bug-catch: read with `std::fs::read` again and this times out.
    #[cfg(unix)]
    #[test]
    fn m36_from_path_does_not_block_on_a_fifo() {
        let path = std::env::temp_dir().join(format!(
            "openledger-watcher-fifo-{}.bean",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let status = std::process::Command::new("mkfifo")
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
        let (sender, receiver) = std::sync::mpsc::channel();
        let polled = path.clone();
        std::thread::spawn(move || {
            let _ = sender.send(FileState::from_path(&polled));
        });
        let state = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("M-36: from_path blocked on a FIFO");
        assert!(state.content_hash.is_none(), "a FIFO is never hashed");
        std::fs::remove_file(&path).ok();
    }

    // ─── M-42 (T69): read only when the file may have changed ────────────

    /// Removes the fixture file when the test ends, pass or fail.
    struct Cleanup(PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            std::fs::remove_file(&self.0).ok();
        }
    }

    fn poller_fixture(name: &str, content: &str) -> (Cleanup, PathBuf) {
        let path = std::env::temp_dir().join(format!(
            "openledger-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, content).unwrap();
        (Cleanup(path.clone()), path)
    }

    /// Put the file's mtime an hour in the past, so a read of it is not racy.
    fn age(path: &Path) -> std::time::SystemTime {
        let old = std::time::SystemTime::now() - Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(old)
            .unwrap();
        old
    }

    /// M-42 KEY TEST: two consecutive polls of an unchanged file perform ONE
    /// read.
    ///
    /// Bug-catch: make `poll_with_key` read unconditionally (the pre-T69
    /// `from_path`-per-tick shape) and `reads()` is 2.
    #[test]
    fn m42_two_polls_of_an_unchanged_file_read_it_once() {
        let (_dir, path) = poller_fixture("m42-unchanged.bean", "2024-01-01 open Assets:Cash\n");
        age(&path);
        let mut poller = FilePoller::new(&path);
        let first = poller.poll();
        let second = poller.poll();
        assert_eq!(poller.reads(), 1, "M-42: the unchanged file was read again");
        assert_eq!(second.detect_change(&first), FileChangeKind::Unchanged);
        assert!(
            second.content_hash.is_some(),
            "the cached state keeps its hash"
        );
    }

    /// A change the `stat` identity shows is read at the very next poll.
    #[test]
    fn m42_a_changed_file_is_read_at_the_next_poll() {
        let (_dir, path) = poller_fixture("m42-changed.bean", "AAAA");
        age(&path);
        let mut poller = FilePoller::new(&path);
        let before = poller.poll();
        std::fs::write(&path, "AAAAAA").unwrap();
        let after = poller.poll();
        assert_eq!(poller.reads(), 2);
        assert_eq!(after.detect_change(&before), FileChangeKind::Modified);
    }

    /// L7 through the poller: a same-size rewrite whose mtime is then put
    /// back is still seen at the next poll — the ctime moved, and nothing can
    /// put that back.
    ///
    /// Bug-catch: drop the ctime from `StatKey` and the rewrite is cached as
    /// `Unchanged` (until the every-Nth backstop).
    #[cfg(unix)]
    #[test]
    fn m42_a_same_size_rewrite_with_its_mtime_restored_is_seen_at_the_next_poll() {
        let (_dir, path) = poller_fixture("m42-restored.bean", "AAAA");
        let old = age(&path);
        let mut poller = FilePoller::new(&path);
        let before = poller.poll();
        // ctime has 1 ns resolution on APFS/ext4, but make sure the clock has
        // visibly moved on a coarser filesystem too.
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&path, "BBBB").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let after = poller.poll();
        assert_eq!(
            poller.reads(),
            2,
            "the ctime changed, so the file was re-read"
        );
        assert_eq!(after.detect_change(&before), FileChangeKind::Modified);
    }

    /// The backstop: a rewrite `stat` cannot see at all (same size, same
    /// mtime, same ctime — a filesystem whose clock is behind ours) is still
    /// detected within `full_read_every` polls.
    ///
    /// Driven through the `poll_with_key` seam, holding the key still across
    /// a real rewrite, because no real filesystem will do that on demand.
    ///
    /// Bug-catch: drop the `due` arm and the rewrite is `Unchanged` forever.
    #[test]
    fn m42_a_rewrite_invisible_to_stat_is_caught_within_n_polls() {
        const N: u32 = 4;
        let (_dir, path) = poller_fixture("m42-invisible.bean", "AAAA");
        let key = StatKey::of(&std::fs::metadata(&path).unwrap());
        let later = std::time::SystemTime::now() + Duration::from_secs(3600);
        let mut poller = FilePoller::with_full_read_every(&path, N);
        let before = poller.poll_with_key(key, later);
        assert_eq!(poller.reads(), 1);

        std::fs::write(&path, "BBBB").unwrap();
        for poll in 1..N {
            let state = poller.poll_with_key(key, later);
            assert_eq!(
                state.detect_change(&before),
                FileChangeKind::Unchanged,
                "poll {poll}: cached while the key holds still"
            );
        }
        let caught = poller.poll_with_key(key, later);
        assert_eq!(poller.reads(), 2, "the Nth poll re-read");
        assert_eq!(caught.detect_change(&before), FileChangeKind::Modified);
    }

    /// A read taken while the file was freshly modified is racy and repeated
    /// at the next poll, so an edit inside the same timestamp granule is not
    /// left to the backstop.
    #[test]
    fn m42_a_read_of_a_freshly_written_file_is_repeated() {
        let (_dir, path) = poller_fixture("m42-racy.bean", "AAAA");
        let mut poller = FilePoller::new(&path);
        poller.poll();
        poller.poll();
        assert_eq!(poller.reads(), 2, "a racy read must be repeated");
    }

    /// The production backstop, spelled out: ~10 s at the node's 250 ms poll.
    #[test]
    fn m42_the_backstop_is_ten_seconds_at_the_node_cadence() {
        assert_eq!(
            Duration::from_millis(250) * FULL_READ_EVERY,
            Duration::from_secs(10)
        );
    }
}
