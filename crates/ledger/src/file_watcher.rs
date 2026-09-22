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
    pub fn from_path(path: &Path) -> Self {
        let Ok(metadata) = std::fs::metadata(path) else {
            return FileState {
                size: None,
                modified: None,
                content_hash: None,
            };
        };
        let modified = metadata.modified().ok();
        if metadata.len() > crate::service::MAX_LEDGER_FILE_BYTES {
            return FileState {
                size: Some(metadata.len()),
                modified,
                content_hash: None,
            };
        }
        // Read once and derive both size and hash from the same bytes so they
        // stay consistent. The `stat` above bounds the read.
        match std::fs::read(path) {
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
}
