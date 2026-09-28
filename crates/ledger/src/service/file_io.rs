//! The `.bean` on disk: the file marker, temporaries and their sweep, the atomic
//! persist, reading the file, and the leading-comment extraction.

use super::*;

/// Size + mtime of the canonical file as this service last saw it (T44).
///
/// The cheap half of the T35 hand-edit check: one `stat` per commit says
/// "nothing touched the `.bean`", which is all an append needs to know. The
/// exact half — re-read, re-hash, adopt — still runs, but only on the
/// compaction path, which is the only path that rewrites the file and therefore
/// the only one that could erase an edit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FileMarker {
    pub(super) length: u64,
    pub(super) modified: Option<std::time::SystemTime>,
}

impl FileMarker {
    /// `None` — "cannot vouch for it", which escalates the next commit to a
    /// compaction and its exact check — for anything that is not a regular
    /// file (T67): a FIFO's `stat` never changes, so a marker for one would
    /// report "untouched" forever. Only a `stat`, which cannot block.
    pub(super) fn of(path: &Path) -> Option<FileMarker> {
        let metadata = std::fs::metadata(path).ok()?;
        if !metadata.is_file() {
            return None;
        }
        Some(FileMarker {
            length: metadata.len(),
            modified: metadata.modified().ok(),
        })
    }
}

/// Infix of every temporary a full rewrite creates beside the ledger (L-57):
/// `<name>.tmp.<pid>.<nonce>`. The pre-T67 name was exactly `<name>.tmp`, which
/// [`sweep_stale_temporaries`] still recognises.
pub(super) const TEMPORARY_INFIX: &str = ".tmp";

/// A temp name nobody can pre-plant (L-57).
///
/// The fixed `<name>.tmp` let anyone who can write the ledger's directory put a
/// **directory** there: `create_new` failed `AlreadyExists`, `remove_file` then
/// failed `EISDIR`/`EPERM`, and every compaction, reconcile and the startup
/// compaction failed until an operator removed it. The name now carries the pid
/// and a per-call nonce (wall-clock nanoseconds mixed with a process-wide
/// counter — no new dependency, and nothing here needs to be unpredictable to a
/// local attacker: an `O_EXCL` collision just draws another name). No stale
/// entry is ever unlinked on this path; [`sweep_stale_temporaries`] does that
/// once, at boot.
pub(super) fn temporary_path_for(path: &Path, file_name: &std::ffi::OsStr) -> PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos() as u64)
        .unwrap_or(0);
    let nonce = nanos.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ sequence.rotate_left(40);
    path.with_file_name(format!(
        "{}{TEMPORARY_INFIX}.{}.{nonce:016x}",
        file_name.to_string_lossy(),
        std::process::id()
    ))
}

/// Is `name` a temporary [`persist_atomically`] could have left beside a
/// ledger whose file name is `ledger_name` (L-57, T78)?
///
/// Exactly two shapes — the **reserved** names beside a ledger:
///
/// * `<name>.tmp` — the fixed name every rewrite used before T67;
/// * `<name>.tmp.<pid>.<nonce>` — [`temporary_path_for`]'s: `<pid>` is
///   `std::process::id()` in decimal (1–10 ASCII digits, a `u32`), `<nonce>`
///   a `u64` formatted `{:016x}` (exactly 16 lowercase hex digits).
///
/// Before T78 the sweep matched `<name>.tmp.*`, so any same-uid file an
/// operator happened to name that way — `ledger.bean.tmp.backup`, say — was
/// deleted at the next boot (0923 audit §5).
pub(super) fn is_reserved_temporary_name(name: &str, ledger_name: &str) -> bool {
    let Some(rest) = name
        .strip_prefix(ledger_name)
        .and_then(|rest| rest.strip_prefix(TEMPORARY_INFIX))
    else {
        return false;
    };
    if rest.is_empty() {
        return true;
    }
    let Some((pid, nonce)) = rest.strip_prefix('.').and_then(|rest| rest.split_once('.')) else {
        return false;
    };
    (1..=10).contains(&pid.len())
        && pid.bytes().all(|byte| byte.is_ascii_digit())
        && nonce.len() == 16
        && nonce
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Clear what an older build's crashed rewrites left beside a ledger LINK
/// (`<link>.tmp.*`) — before T82 temporary files sat beside the link, and since
/// then nothing else ever removes them (T94 / L-118). A no-op unless
/// `configured` is a link that resolved elsewhere.
///
/// `boot_with` does this for a caller that hands it the link's path, but
/// `gl-node` resolves the link first and boots the TARGET, so inside the boot
/// the two paths are equal and T87's sweep never ran on the node. `gl-node`
/// calls this after taking the ledger lock, as the boot's own sweep runs.
pub fn sweep_temporaries_beside_the_link(configured: &Path, resolved: &Path) {
    if configured != resolved {
        // T101 / L-139: never the link's own target — an operator may name
        // the real file `<link>.tmp` beside the link, and the sweep deleted
        // it, so boot started an empty ledger.
        sweep_stale_temporaries(configured, Some(resolved));
    }
}

/// Remove the temporaries crashed rewrites left beside `path` (L-57).
///
/// Runs once, from a process-start boot — under `gl-node` that is after
/// `ledger_lock::acquire`, so no sibling process can be mid-persist on this
/// ledger and every match is a crashed leftover. Matches only the reserved
/// names [`is_reserved_temporary_name`] defines — `<name>.tmp` (the pre-T67
/// fixed name) and `<name>.tmp.<pid>.<16 hex>` — never any other
/// `<name>.tmp.*` (T78). Removes only what a crashed persist
/// could have left: a regular file or a symlink, owned by this uid. Anything
/// else — a directory, a FIFO, a file another account owns — is logged and
/// left alone: it is not ours to delete, and it no longer blocks a write,
/// because writes never reuse a name. Best effort: a failure here never fails
/// the boot. (Library users that run several writers on one ledger without
/// that lock keep the pre-T30 exposure, as `persist_atomically` documents.)
pub(super) fn sweep_stale_temporaries(path: &Path, keep: Option<&Path>) {
    let Some(file_name) = path.file_name() else {
        return;
    };
    #[cfg(unix)]
    let kept = keep
        .and_then(|keep| std::fs::metadata(keep).ok())
        .map(|metadata| {
            use std::os::unix::fs::MetadataExt;
            (metadata.dev(), metadata.ino())
        });
    #[cfg(not(unix))]
    let _ = keep;
    let ledger_name = file_name.to_string_lossy();
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let Ok(entries) = std::fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !is_reserved_temporary_name(&name, &ledger_name) {
            continue;
        }
        let candidate = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&candidate) else {
            continue;
        };
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if kept == Some((metadata.dev(), metadata.ino())) {
                info!(
                    path = %candidate.display(),
                    "an entry named like a ledger temporary file is the ledger itself (the \
                     target of the ledger link); leaving it alone (L-139)"
                );
                continue;
            }
        }
        let file_type = metadata.file_type();
        #[cfg(unix)]
        let ours = {
            use std::os::unix::fs::MetadataExt;
            metadata.uid() == crate::journal::effective_uid()
        };
        #[cfg(not(unix))]
        let ours = true;
        if (file_type.is_file() || file_type.is_symlink()) && ours {
            // `remove_file` unlinks the entry itself, never a link's target.
            match std::fs::remove_file(&candidate) {
                Ok(()) => info!(
                    path = %candidate.display(),
                    "removed a temporary file left by an interrupted ledger rewrite (L-57)"
                ),
                Err(error) => warn!(
                    path = %candidate.display(),
                    %error,
                    "could not remove a stale ledger temporary file (L-57)"
                ),
            }
        } else {
            warn!(
                path = %candidate.display(),
                "an entry named like a ledger temporary file is not a file this node could \
                 have left (a directory, a special file, or another account's); leaving it \
                 alone — it no longer blocks writes, but remove it if you do not recognise \
                 it (L-57)"
            );
        }
    }
}

/// Write `content` via a sibling temp file, fsync, then POSIX rename (H-10 / CAP-1).
pub(super) fn persist_atomically(path: &Path, content: &str) -> Result<(), std::io::Error> {
    if content.len() as u64 > MAX_LEDGER_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "ledger content is {} bytes (max {MAX_LEDGER_FILE_BYTES})",
                content.len()
            ),
        ));
    }

    let file_name = path.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "ledger path has no file name",
        )
    })?;

    let mut options = std::fs::OpenOptions::new();
    // `create_new` sets O_CREAT|O_EXCL, which refuses to open (and therefore
    // to follow) anything already at the temp name — a pre-planted symlink
    // included — closing the race where a persist would truncate a link's
    // target.
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    // L-57: a fresh name per call, and on the (astronomically unlikely, or
    // planted) collision another fresh name — never an unlink of whatever is
    // there. Eight draws bound the loop; exhausting them means something is
    // creating these names on purpose, and the write fails loudly.
    let mut attempts = 0;
    let (temporary_path, mut file) = loop {
        let candidate = temporary_path_for(path, file_name);
        match options.open(&candidate) {
            Ok(file) => break (candidate, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists && attempts < 8 => {
                attempts += 1;
            }
            Err(error) => return Err(error),
        }
    };

    // From here on the temp is ours; a failure removes it, so a failing write
    // does not leave one behind per attempt now that names are never reused.
    let written = write_temporary(&mut file, content).and_then(|()| {
        drop(file);
        std::fs::rename(&temporary_path, path)
    });
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temporary_path);
        return Err(error);
    }

    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    if let Ok(directory_file) = std::fs::File::open(directory) {
        let _ = directory_file.sync_all();
    }
    Ok(())
}

/// Fill, chmod and fsync the temp `persist_atomically` created.
pub(super) fn write_temporary(
    file: &mut std::fs::File,
    content: &str,
) -> Result<(), std::io::Error> {
    file.write_all(content.as_bytes())?;

    // L-44: pin the mode through the HANDLE (`fchmod`), before the rename.
    // `mode(0o600)` above is masked by the process umask, which can only
    // clear bits, so an exact 0600 still needs a chmod — but this used to
    // be `std::fs::metadata(path)` + `std::fs::set_permissions(path)` AFTER
    // the rename, and both follow symlinks. Anyone who can write the
    // ledger's directory could swap a symlink in at `path` between the
    // rename and the chmod and have the node chmod an arbitrary target to
    // 0600 — as root, in the shipped container. The handle names the inode
    // this function created with O_EXCL and nothing else, and the rename
    // moves that same inode into place, so the mode lands on exactly the
    // file that becomes the ledger. The key writer in `gl-node`'s
    // `p2p_service.rs` (L-32) does the same, for the same reason.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o600);
        file.set_permissions(permissions)?;
    }

    // After the chmod, so the mode change is covered by the same fsync
    // that makes the bytes durable.
    file.sync_all()
}

/// Read the ledger file, capped at [`MAX_LEDGER_FILE_BYTES`], with a leading
/// UTF-8 BOM stripped (L-28).
///
/// The BOM is removed here rather than only inside [`parse_file`] because boot
/// also runs `extract_leading_comments` and an emptiness check over this string,
/// and because every hash this module records for a ledger file
/// ([`LedgerService::last_file_hash`]) must be taken over the BOM-free form —
/// otherwise a BOM'd-but-otherwise-identical file would read as a hand edit and
/// trigger a pointless reconcile on the next persist.
///
/// # What may be read (T67, M-36)
///
/// The open is [`crate::journal::open_checked`] with
/// [`crate::journal::FileTrust::OperatorLedger`]: a regular file, or a symlink
/// whose target is one — never a FIFO, device, socket or directory, and never
/// through a blocking `open`. This used to be `metadata().len()` then
/// `read_to_string`: a FIFO has length 0, passed the cap, and then either
/// blocked the caller forever (under the ledger write lock, on the compaction
/// path) or streamed past the cap (73 MB loaded through 64 MiB). The size is
/// now checked on the handle and enforced again by the read itself, through
/// `take(MAX + 1)`. A missing file is still `NotFound` — the H-15 callers
/// depend on telling absence from every other failure.
pub(super) fn read_ledger_file(path: &Path) -> Result<String, ServiceError> {
    let checked = crate::journal::open_checked(
        path,
        std::fs::OpenOptions::new().read(true),
        crate::journal::FileTrust::OperatorLedger,
        "ledger file",
    )?;
    let over_cap = |length: String| ServiceError::ResourceLimitExceeded {
        message: format!("ledger file is {length} bytes (max {MAX_LEDGER_FILE_BYTES})"),
    };
    let length = checked.metadata.len();
    if length > MAX_LEDGER_FILE_BYTES {
        return Err(over_cap(length.to_string()));
    }
    let bytes =
        match crate::journal::read_to_end_capped(&checked.file, length, MAX_LEDGER_FILE_BYTES) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::FileTooLarge => {
                return Err(over_cap(format!("more than {MAX_LEDGER_FILE_BYTES}")));
            }
            Err(error) => return Err(ServiceError::Io(error)),
        };
    // Same error `read_to_string` gave for non-UTF-8 content.
    let content = String::from_utf8(bytes).map_err(|_| {
        ServiceError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "stream did not contain valid UTF-8",
        ))
    })?;
    Ok(match content.strip_prefix(crate::parse::BYTE_ORDER_MARK) {
        Some(stripped) => stripped.to_owned(),
        None => content,
    })
}

/// SHA-256 (lowercase hex) of the exact ledger-file bytes, as read or written.
///
/// This is deliberately a hash of the *file*, not of any directive: it answers
/// only "is what is on disk still the text this service last wrote or read?"
/// (L-30).
pub(super) fn file_content_hash(content: &str) -> String {
    let digest = Sha256::digest(content.as_bytes());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

// ─── Comment extraction ──────────────────────────────────────────────────────

/// Extract leading `;` comments from the beginning of a file (before any directive).
pub(super) fn extract_leading_comments(content: &str) -> Vec<String> {
    let mut comments = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(comment) = trimmed.strip_prefix(';') {
            comments.push(comment.trim().to_owned());
        } else {
            break; // First non-comment, non-blank line = start of directives.
        }
    }
    comments
}
