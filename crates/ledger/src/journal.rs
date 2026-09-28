//! Append-only commit journal — the node-private sidecar that makes persisting
//! one directive cost O(directive) instead of O(ledger) (T44).
//!
//! # Why this file exists
//!
//! Until T44 every mutation ran `full_file_serialize` over the whole DAG and
//! rewrote the entire `.bean` through a temp+rename+fsync. That is O(current
//! size) per write, and T27's batching only amortised it per *batch*: a
//! thousand-directive ledger still paid a thousand-directive rewrite to record
//! one new transaction. The canonical file cannot simply be appended to,
//! because its atomicity (H-10 / CAP-1: write a sibling `.tmp`, fsync, rename)
//! is what guarantees that a crash never leaves a half-written `.bean` — and a
//! torn `.bean` is a **boot brick**, since boot fails closed on a parse error.
//!
//! So the durable write goes somewhere a torn tail is survivable: a sidecar
//! journal that only this node reads, whose last record can be dropped with a
//! warning because a record torn by a crash is one whose commit never returned
//! success to a caller. (Only a crash, though: the same bytes can be produced
//! by truncating or editing the file, which is why the policy below keeps them
//! — M-43.)
//!
//! # File layout
//!
//! `<ledger>.bean` keeps its exact format and its exact atomic write path.
//! `<ledger>.bean.journal` holds the directives that are durable but not yet
//! folded into the canonical file. The pair is unioned at boot; compaction
//! rewrites the canonical file from memory and then deletes the journal —
//! except after a boot that dropped a torn tail, when the compaction renames
//! it to `<ledger>.bean.journal.torn-<unix-seconds>` instead (M-43), a sidecar
//! no later boot reads.
//!
//! # Opening the files (T67)
//!
//! Every ledger-side open — this journal (read and append), the canonical
//! `.bean`, the watcher's read, `gl-node`'s `.lock` and its key file — goes
//! through [`open_checked`]: `lstat` → regular file → `open(O_NOFOLLOW |
//! O_NONBLOCK)` → `fstat` the handle → same `(dev, ino)`, and for node-owned
//! files the owner, link count and mode. A FIFO can no longer park the thread
//! that holds the write permit, a symlink is never followed, and reads go
//! through [`read_to_end_capped`] so a file that grows past its budget between
//! the `fstat` and the read is refused rather than read.
//!
//! # Record format
//!
//! ```text
//! ;;olj <payload-byte-length> <sha256-of-payload-hex>\n
//! <payload bytes>
//! ```
//!
//! The payload is exactly `full_file_serialize(&directives, &[])` for the
//! directives of one commit — the same canonical spelling the `.bean` file
//! uses, so a record's bytes are byte-identical to the slice of the canonical
//! file those directives will eventually occupy, and boot can simply
//! concatenate canonical + payloads and hand the result to `parse_file`.
//!
//! Three properties matter and each is bought by one field:
//!
//! * **`;;olj`** — a `;` line is a Beancount comment, so a journal that someone
//!   concatenates onto a ledger by accident degrades to comments plus
//!   directives rather than to a parse error. It is also an unmistakable
//!   marker when an operator opens the file.
//! * **the length** — tells a torn tail (fewer bytes present than claimed) from
//!   corruption (enough bytes, wrong content). Without it the two are the same
//!   observation and the scanner has to guess.
//! * **the hash** — makes "enough bytes, wrong content" detectable at all.
//!   Length alone would accept a record whose middle was overwritten. It is an
//!   **unkeyed checksum**, not an authenticator: it catches bit rot and
//!   accidents, and anyone who can write the journal can recompute it. The
//!   journal's integrity against a writer rests on the file checks in
//!   [`open_checked`] (owner, link count, mode), not on this field.
//!
//! # Failure policy (T44 hard invariant 4, M-43, M-44)
//!
//! * A **torn final record** is dropped with a `warn!` and the caller is told,
//!   so it can force the next commit to compact (appending *after* a torn
//!   record would let the scanner read payload bytes as a header, so this is
//!   not merely tidiness). Torn means exactly one of:
//!   - the file ends inside a header line;
//!   - the file ends inside a payload whose header promised more bytes than
//!     are present, **and** the claim is within the journal budget, **and** no
//!     later record header (`;;olj ` at a line start) follows in the remainder.
//!     A node-written payload contains neither an over-budget claim nor a
//!     line starting `;;olj ` (control characters are refused in every string
//!     field and a record carries no comments), so a remainder holding either
//!     is a record in the MIDDLE of the file whose length was damaged — it
//!     fails closed, naming the offset (M-43 / R-18). Before T68 it was
//!     classified torn, every later record was silently dropped, and the
//!     startup compaction erased them;
//!   - the **final** record's payload is complete by length but fails its
//!     checksum, and no *intact* record (a `;;olj ` line whose claimed bytes
//!     follow it and match its hash) starts inside it (T78). A metadata-first
//!     filesystem that loses power between `write_all` and `sync_all` can
//!     persist the new length without the data: XFS exposes the region as
//!     zeros (M-44's original, NUL-only rule), ext4 `data=writeback` as
//!     whatever the reused blocks held before — typically an older, folded
//!     journal's text, with no NUL and possibly with stale `;;olj ` lines cut
//!     at block boundaries (0923 audit §5; the byte shape is executed, a real
//!     ext4 crash was not). An intact record inside the region means this
//!     record's length was damaged to swallow records appended after it — a
//!     crash cannot do that (M-43) — so that case still fails closed. A
//!     header line holding NUL with no later record header is the zero-fill
//!     artefact one block earlier.
//! * **Anything else fails closed**: a complete-but-malformed header, a
//!   **non-final** payload whose checksum does not match, a payload that is
//!   not UTF-8, a journal larger than the budget. A crash does not produce
//!   these — a hand edit or real corruption does — and the ledger refuses to
//!   boot on top of them rather than silently discarding directives it was
//!   told were durable. (Residual: a crash whose stale bytes land in a
//!   *header* line rather than a payload reads as a malformed header and
//!   fails closed; so does a stale block that happens to hold one whole old
//!   record.)
//!
//! The torn rule is a heuristic about bytes, so the bytes it drops are never
//! destroyed on its strength: see the `.torn-*` rename above. That is also
//! why widening it (T78) gives a journal writer nothing: whoever can make the
//! final record fail its checksum can truncate the file, which was always a
//! torn tail; either way the record is dropped from memory with a warning and
//! its bytes are kept in the sidecar. What the widening costs is a final
//! record damaged *after* its commit returned (bit rot on the last record):
//! it now boots without that record, loudly, instead of refusing to boot —
//! the "rename, never unlink" policy keeps it recoverable, and a replicated
//! record is re-supplied by peers.
//!
//! **Hand-editing the journal is unsupported.** It is node-private state, not
//! an interchange format; the supported way to hand-edit a ledger is the
//! canonical `.bean`, which the T35 adoption path merges in. An edit that
//! changes a record's bytes without recomputing its checksum fails closed; one
//! that recomputes it is not detected here at all (see the checksum note).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// Header tag opening every journal record.
const RECORD_TAG: &str = ";;olj";

/// Sidecar extension appended to the ledger path (`ledger.bean` →
/// `ledger.bean.journal`), matching the `<ledger>.lock` convention T30 uses.
const JOURNAL_EXTENSION: &str = "journal";

/// The path the node works at for a configured ledger path (T82 / L-84,
/// decision (11)): the configured path itself, or — when it is a symbolic
/// link this node's own user created — the file it points to.
///
/// T67 followed a symlinked `.bean` to READ it but derived the journal, the
/// lock and the temp files from the link's path, and the first compaction
/// renamed a regular file over the link. So the target's own journal was
/// never read (an acknowledged record silently missing) and the operator's
/// link — a ledger kept on another volume — was undone with no warning.
/// Resolving the link once, at boot, and working at the target from then on
/// fixes both: journal, lock and temp files sit beside the target, and every
/// compaction writes the target in place.
///
/// Only a link owned by this process's effective uid is followed. Whoever can
/// write the ledger's DIRECTORY (threat (e)) could otherwise plant
/// `ledger.bean -> <any file this user owns>` and have the next compaction
/// overwrite it; another account cannot create a link this uid owns. A link
/// owned by anyone else is an error. A dangling link, or one whose target
/// cannot be resolved, is returned unresolved, and the ledger's checked open
/// refuses it exactly as before (T67). Resolved once: a link planted after
/// boot is replaced by the next compaction, never followed (L-44).
///
/// T87 / M-60, decision (24): the owner check reads one inode and the follow
/// walks the path again, so an account that can write the link's directory
/// could rename its own link over this user's between the two. The link is
/// therefore followed only when **its directory** is owned by this uid and is
/// not writable by group or others — then no other account can replace it,
/// and the check and the follow see the same link. And it is followed **one
/// hop**: a link whose target is itself a link is refused, since that second
/// link's owner was never checked (a directory link in either path is
/// followed, by policy — the node stays consistent under it). A link that
/// passes resolves to its target as before.
///
/// T87 / M-61, decision (25): a journal beside the LINK is refused. The node
/// derives its journal from the target, so `<link>.journal` — left by an
/// unclean stop before the ledger was moved behind a link — would never be
/// read, folded or renamed, and its acknowledged records would be silently
/// absent (H-15's precedent: refuse rather than lose them).
pub fn resolve_ledger_path(configured: &Path) -> std::io::Result<PathBuf> {
    let Ok(metadata) = std::fs::symlink_metadata(configured) else {
        return Ok(configured.to_path_buf());
    };
    if !metadata.file_type().is_symlink() {
        return Ok(configured.to_path_buf());
    }
    let link_directory = match configured.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    #[cfg(unix)]
    let resolved = match resolve_link_in_its_directory(configured, &link_directory)? {
        Some(resolved) => resolved,
        None => return Ok(configured.to_path_buf()),
    };
    #[cfg(not(unix))]
    let Ok(resolved) = std::fs::canonicalize(configured) else {
        return Ok(configured.to_path_buf());
    };
    let stray_journal = journal_path_for(configured);
    if resolved != configured && std::fs::symlink_metadata(&stray_journal).is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "a journal {} sits beside the ledger link {}, but this node journals at its \
                 target {} and would never read it: it belongs to the ledger that was at the \
                 link's path before it became a link, and may hold acknowledged records. Move \
                 it beside the target as {} (if the target has no journal of its own), or put \
                 the ledger back at {} and start the node once so it folds the journal in, then \
                 make the link (M-61, H-15)",
                stray_journal.display(),
                configured.display(),
                resolved.display(),
                journal_path_for(&resolved).display(),
                configured.display()
            ),
        ));
    }
    Ok(resolved)
}

/// The checks of [`resolve_ledger_path`] on a link, every one of them bound to
/// ONE open handle on the link's directory (T94 / M-68, decision (46)).
///
/// T87 read the directory's owner and mode by path, then followed the link by
/// path again: an account able to write any ANCESTOR of that directory could
/// swap the whole directory — `renameat2(RENAME_EXCHANGE)` / `renamex_np(
/// RENAME_SWAP)` — between the two, so the rule approved the operator's
/// directory and the follow used the attacker's link (A4: ~250 hits in 5 s;
/// the next compaction then rewrote any file the node's uid owns). Here the
/// directory is opened once and the link's owner (`fstatat`, not following),
/// its target (`readlinkat`) and the target itself (`openat` with
/// `O_NOFOLLOW`, which also enforces the one hop: a target that is itself a
/// link fails with `ELOOP`) are all read relative to that handle, whatever
/// the path names by then. The path the node will use is `canonicalize` of
/// the configured one, accepted only when it is the SAME file — `(dev, ino)`
/// — as the one opened through the handle: a swap in between makes them
/// differ and refuses, and a target whose spelling differs from its on-disk
/// name only in case or Unicode normalisation (T87's string compare refused
/// it, L-119) is the same file and resolves.
///
/// `Ok(None)`: the link cannot be followed to anything (dangling, or its
/// target cannot be opened) — the caller returns the configured path and the
/// ledger's checked open refuses it (T67).
#[cfg(unix)]
fn resolve_link_in_its_directory(
    configured: &Path,
    link_directory: &Path,
) -> std::io::Result<Option<PathBuf>> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;

    let refuse =
        |message: String| std::io::Error::new(std::io::ErrorKind::PermissionDenied, message);
    let Some(name) = configured.file_name() else {
        return Ok(None);
    };
    let name = CString::new(name.as_bytes())?;
    let this_uid = effective_uid();

    // T101 / L-138: `O_DIRECTORY | O_NONBLOCK`, so whatever sits at the path
    // by now — a FIFO an ancestor's writer swapped in — fails at once
    // (`ENOTDIR`) instead of blocking boot before the lock, silently. T87 only
    // `stat`ed the directory and could not hang.
    let directory = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NONBLOCK)
            .open(link_directory)?
    };
    let directory_metadata = directory.metadata()?;
    let mode = directory_metadata.mode() & 0o7777;
    if directory_metadata.uid() != this_uid || mode & 0o022 != 0 {
        return Err(refuse(format!(
            "ledger path {} is a symbolic link in {}, a directory {}; another account \
             could replace the link between this node's check and its use, so it is not \
             followed — keep the link in a directory only this node's user (uid {this_uid}) \
             can write, or point ledgerPath at the real file (M-60)",
            configured.display(),
            link_directory.display(),
            if directory_metadata.uid() != this_uid {
                format!("owned by uid {}", directory_metadata.uid())
            } else {
                format!("with mode {mode:o}, writable by group or others")
            }
        )));
    }
    // T94 / L-120, decision (47): on macOS an ACL can let other accounts add
    // and remove entries in a directory whose mode bits say they cannot (on
    // Linux a POSIX ACL shows in the group bits the check above reads).
    // T101 / L-137, decision (65): only an entry that does — an allow entry,
    // in force on the directory itself, granting add-file, add-subdirectory,
    // delete-child, write-security or change-owner. Any ACL at all was refused
    // before, macOS's own `group:everyone deny delete` on `~`, `~/Documents`,
    // `~/Desktop` and `~/Downloads` included, and the `chmod -N` remedy
    // stripped that protection from the home folder.
    #[cfg(target_os = "macos")]
    if directory_acl_lets_others_write(&directory) {
        return Err(refuse(format!(
            "ledger path {} is a symbolic link in {}, a directory whose access control list \
             (ls -le shows it) lets an account add or remove entries in it; that account could \
             replace the link, so it is not followed — remove that entry (chmod -a), keep the \
             link in a directory only this node's user can write, or point ledgerPath at the \
             real file (M-60, L-120, L-137)",
            configured.display(),
            link_directory.display()
        )));
    }

    let link = stat_at(&directory, &name, libc::AT_SYMLINK_NOFOLLOW)?;
    if link.st_mode & libc::S_IFMT != libc::S_IFLNK {
        return Err(refuse(format!(
            "ledger path {} changed while it was being checked (it is no longer the link that \
             was resolved); refusing to follow it (M-68)",
            configured.display()
        )));
    }
    if link.st_uid != this_uid {
        return Err(refuse(format!(
            "ledger path {} is a symbolic link owned by uid {}, not by this node's uid \
             {this_uid}; a ledger link is followed only when this node's own user created it — \
             point ledgerPath at the real file, or recreate the link as this user (L-84)",
            configured.display(),
            link.st_uid
        )));
    }
    let target = read_link_at(&directory, &name)?;
    let target_file = match open_at_no_follow(&directory, &target) {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(refuse(format!(
                "ledger path {} is a symbolic link to {}, which is itself a symbolic link; only \
                 one link is followed, since the second one's owner was never checked — point \
                 the link (or ledgerPath) at the real file (M-60)",
                configured.display(),
                String::from_utf8_lossy(target.as_bytes())
            )));
        }
        Err(_) => return Ok(None),
    };
    let opened = target_file.metadata()?;
    let Ok(resolved) = std::fs::canonicalize(configured) else {
        return Ok(None);
    };
    let at_path = std::fs::metadata(&resolved)?;
    if (at_path.dev(), at_path.ino()) != (opened.dev(), opened.ino()) {
        return Err(refuse(format!(
            "ledger path {} does not lead to the file its link names when followed through the \
             link's own directory (it resolves to {}): the link or a directory above it changed \
             while it was being checked; refusing to follow it (M-68)",
            configured.display(),
            resolved.display()
        )));
    }
    // T101 / M-71, decision (64): and it is that file IN the directory the link
    // names. A hard link elsewhere has the same `(dev, ino)`: with the link's
    // directory swapped for another between the handle and `canonicalize`, the
    // second walk followed the other directory's link to a hard link of the
    // target inside a directory no check had seen — one its owner writes —
    // and the node then compacted, journalled and read there (A5-1). The
    // target's directory, reached through the handle, must be the directory
    // of the returned path.
    let target_bytes = target.as_bytes();
    let target_directory: &[u8] = match target_bytes.iter().rposition(|&byte| byte == b'/') {
        Some(0) => b"/",
        Some(index) => &target_bytes[..index],
        None => b".",
    };
    let named = stat_at(&directory, &CString::new(target_directory)?, 0)?;
    let Some(parent) = resolved.parent() else {
        return Ok(None);
    };
    let at_parent = std::fs::metadata(parent)?;
    if (at_parent.dev(), at_parent.ino()) != (named.st_dev as u64, named.st_ino as u64) {
        return Err(refuse(format!(
            "ledger path {} resolves to {}, which is not in the directory its link names: a \
             directory above the link changed while it was being checked; refusing to follow it \
             (M-68, M-71)",
            configured.display(),
            resolved.display()
        )));
    }
    Ok(Some(resolved))
}

/// `fstatat(directory, name, flags)` (T94 / M-68).
#[cfg(unix)]
fn stat_at(
    directory: &std::fs::File,
    name: &std::ffi::CStr,
    flags: libc::c_int,
) -> std::io::Result<libc::stat> {
    use std::os::unix::io::AsRawFd;
    let mut buffer = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `directory` is an open descriptor for the duration of the call,
    // `name` is a NUL-terminated string, and `buffer` is a properly aligned
    // `stat` the kernel fills in full on success; it is read only then.
    unsafe {
        if libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            buffer.as_mut_ptr(),
            flags,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
        Ok(buffer.assume_init())
    }
}

/// `readlinkat(directory, name)` (T94 / M-68).
#[cfg(unix)]
fn read_link_at(
    directory: &std::fs::File,
    name: &std::ffi::CStr,
) -> std::io::Result<std::ffi::CString> {
    use std::os::unix::io::AsRawFd;
    let mut buffer = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: `directory` is open, `name` is NUL-terminated, and the kernel
    // writes at most `buffer.len()` bytes into `buffer`, returning how many.
    let length = unsafe {
        libc::readlinkat(
            directory.as_raw_fd(),
            name.as_ptr(),
            buffer.as_mut_ptr().cast::<libc::c_char>(),
            buffer.len(),
        )
    };
    if length < 0 {
        return Err(std::io::Error::last_os_error());
    }
    buffer.truncate(length as usize);
    Ok(std::ffi::CString::new(buffer)?)
}

/// `openat(directory, path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC)`,
/// as an owned file (T94 / M-68). Relative paths resolve from `directory`;
/// a final component that is a symbolic link fails with `ELOOP`.
#[cfg(unix)]
fn open_at_no_follow(
    directory: &std::fs::File,
    path: &std::ffi::CStr,
) -> std::io::Result<std::fs::File> {
    use std::os::unix::io::{AsRawFd, FromRawFd};
    // SAFETY: `directory` is open and `path` is NUL-terminated; on success the
    // returned descriptor is new and owned by nobody else, so the `File` takes
    // sole ownership of it and closes it on drop.
    unsafe {
        let descriptor = libc::openat(
            directory.as_raw_fd(),
            path.as_ptr(),
            // T101: `O_NOCTTY` — a link the operator points at a terminal must
            // not make it this process's controlling terminal.
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC,
        );
        if descriptor < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(std::fs::File::from_raw_fd(descriptor))
    }
}

/// Whether the directory's extended (NFSv4-style) ACL lets some account add
/// or remove entries in it (T94 / L-120; T101 / L-137, decision (65); macOS
/// only — see [`resolve_link_in_its_directory`]): an allow entry, not
/// inherit-only, granting add-file, add-subdirectory, delete-child,
/// write-security or change-owner. A deny entry, an entry that only children
/// inherit, and an allow entry granting only reads are not refused — macOS's
/// default `group:everyone deny delete` on the home folders among them.
#[cfg(target_os = "macos")]
fn directory_acl_lets_others_write(directory: &std::fs::File) -> bool {
    use std::os::unix::io::AsRawFd;
    // <sys/acl.h>.
    const ACL_TYPE_EXTENDED: libc::c_int = 0x0000_0100;
    const ACL_FIRST_ENTRY: libc::c_int = 0;
    const ACL_NEXT_ENTRY: libc::c_int = -1;
    const ACL_EXTENDED_ALLOW: libc::c_int = 1;
    const ACL_ENTRY_ONLY_INHERIT: libc::c_int = 1 << 8;
    const LETS_ANOTHER_REPLACE_THE_LINK: [libc::c_int; 5] = [
        1 << 2,  // ACL_ADD_FILE
        1 << 5,  // ACL_ADD_SUBDIRECTORY
        1 << 6,  // ACL_DELETE_CHILD
        1 << 12, // ACL_WRITE_SECURITY
        1 << 13, // ACL_CHANGE_OWNER
    ];
    extern "C" {
        fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
        fn acl_get_entry(
            acl: *mut libc::c_void,
            entry_id: libc::c_int,
            entry: *mut *mut libc::c_void,
        ) -> libc::c_int;
        fn acl_get_tag_type(entry: *mut libc::c_void, tag: *mut libc::c_int) -> libc::c_int;
        fn acl_get_flagset_np(
            entry: *mut libc::c_void,
            flags: *mut *mut libc::c_void,
        ) -> libc::c_int;
        fn acl_get_flag_np(flags: *mut libc::c_void, flag: libc::c_int) -> libc::c_int;
        fn acl_get_permset(entry: *mut libc::c_void, perms: *mut *mut libc::c_void) -> libc::c_int;
        fn acl_get_perm_np(perms: *mut libc::c_void, perm: libc::c_int) -> libc::c_int;
        fn acl_free(object: *mut libc::c_void) -> libc::c_int;
    }
    // SAFETY: libSystem's documented ACL calls on an open descriptor. The ACL
    // returned (non-null) is owned here and freed exactly once; the entries,
    // flag sets and permission sets are views into it, read only while it is
    // alive, and every out-pointer is a local written by the call before use.
    unsafe {
        let acl = acl_get_fd_np(directory.as_raw_fd(), ACL_TYPE_EXTENDED);
        if acl.is_null() {
            return false;
        }
        let mut lets_write = false;
        let mut entry: *mut libc::c_void = std::ptr::null_mut();
        let mut which = ACL_FIRST_ENTRY;
        while !lets_write && acl_get_entry(acl, which, &mut entry) == 0 {
            which = ACL_NEXT_ENTRY;
            let mut tag: libc::c_int = 0;
            if acl_get_tag_type(entry, &mut tag) != 0 || tag != ACL_EXTENDED_ALLOW {
                continue;
            }
            let mut flags: *mut libc::c_void = std::ptr::null_mut();
            if acl_get_flagset_np(entry, &mut flags) == 0
                && acl_get_flag_np(flags, ACL_ENTRY_ONLY_INHERIT) == 1
            {
                continue;
            }
            let mut perms: *mut libc::c_void = std::ptr::null_mut();
            if acl_get_permset(entry, &mut perms) != 0 {
                // Unreadable: refuse, as T94 refused every entry.
                lets_write = true;
                continue;
            }
            lets_write = LETS_ANOTHER_REPLACE_THE_LINK
                .iter()
                .any(|perm| acl_get_perm_np(perms, *perm) == 1);
        }
        acl_free(acl);
        lets_write
    }
}

/// The journal path for a ledger file.
pub fn journal_path_for(ledger_path: &Path) -> PathBuf {
    let file_name = ledger_path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "ledger.bean".to_owned());
    ledger_path.with_file_name(format!("{file_name}.{JOURNAL_EXTENSION}"))
}

/// Why a journal could not be read.
#[derive(Debug)]
pub enum JournalError {
    /// The journal is longer than the caller's budget.
    TooLarge {
        /// Size of the journal on disk, in bytes.
        length: u64,
        /// Budget the caller allowed, in bytes.
        budget: u64,
    },
    /// A structurally invalid record that a crash cannot produce.
    Corrupt {
        /// Byte offset of the record the scan refused.
        offset: u64,
        /// What was wrong.
        reason: String,
    },
    /// The journal could not be read at all.
    Io(std::io::Error),
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalError::TooLarge { length, budget } => {
                // M-35: the one shape that produces this on a node nobody
                // touched is a compaction that crashed between the `.bean`
                // rename and the journal removal — the journal is then older
                // than the `.bean` and every record in it is already folded in.
                write!(
                    f,
                    "ledger journal is {length} bytes (max {budget}); a journal older than the \
                     .bean it sits beside may be the leftover of a compaction that crashed before \
                     removing it, in which case its records are already folded into the .bean \
                     (M-35)"
                )
            }
            JournalError::Corrupt { offset, reason } => {
                write!(f, "ledger journal is corrupt at byte {offset}: {reason}")
            }
            JournalError::Io(error) => write!(f, "ledger journal I/O error: {error}"),
        }
    }
}

impl std::error::Error for JournalError {}

impl From<std::io::Error> for JournalError {
    fn from(error: std::io::Error) -> Self {
        JournalError::Io(error)
    }
}

/// What one journal scan found.
#[derive(Debug, Default)]
pub struct JournalScan {
    /// Payload text of every intact record, in the order they were appended.
    ///
    /// Append order is **arrival order**, not canonical order: boot sorts the
    /// union by `(date, type_priority)` exactly as it sorts the canonical file,
    /// and the directive set is a G-Set, so the order records land in cannot
    /// affect the state they produce. That is what lets a commit append
    /// without reading or rewriting anything.
    pub payloads: Vec<String>,
    /// Length of the journal file on disk.
    pub file_bytes: u64,
    /// Bytes at the end of the file that belong to a torn final record and were
    /// dropped. Zero for an intact journal.
    pub torn_tail_bytes: u64,
    /// The journal is ours and not writable by anyone else, but it IS group- or
    /// world-readable (L-58) — e.g. restored by a `cp` without `-p`. Its
    /// records are loaded (nobody else could have written them), but
    /// [`append_record`] refuses to add more to a file others can read, so the
    /// caller must fold it with a compaction, which deletes it; the next append
    /// then creates a fresh 0600 journal.
    pub readable_by_others: bool,
}

/// Frame one commit's canonical text as a journal record.
pub fn record_bytes(payload: &str) -> String {
    let digest = Sha256::digest(payload.as_bytes());
    let hash: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{RECORD_TAG} {} {hash}\n{payload}", payload.len())
}

/// Read and validate a journal, tolerating exactly one torn trailing record.
///
/// `budget` caps the file size. Boot passes the whole `MAX_LEDGER_FILE_BYTES`
/// (M-35: the append path, not this read, is what keeps canonical ∪ journal
/// under the cap). It is also the bound a record header's claimed length is
/// checked against: a claim larger than any journal this node could have
/// written is damage, not a torn tail (M-43).
///
/// An absent journal is an empty scan, not an error: that is the steady state
/// of every ledger small enough to be compacted on every write. Anything at
/// the path that is not a regular file this node owns is refused before a byte
/// is read (T67) — see [`open_checked`] with [`FileTrust::NodeRead`].
pub fn read_journal(path: &Path, budget: u64) -> Result<JournalScan, JournalError> {
    let checked = match open_checked(
        path,
        OpenOptions::new().read(true),
        FileTrust::NodeRead,
        "ledger journal",
    ) {
        Ok(checked) => checked,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(JournalScan::default())
        }
        Err(error) => return Err(JournalError::Io(error)),
    };
    let length = checked.metadata.len();
    if length > budget {
        return Err(JournalError::TooLarge { length, budget });
    }

    // Read as bytes, not as a `String`: a torn write can split a multi-byte
    // character, and `read_to_string` would turn a tolerable crash artefact
    // into a hard failure. Capped at the budget through the handle (T67), so a
    // file that grows after the `fstat` above cannot stream past it.
    let bytes = match read_to_end_capped(&checked.file, length, budget) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::FileTooLarge => {
            return Err(JournalError::TooLarge {
                length: budget.saturating_add(1),
                budget,
            })
        }
        Err(error) => return Err(JournalError::Io(error)),
    };
    let mut scan = JournalScan {
        file_bytes: bytes.len() as u64,
        readable_by_others: checked.readable_by_others,
        ..JournalScan::default()
    };

    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        let record_start = cursor;

        // ── Header line ────────────────────────────────────────────────
        let Some(newline_offset) = bytes[cursor..].iter().position(|byte| *byte == b'\n') else {
            // No terminator: the file ends inside a header. Torn tail.
            scan.torn_tail_bytes = (bytes.len() - record_start) as u64;
            break;
        };
        let header = &bytes[cursor..cursor + newline_offset];
        cursor += newline_offset + 1;

        // M-44, header shape: a crash on a metadata-first filesystem can zero
        // the block holding the end of the LAST header line, so the line runs
        // on into NULs (and possibly into payload text) before a `\n`. NUL is
        // never in a header this node wrote; with no later record header
        // after it, this is the final record, torn.
        if header.contains(&0) && !has_later_record_header(&bytes[cursor..]) {
            scan.torn_tail_bytes = (bytes.len() - record_start) as u64;
            break;
        }

        let header = std::str::from_utf8(header).map_err(|_| JournalError::Corrupt {
            offset: record_start as u64,
            reason: "record header is not UTF-8".to_owned(),
        })?;
        let (payload_length, expected_hash) =
            parse_header(header).ok_or_else(|| JournalError::Corrupt {
                offset: record_start as u64,
                reason: format!("unreadable record header {header:?}"),
            })?;

        // ── Payload ────────────────────────────────────────────────────
        //
        // L-41: compared against the bytes REMAINING, never as
        // `cursor + payload_length`. The length is attacker-shaped (it is
        // whatever digits the header holds), and the sum used to overflow for
        // any length near `usize::MAX` — a panic (`overflow-checks = true` in
        // release too) instead of this module's policy, landing inside
        // `recover_failed_commit` with the ledger write lock held. The
        // subtraction cannot underflow: `cursor` only ever advances past bytes
        // that exist.
        let remaining = bytes.len() - cursor;
        if payload_length > remaining {
            // The header promised more bytes than the file holds. A crash
            // between `write_all` and `sync_all` produces this, and only ever
            // for the LAST record, with a claim no larger than one commit.
            //
            // M-43 (R-18): so does one flipped digit in the MIDDLE of the
            // file, and treating that as torn loaded only the prefix, dropped
            // every later acknowledged record, and let the startup compaction
            // erase them. The two are told apart by what a node-written
            // journal can contain: never a claim over the budget (the file is
            // capped far below it — this also covers L-41's saturated
            // `usize::MAX`), and never a later line starting `;;olj ` inside a
            // payload. Either one means records follow the damaged header:
            // fail closed, name the offset, and let the operator decide.
            let over_budget = payload_length as u64 > budget;
            // T93 / L-122: and a later append torn inside the first five bytes
            // of its `;;olj ` tag, before a whole tag exists to find — the gap
            // T86 closed in the exact-length arm below (L-105), with the same
            // discriminator: the bytes before the fragment are exactly this
            // record's payload and verify against its own hash, which a torn
            // final record's bytes never do.
            if over_budget
                || has_later_record_header(&bytes[cursor..])
                || has_later_intact_record(&bytes[cursor..], expected_hash)
            {
                return Err(JournalError::Corrupt {
                    offset: record_start as u64,
                    reason: format!(
                        "record header claims {} payload bytes but only {remaining} remain \
                         and {}; a crash tears only the last record, so this is damage to a \
                         record in the middle of the journal, not a torn tail (M-43)",
                        if payload_length == usize::MAX {
                            "more than usize::MAX".to_owned()
                        } else {
                            payload_length.to_string()
                        },
                        if over_budget {
                            format!("the claim exceeds the journal budget of {budget} bytes")
                        } else {
                            "a later record header follows it".to_owned()
                        }
                    ),
                });
            }
            scan.torn_tail_bytes = (bytes.len() - record_start) as u64;
            break;
        }
        let payload = &bytes[cursor..cursor + payload_length];
        cursor += payload_length;

        let digest = Sha256::digest(payload);
        let actual_hash: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        if actual_hash != expected_hash {
            // M-44 → T78: the FINAL record, complete by length, whose
            // payload fails its checksum. A power loss between `write_all`
            // and `sync_all` on a metadata-first filesystem leaves exactly
            // this: the new length reached the disk, the data did not, and
            // the region reads back as zeros (XFS — M-44's NUL rule) or as
            // whatever the reused blocks held before (ext4 `data=writeback`:
            // typically an older, folded journal's text — no NUL at all).
            // Torn, unless an INTACT record starts inside it: then this
            // record's length was damaged to swallow records appended after
            // it, which a crash cannot do (M-43), and it fails closed.
            // Anywhere but the end a checksum failure is still corrupt.
            if cursor == bytes.len() && !has_later_intact_record(payload, expected_hash) {
                scan.torn_tail_bytes = (bytes.len() - record_start) as u64;
                break;
            }
            return Err(JournalError::Corrupt {
                offset: record_start as u64,
                reason: "record payload does not match its recorded SHA-256".to_owned(),
            });
        }
        let payload = std::str::from_utf8(payload).map_err(|_| JournalError::Corrupt {
            offset: record_start as u64,
            reason: "record payload is not UTF-8".to_owned(),
        })?;
        scan.payloads.push(payload.to_owned());
    }

    Ok(scan)
}

/// Does `rest` hold the start of another record — `;;olj ` at a line start?
///
/// `rest` begins immediately after a header's `\n`, so its offset 0 is a line
/// start too. A node-written payload never contains such a line (M-43): every
/// string field refuses control characters, so a payload line can only begin
/// with a date or indentation, and a record carries no comments.
fn has_later_record_header(rest: &[u8]) -> bool {
    const TAG: &[u8] = b";;olj ";
    rest.starts_with(TAG)
        || rest
            .windows(TAG.len() + 1)
            .any(|window| window[0] == b'\n' && &window[1..] == TAG)
}

/// Does `region` hold a complete, checksum-valid record starting at a line
/// start (T78)?
///
/// `region` is the payload of a final record that failed its checksum; its
/// offset 0 is a line start. A node-written payload never holds a line
/// starting `;;olj ` ([`has_later_record_header`]), so the FIRST such line in
/// the region is where the next appended record would begin if this record's
/// length had been damaged to run to the end of the file — and an appended
/// record reads back intact. Only that first candidate is checked, so the cost
/// is one parse and at most one hash over bytes already in memory, whatever
/// the region holds.
///
/// Not [`has_later_record_header`], which the over-long-claim arm uses: the
/// ext4 `data=writeback` shape exposes a reused block of an OLDER journal,
/// whose text is full of `;;olj ` lines cut at arbitrary block boundaries.
/// Those do not verify against the bytes that follow them; a real later
/// record does. (A stale block that happens to hold one whole old record
/// verifies too, and fails closed — the pre-T78 answer.)
///
/// T82 / L-85: the candidate may itself be TORN — a crash mid-append after
/// this record's length was damaged to run to the end of the file — cut in
/// its header or in its payload (T86 / L-105: including inside the first five
/// bytes of `;;olj `, before a complete tag exists to find). Before T82 that read as "no later record",
/// so an acknowledged record was dropped as a torn tail. The discriminator is
/// this record's own checksum: when the bytes before the candidate — exactly
/// this record's payload, if only its length was damaged — verify against
/// `own_hash`, the candidate is a real later append, whatever state it is in,
/// and the record fails closed. Stale ext4 bytes never verify against it, so
/// T78's torn classification of a stale block is unchanged.
fn has_later_intact_record(region: &[u8], own_hash: &str) -> bool {
    const TAG: &[u8] = b";;olj ";
    let start = if region.starts_with(TAG) {
        0
    } else {
        match region
            .windows(TAG.len() + 1)
            .position(|window| window[0] == b'\n' && &window[1..] == TAG)
        {
            Some(newline) => newline + 1,
            // T86 / L-105: no complete `;;olj ` line — but the later append
            // may have been torn inside its first five header bytes (`;`,
            // `;;`, … `;;olj`). Then the region is this record's payload
            // followed by that fragment at a line start, and the payload
            // verifies against `own_hash`: fail closed, as for a later
            // append torn anywhere else.
            None => {
                return (1..TAG.len()).any(|cut| {
                    region.len() >= cut
                        && region.ends_with(&TAG[..cut])
                        && (region.len() == cut || region[region.len() - cut - 1] == b'\n')
                        && {
                            let digest = Sha256::digest(&region[..region.len() - cut]);
                            let hash: String =
                                digest.iter().map(|byte| format!("{byte:02x}")).collect();
                            hash == own_hash
                        }
                });
            }
        }
    };
    // T82 / L-85: see the doc comment.
    let prefix = Sha256::digest(&region[..start]);
    let prefix_hash: String = prefix.iter().map(|byte| format!("{byte:02x}")).collect();
    if prefix_hash == own_hash {
        return true;
    }
    let candidate = &region[start..];
    let Some(header_end) = candidate.iter().position(|byte| *byte == b'\n') else {
        return false;
    };
    let Some((length, expected_hash)) = std::str::from_utf8(&candidate[..header_end])
        .ok()
        .and_then(parse_header)
    else {
        return false;
    };
    let body = &candidate[header_end + 1..];
    if length > body.len() {
        return false;
    }
    let digest = Sha256::digest(&body[..length]);
    let actual_hash: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    actual_hash == expected_hash
}

/// Parse `;;olj <len> <sha256hex>` into its two fields.
///
/// A length that is a well-formed number too large for `usize` saturates to
/// `usize::MAX` rather than failing the parse (L-41). It is still a header that
/// claims more bytes than the file can hold — the file is capped far below
/// `usize::MAX` — so [`read_journal`] must classify it exactly as it classifies
/// every other over-long claim, and that classification belongs in one place
/// (the payload bound check), not split across a parse error here and a torn
/// tail there depending on how many digits were written. Since M-43 that one
/// place refuses it as corrupt — it is over any budget — which is the same
/// answer for 21 digits as for 40.
fn parse_header(header: &str) -> Option<(usize, &str)> {
    let rest = header.strip_prefix(RECORD_TAG)?.strip_prefix(' ')?;
    let (length, hash) = rest.split_once(' ')?;
    let length: usize = match length.parse::<usize>() {
        Ok(length) => length,
        Err(error) if *error.kind() == std::num::IntErrorKind::PosOverflow => usize::MAX,
        Err(_) => return None,
    };
    if hash.len() != 64 || !hash.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f')) {
        return None;
    }
    Some((length, hash))
}

/// Append one record and fsync it. Returns the journal's new length.
///
/// `created_now` tells the caller whether the file had to be created, so it can
/// fsync the containing directory — without that, a crash can lose the whole
/// journal's directory entry even though the record's own bytes are on the
/// platter.
///
/// The open is [`open_checked`] with [`FileTrust::NodePrivate`] (T67):
///
/// * **M-36** — the old `lstat` refused only a symlink and then called a
///   blocking `open(O_WRONLY|O_APPEND|O_CREAT)`. On a FIFO with no reader that
///   parked the commit's blocking thread, holding the `WritePermit`, forever:
///   every writer queued behind the gate, SIGTERM's compaction waited on it,
///   and the post-open `is_file()` check never ran. `O_NONBLOCK` makes the open
///   of a FIFO return (`ENXIO`) and the `lstat` refuses it before that.
/// * **L-44** — `O_NOFOLLOW` refuses a symlink at the path at the `open`
///   itself, so the create no longer has a window in which a swapped-in link
///   is followed (before T67 only the write was protected, by a post-open
///   inode comparison, because this crate took no `libc`).
/// * **L-58** — the handle must be owned by this uid, have exactly one link,
///   and be owner-only. A pre-planted 0644 journal or a hard link to a file
///   elsewhere used to pass the regular-file and inode checks and receive every
///   commit in a file someone else could read. `mode(0o600)` only ever applied
///   when the file was created.
pub fn append_record(path: &Path, record: &str) -> Result<(u64, bool), std::io::Error> {
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Owner-only, exactly like the `.bean` — the journal carries the same
        // directives and would otherwise be the easier file to read.
        options.mode(0o600);
    }
    let CheckedFile {
        mut file, created, ..
    } = open_checked(path, &options, FileTrust::NodePrivate, "ledger journal")?;

    // `O_NONBLOCK` stays set on this descriptor. The checks above proved it is
    // a regular file, and for regular files Linux, macOS and the BSDs ignore
    // the flag — a write never returns `EAGAIN` (the one historical exception,
    // Linux mandatory locking on a `mand` mount, was removed in 5.15). Clearing
    // it would take an `fcntl(F_SETFL)`, one more `unsafe` FFI call, for no
    // behavioural gain.
    file.write_all(record.as_bytes())?;
    file.sync_all()?;
    let length = file.metadata()?.len();

    if created {
        sync_parent_directory(path);
    }
    Ok((length, created))
}

/// Delete the journal after its records have been folded into the canonical
/// file. Absence is success.
pub fn remove_journal(path: &Path) -> Result<(), std::io::Error> {
    match std::fs::remove_file(path) {
        Ok(()) => {
            sync_parent_directory(path);
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Suffix of the sidecar a torn journal is renamed to (M-43):
/// `<ledger>.bean.journal.torn-<unix-seconds>`. No boot reads it.
pub const TORN_JOURNAL_SUFFIX: &str = ".torn-";

/// Retire a journal whose tail boot dropped as torn, instead of deleting it
/// (M-43, decision taken: torn journals are renamed, never unlinked).
///
/// The torn classification is a heuristic about bytes — "the file ends inside
/// a record" is what a crash leaves, and also what a truncation or an edited
/// length on the last record leaves — so the compaction that folds the intact
/// records must not destroy the ones it dropped on the strength of it. The
/// journal is renamed to `<journal>.torn-<unix-seconds>` (with `-<n>` appended
/// if that name is taken) and the new path is returned for the caller to log.
/// Boot reads only `<journal>` itself, so the sidecar is inert; the operator
/// deletes it once satisfied nothing in it matters.
///
/// Absence is success (`Ok(None)`), exactly as for [`remove_journal`].
pub fn retire_torn_journal(path: &Path) -> Result<Option<PathBuf>, std::io::Error> {
    if let Err(error) = std::fs::symlink_metadata(path) {
        return if error.kind() == std::io::ErrorKind::NotFound {
            Ok(None)
        } else {
            Err(error)
        };
    }
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let base = format!("{}{TORN_JOURNAL_SUFFIX}{seconds}", path.display());
    // `rename` replaces an existing target, so pick a free name first. The
    // caller holds the single-writer permit (and, under `gl-node`, the ledger
    // lock), so nothing else creates these names concurrently.
    let mut target = PathBuf::from(&base);
    let mut attempt: u32 = 0;
    while std::fs::symlink_metadata(&target).is_ok() {
        attempt += 1;
        target = PathBuf::from(format!("{base}-{attempt}"));
    }
    std::fs::rename(path, &target)?;
    sync_parent_directory(path);
    Ok(Some(target))
}

/// Best-effort fsync of the directory holding `path`, so a create or unlink of
/// the entry itself is durable. Mirrors what `persist_atomically` does after
/// its rename.
fn sync_parent_directory(path: &Path) {
    let directory = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    if let Ok(handle) = std::fs::File::open(directory) {
        let _ = handle.sync_all();
    }
}

// ─── Checked opens (T67: M-36, L-57, L-58, L-59, R-17) ──────────────────────

/// How much the node trusts a path it is about to open (T67).
///
/// Every ledger-side file falls in exactly one class, and the class decides
/// whether a symlink is followed and whether ownership is checked. See
/// [`open_checked`] for the checks themselves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileTrust {
    /// The canonical `.bean` — **read only**. The operator edits it, possibly
    /// as another account, so its owner and mode are not checked.
    ///
    /// # Policy for a symlinked `.bean`
    ///
    /// Some deployments deliberately make the `.bean` a symlink (to a file on
    /// another volume, or managed by another tool). It is **followed**, but the
    /// TARGET must be a regular file: a link to a FIFO, device, socket or
    /// directory is refused exactly like one at the path, and a dangling link
    /// is refused rather than treated as "no ledger yet". The open never
    /// blocks either way (`O_NONBLOCK`). Since T82 (L-84) the node resolves
    /// the link once, at boot ([`resolve_ledger_path`]), and works at the
    /// target from then on: journal, lock, temp files and every rewrite sit
    /// beside the target, and the link is kept. Since T87 (M-60, M-61) the
    /// link is followed only from a directory only this node's user can
    /// write, one hop, and never with a journal left beside it.
    OperatorLedger,
    /// `gl-node`'s config file (`GL_NODE_CONFIG`) — **read only**, operator
    /// owned (T77 / L-73). The [`FileTrust::OperatorLedger`] policy: a symlink
    /// is followed (configs are routinely mounted as links — a Kubernetes
    /// ConfigMap is one), the target must be a regular file, the open never
    /// blocks, and owner and mode are not checked (the operator may keep it
    /// under another account; `gl-node` warns separately when a file holding
    /// the API key is readable by others). Its own variant so the refusal and
    /// any later tightening name the config, not the ledger.
    OperatorConfig,
    /// A node-private file the node **reads** — the journal at boot and in the
    /// L-13 reload. Never followed through a symlink; must be owned by this
    /// uid, have exactly one link, and be writable by nobody else. Group/world
    /// READ bits are tolerated here and reported
    /// ([`CheckedFile::readable_by_others`]): they do not let anyone else put
    /// records in the file, and refusing them would brick boot on a journal
    /// restored with `cp`. The ledger folds such a journal away at the next
    /// commit, and [`append_record`] (which is [`FileTrust::NodePrivate`])
    /// never adds to it.
    NodeRead,
    /// A node-private file the node **writes, locks, or keeps a secret in** —
    /// the journal on append, `gl-node`'s `.lock` sidecar and its key file.
    /// Everything [`FileTrust::NodeRead`] requires, plus `mode & 0o077 == 0`.
    NodePrivate,
}

/// A handle [`open_checked`] vouched for.
#[derive(Debug)]
pub struct CheckedFile {
    /// The open file. On Unix it carries `O_NONBLOCK`, which regular files
    /// ignore — see [`append_record`].
    pub file: File,
    /// `fstat` of [`Self::file`], taken for the checks.
    pub metadata: std::fs::Metadata,
    /// Nothing was at the path when it was inspected, so the open created it
    /// (only possible when the caller asked for `create`). The caller fsyncs
    /// the directory.
    pub created: bool,
    /// [`FileTrust::NodeRead`] only: the file has group or world read bits.
    pub readable_by_others: bool,
}

/// Open a ledger-side file without following what should not be followed,
/// without blocking on what is not a file, and only if it is the file it
/// claims to be (T67).
///
/// One helper for every ledger-side open (M-36, L-58, L-59, the key file's
/// L-49 race), in this order:
///
/// 1. **`lstat`** (or `stat` for [`FileTrust::OperatorLedger`] and
///    [`FileTrust::OperatorConfig`], which follow a symlink by policy) and
///    require a regular file. Refusing here means a FIFO, device or directory
///    is never opened at all.
/// 2. **`open`** with `O_NONBLOCK` — a FIFO swapped in after step 1 opens
///    immediately (or fails `ENXIO` for writing) instead of parking the thread
///    until a peer process appears — and, unless following by policy,
///    `O_NOFOLLOW`, so a symlink swapped in after step 1 fails `ELOOP`.
/// 3. **`fstat`** the handle: a regular file, and the same `(dev, ino)` step 1
///    saw (or, if step 1 saw nothing and the open created the file, the inode
///    now at the path).
/// 4. For node-owned files: `uid == geteuid()`, `nlink == 1`, and the mode
///    [`FileTrust`] requires.
///
/// `options` are the caller's; this adds the flags and never removes any.
/// `label` names the file in every refusal ("ledger journal", "Secret key
/// file"). A missing file (without `create`) is the `open`'s own `NotFound`,
/// so callers can keep treating absence specially.
pub fn open_checked(
    path: &Path,
    options: &OpenOptions,
    trust: FileTrust,
    label: &str,
) -> std::io::Result<CheckedFile> {
    open_checked_impl(path, options, trust, label)
}

#[cfg(unix)]
fn open_checked_impl(
    path: &Path,
    options: &OpenOptions,
    trust: FileTrust,
    label: &str,
) -> std::io::Result<CheckedFile> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let follow = matches!(trust, FileTrust::OperatorLedger | FileTrust::OperatorConfig);
    let inspect = |path: &Path| {
        if follow {
            std::fs::metadata(path)
        } else {
            std::fs::symlink_metadata(path)
        }
    };

    // 1. What is at the path, before anything is opened.
    let before = match inspect(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() {
                return Err(refuse_file_type(path, label, &metadata.file_type()));
            }
            Some(metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // For a followed path this is also a dangling symlink: say so,
            // rather than letting a create resolve it (M-36's `symlink-bean`).
            if follow {
                if let Ok(link) = std::fs::symlink_metadata(path) {
                    // T83 (0924 §5): a followed path IS allowed to be a link;
                    // what is wrong here is that its target is missing.
                    if link.file_type().is_symlink() {
                        return Err(refuse(
                            path,
                            label,
                            "is a dangling symbolic link (its target does not exist); refusing \
                             to follow it or to create anything through it",
                        ));
                    }
                    return Err(refuse_file_type(path, label, &link.file_type()));
                }
            }
            None
        }
        Err(error) => return Err(error),
    };

    // 2. The open itself cannot block, and cannot follow a link it should not.
    let mut options = options.clone();
    let mut flags = libc::O_NONBLOCK;
    if !follow {
        flags |= libc::O_NOFOLLOW;
    }
    options.custom_flags(flags);
    let file = match options.open(path) {
        Ok(file) => file,
        // `O_NOFOLLOW` on a symlink: ELOOP on Linux and macOS alike.
        Err(error) if !follow && error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(refuse(
                path,
                label,
                "is a symbolic link; refusing to follow it",
            ));
        }
        // `O_WRONLY|O_NONBLOCK` on a FIFO with no reader.
        Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {
            return Err(refuse(
                path,
                label,
                "is not a regular file (it is a FIFO or socket); refusing to open it",
            ));
        }
        Err(error) => return Err(error),
    };

    // 3. The handle is a regular file, and the one that was inspected.
    let opened = file.metadata()?;
    if !opened.file_type().is_file() {
        return Err(refuse_file_type(path, label, &opened.file_type()));
    }
    let reference = match before {
        Some(ref metadata) => metadata.clone(),
        None => inspect(path)?,
    };
    if (opened.dev(), opened.ino()) != (reference.dev(), reference.ino()) {
        return Err(refuse(
            path,
            label,
            "was replaced while being opened; refusing to use it",
        ));
    }

    // 4. Node-owned files: ours, one name, and nobody else's to write (or read).
    let mode = opened.mode() & 0o777;
    let mut readable_by_others = false;
    // Operator files (the followed classes) stop at type and identity.
    if !follow {
        let uid = effective_uid();
        if opened.uid() != uid {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "{label} {} is owned by uid {}, but this node runs as uid {uid}; refusing to \
                     use a node-private file another account controls — chown it to the node's \
                     user (L-58)",
                    path.display(),
                    opened.uid()
                ),
            ));
        }
        if opened.nlink() != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "{label} {} has {} hard links; a node-private file must have exactly one — \
                     every other name is another way to read or write it (L-58). Copy it to \
                     break the link",
                    path.display(),
                    opened.nlink()
                ),
            ));
        }
        let forbidden = match trust {
            FileTrust::NodePrivate => 0o077,
            _ => 0o022,
        };
        if mode & forbidden != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "{label} {} has overly permissive mode {mode:o}; expected owner-only 0600 \
                     (L-58)",
                    path.display()
                ),
            ));
        }
        readable_by_others = mode & 0o044 != 0;
    }

    Ok(CheckedFile {
        file,
        metadata: opened,
        created: before.is_none(),
        readable_by_others,
    })
}

/// Non-Unix: no `O_NOFOLLOW`/`O_NONBLOCK`, no inode identity and no uid; the
/// type check on the handle is all that is portable. Ownership is governed by
/// the platform's ACLs (see `gl-node`'s L-05 warning for the key file).
#[cfg(not(unix))]
fn open_checked_impl(
    path: &Path,
    options: &OpenOptions,
    _trust: FileTrust,
    label: &str,
) -> std::io::Result<CheckedFile> {
    let created = std::fs::symlink_metadata(path).is_err();
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(refuse_file_type(path, label, &metadata.file_type()));
    }
    Ok(CheckedFile {
        file,
        metadata,
        created,
        readable_by_others: false,
    })
}

/// The refusal for anything that is not a plain file at the path (T67). An
/// I/O error of kind `InvalidInput`, so a commit that meets it fails and the
/// L-13 reload runs exactly as for any other failed write.
fn refuse(path: &Path, label: &str, what: &str) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!("{label} {} {what} (T67)", path.display()),
    )
}

fn refuse_file_type(path: &Path, label: &str, file_type: &std::fs::FileType) -> std::io::Error {
    if file_type.is_symlink() {
        return refuse(path, label, "is a symbolic link; refusing to follow it");
    }
    let kind = if file_type.is_dir() {
        "a directory"
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if file_type.is_fifo() {
                "a FIFO"
            } else if file_type.is_socket() {
                "a socket"
            } else if file_type.is_block_device() || file_type.is_char_device() {
                "a device"
            } else {
                "not a file"
            }
        }
        #[cfg(not(unix))]
        {
            "not a file"
        }
    };
    refuse(
        path,
        label,
        &format!("is not a regular file (it is {kind}); refusing to open it"),
    )
}

/// Read everything from `reader`, refusing past `cap` bytes (T67, M-36).
///
/// Reads through `take(cap + 1)`, so at most one byte past the cap is ever
/// read, whatever the file does after it was `fstat`ed — a regular file
/// appended to mid-read, or (were one ever to get past [`open_checked`]) a
/// stream, which is how 73 MB once loaded through a 64 MiB cap. Past the cap
/// the result is an error of kind `FileTooLarge`, which callers map to their
/// own size error. `size_hint` pre-sizes the buffer (clamped to the cap).
pub fn read_to_end_capped(reader: impl Read, size_hint: u64, cap: u64) -> std::io::Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(usize::try_from(size_hint.min(cap)).unwrap_or(0));
    reader.take(cap.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            format!("more than {cap} bytes"),
        ));
    }
    Ok(bytes)
}

/// `geteuid(2)`: the uid node-owned files must belong to (L-49, L-58).
///
/// R-17: this replaces `gl-node`'s hand-written `extern "C"` declaration with
/// the `libc` crate's binding — `libc` is a direct dependency now (it was
/// already compiled in through tokio/mio). The binding is an `extern "C"` item,
/// so calling it is still `unsafe` syntactically; there is no `std` route to the
/// effective uid. One of the workspace's production `unsafe` expressions; the
/// others are the directory-handle calls of [`resolve_link_in_its_directory`]
/// (T94: `fstatat`, `readlinkat`, `openat`, and on macOS the ACL calls).
#[cfg(unix)]
pub fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, touches no memory, cannot fail
    // (POSIX: "shall always be successful"), and is async-signal-safe and
    // thread-safe; its signature comes from `libc`, not from a hand-written
    // declaration.
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write a journal fixture as the node would own it — 0600 whatever the
    /// test process's umask — so only the property under test differs.
    fn write_private(path: &Path, bytes: impl AsRef<[u8]>) {
        std::fs::write(path, bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }

    fn temp_journal(name: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("openledger-journal-{name}-{stamp}.bean.journal"))
    }

    #[test]
    fn journal_path_sits_beside_the_ledger() {
        assert_eq!(
            journal_path_for(Path::new("/srv/data/ledger.bean")),
            PathBuf::from("/srv/data/ledger.bean.journal")
        );
    }

    #[test]
    fn records_round_trip_in_append_order() {
        let path = temp_journal("round-trip");
        append_record(&path, &record_bytes("first\n")).unwrap();
        append_record(&path, &record_bytes("second\n")).unwrap();
        append_record(&path, &record_bytes("third\n")).unwrap();

        let scan = read_journal(&path, 1 << 20).unwrap();
        assert_eq!(scan.payloads, vec!["first\n", "second\n", "third\n"]);
        assert_eq!(scan.torn_tail_bytes, 0);
        assert_eq!(scan.file_bytes, std::fs::metadata(&path).unwrap().len());
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn an_absent_journal_is_an_empty_scan() {
        let scan = read_journal(&temp_journal("absent"), 1 << 20).unwrap();
        assert!(scan.payloads.is_empty());
        assert_eq!(scan.file_bytes, 0);
    }

    #[test]
    fn a_payload_truncated_mid_record_is_a_torn_tail() {
        let path = temp_journal("torn-payload");
        append_record(&path, &record_bytes("kept\n")).unwrap();
        append_record(&path, &record_bytes("0123456789abcdef\n")).unwrap();

        // Chop the last five bytes: the final header still promises 17.
        let full = std::fs::read(&path).unwrap();
        write_private(&path, &full[..full.len() - 5]);

        let scan = read_journal(&path, 1 << 20).unwrap();
        assert_eq!(scan.payloads, vec!["kept\n"]);
        assert!(scan.torn_tail_bytes > 0, "the torn record must be reported");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn a_header_truncated_mid_line_is_a_torn_tail() {
        let path = temp_journal("torn-header");
        append_record(&path, &record_bytes("kept\n")).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.extend_from_slice(b";;olj 12 abc");
        write_private(&path, &bytes);

        let scan = read_journal(&path, 1 << 20).unwrap();
        assert_eq!(scan.payloads, vec!["kept\n"]);
        assert_eq!(scan.torn_tail_bytes, 12);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn a_payload_with_the_wrong_hash_fails_closed() {
        let path = temp_journal("bad-hash");
        append_record(&path, &record_bytes("original\n")).unwrap();
        append_record(&path, &record_bytes("trailing\n")).unwrap();
        // Flip one byte inside the FIRST payload: full length is present, so
        // this is corruption rather than a torn tail.
        let mut bytes = std::fs::read(&path).unwrap();
        let position = bytes
            .windows(8)
            .position(|window| window == b"original")
            .unwrap();
        bytes[position] = b'0';
        write_private(&path, &bytes);

        let error = read_journal(&path, 1 << 20).unwrap_err();
        assert!(
            matches!(error, JournalError::Corrupt { .. }),
            "expected corruption, got {error}"
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn a_malformed_complete_header_fails_closed() {
        let path = temp_journal("bad-header");
        write_private(&path, b";;olj not-a-number deadbeef\nbody\n");
        let error = read_journal(&path, 1 << 20).unwrap_err();
        assert!(
            matches!(error, JournalError::Corrupt { offset: 0, .. }),
            "expected corruption at offset 0, got {error}"
        );
        std::fs::remove_file(path).ok();
    }

    /// A syntactically valid header whose hash field is well-formed, so the
    /// only thing wrong with it is the length it claims.
    fn header_claiming(length: &str) -> String {
        format!("{RECORD_TAG} {length} {}\n", "ab".repeat(32))
    }

    /// L-41: a header claiming `usize::MAX` bytes is refused cleanly, never a
    /// panic.
    ///
    /// Before L-41 `cursor + payload_length` overflowed (`attempt to add with
    /// overflow`; release builds run `overflow-checks = true`), and
    /// `read_journal` is the body of `recover_failed_commit`, so the panic
    /// landed in a live node holding the ledger write lock. L-41 made it a torn
    /// tail; M-43 (T68) makes it `Corrupt` — no journal this node writes can
    /// claim more than the budget — which is still an answer, not a panic.
    #[test]
    fn l41_a_usize_max_header_length_fails_closed_not_a_panic() {
        let path = temp_journal("l41-usize-max");
        let mut bytes = header_claiming(&usize::MAX.to_string()).into_bytes();
        bytes.extend_from_slice(b"a few payload bytes\n");
        write_private(&path, &bytes);

        let error = read_journal(&path, 1 << 20).expect_err("an over-budget claim is corrupt");
        assert!(
            matches!(error, JournalError::Corrupt { offset: 0, .. }),
            "expected corruption at offset 0, got {error}"
        );
        std::fs::remove_file(path).ok();
    }

    /// L-41, the other shape: a length that is itself representable but that
    /// overflows once added to a non-zero cursor. Refused at the damaged
    /// record's offset (M-43), without a panic.
    #[test]
    fn l41_a_header_length_that_overflows_the_cursor_fails_closed() {
        let path = temp_journal("l41-cursor-overflow");
        append_record(&path, &record_bytes("kept\n")).unwrap();
        let kept = std::fs::read(&path).unwrap();

        // Pick the length so that `cursor + length == usize::MAX + 1`, where
        // `cursor` is the offset just past this header line. The claimed
        // length has 20 digits, which fixes the header's own length.
        let header_len = header_claiming(&usize::MAX.to_string()).len();
        let cursor_after_header = kept.len() + header_len;
        let length = usize::MAX - cursor_after_header + 1;
        assert_eq!(length.to_string().len(), usize::MAX.to_string().len());
        assert!(
            cursor_after_header.checked_add(length).is_none(),
            "the fixture must overflow the old `cursor + payload_length`"
        );

        let mut bytes = kept.clone();
        bytes.extend_from_slice(header_claiming(&length.to_string()).as_bytes());
        bytes.extend_from_slice(b"partial");
        write_private(&path, &bytes);

        let error = read_journal(&path, 1 << 20).expect_err("an over-budget claim is corrupt");
        assert!(
            matches!(error, JournalError::Corrupt { offset, .. } if offset == kept.len() as u64),
            "expected corruption at the second record, got {error}"
        );
        std::fs::remove_file(path).ok();
    }

    /// A length with more digits than `usize` can hold is the same claim, and
    /// gets the same answer — not a parse error on one side of 20 digits and
    /// something else on the other.
    #[test]
    fn l41_a_length_wider_than_usize_fails_closed_too() {
        let path = temp_journal("l41-wide");
        append_record(&path, &record_bytes("kept\n")).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let kept = bytes.len();
        bytes.extend_from_slice(header_claiming(&"9".repeat(40)).as_bytes());
        write_private(&path, &bytes);

        let error = read_journal(&path, 1 << 20).expect_err("an over-budget claim is corrupt");
        assert!(
            matches!(error, JournalError::Corrupt { offset, .. } if offset == kept as u64),
            "expected corruption at the second record, got {error}"
        );
        std::fs::remove_file(path).ok();
    }

    /// The saturation above is for OVERFLOW only: a length that is not a
    /// number at all is still a malformed complete header, and fails closed.
    #[test]
    fn l41_a_non_numeric_length_still_fails_closed() {
        let path = temp_journal("l41-not-a-number");
        write_private(&path, header_claiming("-1"));
        let error = read_journal(&path, 1 << 20).unwrap_err();
        assert!(
            matches!(error, JournalError::Corrupt { offset: 0, .. }),
            "expected corruption at offset 0, got {error}"
        );
        std::fs::remove_file(path).ok();
    }

    /// L-44's sibling: a symlink planted at the journal path is refused, and
    /// its target is neither created nor written.
    #[cfg(unix)]
    #[test]
    fn l44_append_refuses_a_symlinked_journal() {
        let directory = std::env::temp_dir().join(format!(
            "openledger-journal-l44-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let journal = directory.join("ledger.bean.journal");

        // A dangling link: the old `Path::exists` check followed it, saw
        // nothing, and the `O_CREAT` open then created the target.
        let dangling_target = directory.join("created-through-the-link");
        std::os::unix::fs::symlink(&dangling_target, &journal).unwrap();
        assert!(append_record(&journal, &record_bytes("x\n")).is_err());
        assert!(
            !dangling_target.exists(),
            "the append must not create a file through the link"
        );

        // A link to an existing file: its bytes must be untouched.
        std::fs::remove_file(&journal).unwrap();
        let victim = directory.join("victim");
        std::fs::write(&victim, b"precious\n").unwrap();
        std::os::unix::fs::symlink(&victim, &journal).unwrap();
        assert!(append_record(&journal, &record_bytes("x\n")).is_err());
        assert_eq!(std::fs::read(&victim).unwrap(), b"precious\n");

        std::fs::remove_dir_all(directory).ok();
    }

    #[test]
    fn an_over_budget_journal_fails_closed() {
        let path = temp_journal("over-budget");
        append_record(&path, &record_bytes("some payload\n")).unwrap();
        let error = read_journal(&path, 4).unwrap_err();
        assert!(
            matches!(error, JournalError::TooLarge { budget: 4, .. }),
            "expected a budget refusal, got {error}"
        );
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn removing_an_absent_journal_succeeds() {
        remove_journal(&temp_journal("never-existed")).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_journal_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_journal("permissions");
        append_record(&path, &record_bytes("secret\n")).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "journal must be owner-only like the .bean"
        );
        std::fs::remove_file(path).ok();
    }

    // ── T68: journal policy (M-43 / R-18, M-44) ─────────────────────────

    /// Three appended records; returns the journal bytes and the byte offset
    /// of the second record's header.
    fn three_records(path: &Path) -> (Vec<u8>, usize) {
        append_record(path, &record_bytes("2024-01-01 open Assets:One USD\n")).unwrap();
        let second = std::fs::metadata(path).unwrap().len() as usize;
        append_record(path, &record_bytes("2024-01-01 open Assets:Two USD\n")).unwrap();
        append_record(path, &record_bytes("2024-01-01 open Assets:Three USD\n")).unwrap();
        (std::fs::read(path).unwrap(), second)
    }

    /// Rewrite the length field of the header starting at `offset`.
    fn with_length(bytes: &[u8], offset: usize, length: &str) -> Vec<u8> {
        let end = offset + bytes[offset..].iter().position(|b| *b == b'\n').unwrap();
        let header = std::str::from_utf8(&bytes[offset..end]).unwrap();
        let mut fields = header.splitn(3, ' ');
        let (tag, old, hash) = (
            fields.next().unwrap(),
            fields.next().unwrap(),
            fields.next().unwrap(),
        );
        let length = length.replace("{old}", old);
        let mut out = bytes[..offset].to_vec();
        out.extend_from_slice(format!("{tag} {length} {hash}").as_bytes());
        out.extend_from_slice(&bytes[end..]);
        out
    }

    /// M-43 / R-18, the audit's fixture: the SECOND of three acknowledged
    /// records has its length damaged — one digit prefixed (`86 → 986`),
    /// `999999`, `10^23`, `u64::MAX`. Every spelling used to be a "torn tail":
    /// one record loaded, two dropped, and the startup compaction erased them.
    /// Each is now `Corrupt` at exactly that record's offset.
    ///
    /// Bug-catch: drop the `has_later_record_header` / budget test in
    /// `read_journal` and this returns `Ok` with one payload.
    #[test]
    fn m43_a_damaged_length_mid_journal_fails_closed_naming_the_offset() {
        for (index, length) in [
            "9{old}",
            "999999",
            "100000000000000000000000",
            "18446744073709551615",
        ]
        .into_iter()
        .enumerate()
        {
            let path = temp_journal(&format!("m43-{index}"));
            let (bytes, second) = three_records(&path);
            write_private(&path, with_length(&bytes, second, length));

            match read_journal(&path, 64 * 1024 * 1024) {
                Err(JournalError::Corrupt { offset, ref reason }) => {
                    assert_eq!(offset, second as u64, "{length}: wrong offset ({reason})");
                    let rendered = read_journal(&path, 64 * 1024 * 1024)
                        .unwrap_err()
                        .to_string();
                    assert!(
                        rendered.contains(&format!("at byte {second}")),
                        "{length}: the error must name the offset: {rendered}"
                    );
                }
                Ok(scan) => panic!(
                    "{length}: M-43 — a damaged mid-journal length was read as a torn tail \
                     ({} payloads, {} torn bytes)",
                    scan.payloads.len(),
                    scan.torn_tail_bytes
                ),
                Err(other) => panic!("{length}: expected Corrupt, got {other}"),
            }
            std::fs::remove_file(path).ok();
        }
    }

    /// M-43, the budget half on its own: the LAST record claims more than any
    /// journal can hold. No later header follows, so only the budget says this
    /// is damage and not a crash.
    ///
    /// Bug-catch: drop the `over_budget` term and this is `Ok` (torn).
    #[test]
    fn m43_an_over_budget_claim_on_the_last_record_fails_closed() {
        let path = temp_journal("m43-budget");
        append_record(&path, &record_bytes("kept\n")).unwrap();
        let kept = std::fs::metadata(&path).unwrap().len();
        let mut bytes = std::fs::read(&path).unwrap();
        bytes.extend_from_slice(header_claiming("2000000").as_bytes());
        bytes.extend_from_slice(b"partial");
        write_private(&path, &bytes);

        let error = read_journal(&path, 1 << 20).expect_err("over the 1 MiB budget");
        assert!(
            matches!(error, JournalError::Corrupt { offset, .. } if offset == kept),
            "got {error}"
        );
        std::fs::remove_file(path).ok();
    }

    /// The boundary the heuristic cannot see past, pinned so it is a decision
    /// and not an accident: the LAST record's length damaged to a value within
    /// the budget is indistinguishable from a crash and stays a torn tail. What
    /// makes that survivable is the `.torn-*` rename (see the service tests):
    /// the bytes are never deleted on the strength of this classification.
    #[test]
    fn m43_an_in_budget_over_long_claim_on_the_last_record_is_still_torn() {
        let path = temp_journal("m43-last");
        let (bytes, _) = three_records(&path);
        let third = bytes.len() - record_bytes("2024-01-01 open Assets:Three USD\n").len();
        let damaged = with_length(&bytes, third, "999999");
        write_private(&path, &damaged);

        let scan = read_journal(&path, 64 * 1024 * 1024).expect("torn, not corrupt");
        assert_eq!(scan.payloads.len(), 2);
        assert_eq!(scan.torn_tail_bytes, (damaged.len() - third) as u64);
        std::fs::remove_file(path).ok();
    }

    /// M-44: the B8 `zero-fill` fixture. The final record's header reached the
    /// disk and its payload block did not, so the payload reads back as NULs
    /// at the right length — a crash artefact on XFS / ext4 `data=writeback`,
    /// and a torn tail, not corruption.
    ///
    /// Bug-catch: drop the NUL arm and this is `Corrupt` ("does not match its
    /// recorded SHA-256").
    #[test]
    fn m44_a_zero_filled_final_payload_is_a_torn_tail() {
        let path = temp_journal("m44-zero-fill");
        append_record(&path, &record_bytes("2024-01-02 open Assets:Kept USD\n")).unwrap();
        let record = record_bytes("2024-01-03 open Assets:Lost USD\n");
        append_record(&path, &record).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let payload_start = bytes.len() - (record.len() - (record.find('\n').unwrap() + 1));
        bytes[payload_start..].fill(0);
        write_private(&path, &bytes);

        let scan = read_journal(&path, 1 << 20).expect("a zero-filled final payload is torn");
        assert_eq!(scan.payloads, vec!["2024-01-02 open Assets:Kept USD\n"]);
        assert_eq!(scan.torn_tail_bytes, record.len() as u64);

        // The block boundary one step earlier: the header's own end zeroed
        // too, so the "header" runs into NULs. Still the final record, torn.
        let header_start = bytes.len() - record.len();
        bytes[header_start + 10..].fill(0);
        bytes.push(b'\n');
        write_private(&path, &bytes);
        let scan = read_journal(&path, 1 << 20).expect("a zero-filled final header is torn");
        assert_eq!(scan.payloads.len(), 1);
        assert!(scan.torn_tail_bytes > 0);
        std::fs::remove_file(path).ok();
    }

    /// M-44's limit: NUL is the crash signature only at the END. A NUL-damaged
    /// payload with a record after it is corruption, and fails closed.
    #[test]
    fn m44_a_nul_in_a_non_final_payload_is_still_corrupt() {
        let path = temp_journal("m44-mid");
        let (mut bytes, second) = three_records(&path);
        let payload = second + bytes[second..].iter().position(|b| *b == b'\n').unwrap() + 1;
        bytes[payload + 3] = 0;
        write_private(&path, &bytes);
        let error = read_journal(&path, 1 << 20).expect_err("mid-file NUL is corruption");
        assert!(
            matches!(error, JournalError::Corrupt { offset, .. } if offset == second as u64),
            "got {error}"
        );
        std::fs::remove_file(path).ok();
    }

    // ── T78: a checksum-failing final record (ext4 `data=writeback`) ───

    /// Two appended records whose LAST payload is then overwritten, at its
    /// exact length, by `stale` cycled — the byte shape ext4 `data=writeback`
    /// leaves after a power cut between `write_all` and `sync_all` (the
    /// 0923 audit's D2 `torn (e1)/(e2)` fixture). Returns the bytes and the
    /// offset of the last record's header.
    fn with_stale_final_payload(path: &Path, stale: &[u8]) -> (Vec<u8>, usize) {
        append_record(path, &record_bytes("2024-01-02 open Assets:Kept USD\n")).unwrap();
        let last = std::fs::metadata(path).unwrap().len() as usize;
        let record = record_bytes("2024-01-03 open Assets:Lost USD\n");
        append_record(path, &record).unwrap();
        let mut bytes = std::fs::read(path).unwrap();
        let payload_start = last + record.find('\n').unwrap() + 1;
        let length = bytes.len() - payload_start;
        bytes[payload_start..].copy_from_slice(
            &stale
                .iter()
                .copied()
                .cycle()
                .take(length)
                .collect::<Vec<u8>>(),
        );
        write_private(path, &bytes);
        (bytes, last)
    }

    /// T78 (0923 audit §5, D2 `(e1)`/`(e2)`): the final record's payload reads
    /// back as STALE text, not zeros — an older journal's record, header line
    /// included (e1), or plain old payload text (e2). No NUL, so M-44's rule
    /// said `Corrupt` and boot refused on a file the node wrote. Both are the
    /// torn final record now: the record before it loads, the whole last
    /// record is reported as torn.
    ///
    /// Bug-catch: restore the `payload.contains(&0)` condition in
    /// `read_journal` and both shapes are `Corrupt` ("does not match its
    /// recorded SHA-256").
    #[test]
    fn t78_a_stale_final_payload_is_a_torn_tail() {
        let old_record = record_bytes("2023-12-01 open Assets:OldFolded USD\n");
        for (shape, stale) in [
            ("e1 (old record, header included)", old_record.as_bytes()),
            (
                "e2 (old payload text)",
                b"2023-12-01 open Assets:OldFolded USD\n".as_slice(),
            ),
        ] {
            let path = temp_journal("t78-stale");
            let (bytes, last) = with_stale_final_payload(&path, stale);
            assert!(!bytes.contains(&0), "{shape}: the fixture holds no NUL");
            let scan = read_journal(&path, 1 << 20)
                .unwrap_or_else(|error| panic!("{shape}: must be torn, got {error}"));
            assert_eq!(
                scan.payloads,
                vec!["2024-01-02 open Assets:Kept USD\n"],
                "{shape}"
            );
            assert_eq!(scan.torn_tail_bytes, (bytes.len() - last) as u64, "{shape}");
            std::fs::remove_file(path).ok();
        }
    }

    /// T78's limit, where the widened rule must NOT reach: the checksum
    /// failure is only a crash artefact on the FINAL record. The same stale
    /// text in a payload with a record after it is corruption; and a final
    /// record whose length was damaged to run exactly to the end of the file
    /// — swallowing the intact records appended after it — is corruption too
    /// (the M-43 shape a crash cannot produce), both at the damaged record's
    /// offset.
    ///
    /// Bug-catch: drop `!has_later_intact_record(payload)` from the final-record
    /// arm and the second shape is `Ok` with one payload and two records
    /// silently dropped.
    #[test]
    fn t78_a_checksum_failure_before_the_end_or_over_an_intact_record_is_corrupt() {
        // Stale text in the MIDDLE record.
        let path = temp_journal("t78-mid");
        let (mut bytes, second) = three_records(&path);
        let payload = second + bytes[second..].iter().position(|b| *b == b'\n').unwrap() + 1;
        bytes[payload..payload + 10].copy_from_slice(b"2023-12-01");
        write_private(&path, &bytes);
        let error = read_journal(&path, 1 << 20).expect_err("mid-journal stale text");
        assert!(
            matches!(error, JournalError::Corrupt { offset, .. } if offset == second as u64),
            "got {error}"
        );
        std::fs::remove_file(path).ok();

        // The second of three claims exactly the bytes left in the file.
        let path = temp_journal("t78-swallow");
        let (bytes, second) = three_records(&path);
        let header_end = second + bytes[second..].iter().position(|b| *b == b'\n').unwrap() + 1;
        let to_end = (bytes.len() - header_end).to_string();
        let damaged = with_length(&bytes, second, &to_end);
        write_private(&path, &damaged);
        match read_journal(&path, 64 * 1024 * 1024) {
            Err(JournalError::Corrupt { offset, .. }) => assert_eq!(offset, second as u64),
            Ok(scan) => panic!(
                "a length damaged to swallow two intact records was read as a torn tail \
                 ({} payloads, {} torn bytes)",
                scan.payloads.len(),
                scan.torn_tail_bytes
            ),
            Err(other) => panic!("expected Corrupt, got {other}"),
        }
        std::fs::remove_file(path).ok();
    }

    /// A fresh private directory (mode 0700) for the T87 link tests.
    #[cfg(unix)]
    fn t87_directory(name: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let directory = std::env::temp_dir().join(format!(
            "openledger-t87-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }

    /// M-60 (T87, decision (24)): the uid check on the link and the follow are
    /// two path walks, so an account that can write the link's directory can
    /// swap its own link in between (X3 `k4a`). A link is followed only from a
    /// directory this uid owns that group and others cannot write — then no
    /// other account can replace it. The same link resolves once the
    /// directory is private again.
    ///
    /// Bug-catch: drop the directory check and the link in the
    /// group-writable directory resolves.
    #[cfg(unix)]
    #[test]
    fn m60_a_link_in_a_directory_others_can_write_is_not_followed() {
        use std::os::unix::fs::PermissionsExt;
        let directory = t87_directory("m60-dir");
        let target = directory.join("real.bean");
        std::fs::write(&target, "").unwrap();
        let link = directory.join("ledger.bean");
        std::os::unix::fs::symlink("real.bean", &link).unwrap();
        for mode in [0o770, 0o707, 0o777] {
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(mode)).unwrap();
            let error = resolve_ledger_path(&link).expect_err("a swappable link is refused");
            assert_eq!(
                error.kind(),
                std::io::ErrorKind::PermissionDenied,
                "mode {mode:o}"
            );
            assert!(error.to_string().contains("(M-60)"), "{error}");
        }
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            resolve_ledger_path(&link).unwrap(),
            std::fs::canonicalize(&target).unwrap()
        );
        std::fs::remove_dir_all(&directory).ok();
    }

    /// Swap two directories atomically (the attacker's move in M-68).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn swap_directories(a: &std::ffi::CStr, b: &std::ffi::CStr) {
        // SAFETY: two NUL-terminated paths; the call only renames.
        #[cfg(target_os = "macos")]
        unsafe {
            libc::renamex_np(a.as_ptr(), b.as_ptr(), libc::RENAME_SWAP);
        }
        // SAFETY: as above, through the raw syscall (glibc may lack the wrapper).
        #[cfg(target_os = "linux")]
        unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                libc::AT_FDCWD,
                a.as_ptr(),
                libc::AT_FDCWD,
                b.as_ptr(),
                libc::RENAME_EXCHANGE,
            );
        }
    }

    /// M-68 (T94, decision (46)), the audit's A4 `raceswap`: an account able to
    /// write the directory ABOVE the link's directory keeps swapping, with an
    /// atomic exchange, the operator's link directory (`node/`, 0755, holding
    /// `ledger.bean -> ../../store/real.bean`) and its own (`evil/`, 0777 — the
    /// rule refuses it whenever it is inspected — holding `ledger.bean ->
    /// ../../victim/secret.bean`). T87 checked the directory by path and followed
    /// the link by path again, so the rule approved `node/` and the follow used
    /// `evil/`'s link: the victim file came back ~50 times a second. Bound to
    /// one directory handle, every check and the follow see the same directory,
    /// and a path that no longer leads to the file opened through it is
    /// refused: the victim never comes back.
    ///
    /// Bug-catch: check the directory by path again (`std::fs::metadata` of the
    /// link's directory, then `canonicalize`) and the victim is returned.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn m68_a_directory_swapped_under_the_link_is_never_followed() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;
        let root = t87_directory("m68-race");
        let shared = root.join("shared");
        let store = root.join("store");
        let victim = root.join("victim");
        for directory in [&shared, &store, &victim] {
            std::fs::create_dir(directory).unwrap();
        }
        std::fs::write(store.join("real.bean"), "").unwrap();
        std::fs::write(victim.join("secret.bean"), "").unwrap();
        let node = shared.join("node");
        let evil = shared.join("evil");
        std::fs::create_dir(&node).unwrap();
        std::fs::create_dir(&evil).unwrap();
        std::os::unix::fs::symlink("../../store/real.bean", node.join("ledger.bean")).unwrap();
        std::os::unix::fs::symlink("../../victim/secret.bean", evil.join("ledger.bean")).unwrap();
        std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&evil, std::fs::Permissions::from_mode(0o777)).unwrap();
        let configured = node.join("ledger.bean");
        let real = std::fs::canonicalize(store.join("real.bean")).unwrap();
        let secret = std::fs::canonicalize(victim.join("secret.bean")).unwrap();
        assert_eq!(resolve_ledger_path(&configured).unwrap(), real, "premise");

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let swapper = {
            let stop = std::sync::Arc::clone(&stop);
            let a = std::ffi::CString::new(node.as_os_str().as_bytes()).unwrap();
            let b = std::ffi::CString::new(evil.as_os_str().as_bytes()).unwrap();
            std::thread::spawn(move || {
                let mut swaps = 0u64;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    swap_directories(&a, &b);
                    swaps += 1;
                }
                // Leave the operator's directory where it started.
                if swaps % 2 == 1 {
                    swap_directories(&a, &b);
                }
                swaps
            })
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let (mut calls, mut victim_hits, mut elsewhere) = (0u64, 0u64, 0u64);
        while std::time::Instant::now() < deadline {
            calls += 1;
            match resolve_ledger_path(&configured).ok() {
                Some(path) if path == secret => victim_hits += 1,
                // T101 / L-157: any path but the target (or the link itself,
                // when it cannot be followed) is a wrong answer too — A5-1's
                // hard link in another directory passed a count of the victim
                // alone.
                Some(path) if path != real && path != configured => elsewhere += 1,
                _ => {}
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let swaps = swapper.join().unwrap();
        std::fs::remove_dir_all(&root).ok();
        assert!(swaps > 0 && calls > 0, "premise: the race ran");
        assert_eq!(
            (victim_hits, elsewhere),
            (0, 0),
            "of {calls} resolutions, {victim_hits} returned the victim file and {elsewhere} \
             another path ({swaps} swaps)"
        );
    }

    /// M-71 (T101, decision (64); audit 0927 A5-1): the path returned is
    /// `canonicalize` of the configured path — a second walk of it — and T94
    /// accepted it on the target file's identity alone. The writer of
    /// `shared/` (above the link's directory) swaps `node/` and its own
    /// `evil/`, whose `ledger.bean` names a hard link of the operator's target
    /// inside a directory it owns (`attacker/h`): whenever the handle saw
    /// `node/` and the second walk `evil/`, the identities agreed and the node
    /// was handed `attacker/h` — a path through a directory no check looked at
    /// and the attacker writes, though the operator's target (`store/`) has no
    /// ancestor it can write. The returned path's directory must be the one
    /// the link names, reached through the handle.
    ///
    /// Bug-catch: drop the directory comparison and `attacker/h` comes back
    /// (~430 times in 5 s at `a5313a1`).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn m71_a_hard_link_in_a_directory_the_checks_never_saw_is_never_returned() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;
        let root = t87_directory("m71-hardlink");
        let shared = root.join("shared");
        let store = root.join("store");
        let attacker = root.join("attacker");
        for directory in [&shared, &store, &attacker] {
            std::fs::create_dir(directory).unwrap();
        }
        std::fs::write(store.join("real.bean"), "").unwrap();
        std::fs::hard_link(store.join("real.bean"), attacker.join("h")).unwrap();
        let node = shared.join("node");
        let evil = shared.join("evil");
        std::fs::create_dir(&node).unwrap();
        std::fs::create_dir(&evil).unwrap();
        std::os::unix::fs::symlink("../../store/real.bean", node.join("ledger.bean")).unwrap();
        std::os::unix::fs::symlink(attacker.join("h"), evil.join("ledger.bean")).unwrap();
        std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&evil, std::fs::Permissions::from_mode(0o777)).unwrap();
        let configured = node.join("ledger.bean");
        let real = std::fs::canonicalize(store.join("real.bean")).unwrap();
        assert_eq!(resolve_ledger_path(&configured).unwrap(), real, "premise");

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let swapper = {
            let stop = std::sync::Arc::clone(&stop);
            let a = std::ffi::CString::new(node.as_os_str().as_bytes()).unwrap();
            let b = std::ffi::CString::new(evil.as_os_str().as_bytes()).unwrap();
            std::thread::spawn(move || {
                let mut swaps = 0u64;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    swap_directories(&a, &b);
                    swaps += 1;
                }
                if swaps % 2 == 1 {
                    swap_directories(&a, &b);
                }
                swaps
            })
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let (mut calls, mut elsewhere) = (0u64, Vec::new());
        while std::time::Instant::now() < deadline {
            calls += 1;
            if let Ok(path) = resolve_ledger_path(&configured) {
                if path != real && path != configured {
                    elsewhere.push(path);
                }
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let swaps = swapper.join().unwrap();
        std::fs::remove_dir_all(&root).ok();
        assert!(swaps > 0 && calls > 0, "premise: the race ran");
        assert!(
            elsewhere.is_empty(),
            "{} of {calls} resolutions returned another path ({swaps} swaps), e.g. {}",
            elsewhere.len(),
            elsewhere[0].display()
        );
    }

    /// L-138 (T101): the link's directory is opened `O_DIRECTORY | O_NONBLOCK`.
    /// An ancestor's writer can swap a FIFO in at the directory's path between
    /// `symlink_metadata` and the open; a plain open blocked there for good,
    /// before the lock, with no log line (A5-3). Driven here by handing the
    /// resolution a FIFO as the link's directory: it must return at once.
    ///
    /// Bug-catch: open the directory with `File::open` again and the call
    /// never returns (the test times out after 5 s).
    #[cfg(unix)]
    #[test]
    fn l138_a_fifo_at_the_link_directorys_path_never_blocks_the_resolution() {
        let root = t87_directory("l138-fifo");
        let fifo = root.join("fifo");
        let path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        // SAFETY: a NUL-terminated path; `mkfifo` reads it only.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0, "premise");
        let configured = fifo.join("ledger.bean");
        let (sender, receiver) = std::sync::mpsc::channel();
        let directory = fifo.clone();
        std::thread::spawn(move || {
            let outcome = resolve_link_in_its_directory(&configured, &directory);
            sender.send(outcome.is_err()).ok();
        });
        let refused = receiver
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the resolution returned instead of blocking on the FIFO");
        std::fs::remove_dir_all(&root).ok();
        assert!(refused, "a FIFO is not a directory");
    }

    /// L-137 (T101, decision (65)): only an ACL entry that lets another account
    /// add or remove entries in the link's directory refuses it. macOS gives
    /// the home folders `group:everyone deny delete`; T94 refused any ACL, so
    /// a link kept in `~` stopped booting, and its `chmod -N` remedy stripped
    /// that protection. A deny entry, an inherit-only allow entry and a
    /// read-only allow entry resolve; an allow entry granting `add_file` does
    /// not.
    ///
    /// Bug-catch: refuse any entry again and the deny-only directory is
    /// refused.
    #[cfg(target_os = "macos")]
    #[test]
    fn l137_only_an_acl_entry_that_lets_others_write_refuses_the_link() {
        use std::os::unix::fs::PermissionsExt;
        let directory = t87_directory("l137-acl");
        std::fs::write(directory.join("real.bean"), "").unwrap();
        let link = directory.join("ledger.bean");
        std::os::unix::fs::symlink("real.bean", &link).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let chmod = |arguments: &[&str]| {
            let status = std::process::Command::new("chmod")
                .args(arguments)
                .arg(&directory)
                .status()
                .unwrap();
            assert!(status.success(), "chmod {arguments:?}");
        };
        let mut verdicts = Vec::new();
        for entry in [
            "group:everyone deny delete",
            "everyone allow add_file,only_inherit,file_inherit",
            "everyone allow list,readattr",
        ] {
            chmod(&["-N"]);
            chmod(&["+a", entry]);
            verdicts.push((entry, resolve_ledger_path(&link).is_ok()));
        }
        chmod(&["-N"]);
        chmod(&["+a", "everyone allow add_file"]);
        let granting = resolve_ledger_path(&link);
        chmod(&["-N"]);
        std::fs::remove_dir_all(&directory).ok();
        assert!(
            verdicts.iter().all(|(_, resolves)| *resolves),
            "{verdicts:?}"
        );
        let error = granting.expect_err("an entry granting add_file is refused");
        assert!(error.to_string().contains("L-137"), "{error}");
    }

    /// L-119 (T94): a link whose target is spelled differently from the file's
    /// on-disk name only in letter case — the same file on a case-insensitive
    /// file system (macOS's default) — resolves. T87 compared the link's
    /// spelling with `canonicalize`'s as strings and refused it as "itself a
    /// symbolic link", which it is not; the file identity is what is compared
    /// now. Skipped where the file system is case-sensitive.
    ///
    /// Bug-catch: compare the path strings again and it is refused.
    #[cfg(target_os = "macos")]
    #[test]
    fn l119_a_link_spelling_its_target_in_another_case_resolves() {
        let directory = t87_directory("l119-case");
        let store = directory.join("store");
        std::fs::create_dir(&store).unwrap();
        std::fs::write(store.join("mixed.bean"), "").unwrap();
        let link = directory.join("ledger.bean");
        std::os::unix::fs::symlink("store/MIXED.bean", &link).unwrap();
        if std::fs::metadata(&link).is_err() {
            std::fs::remove_dir_all(&directory).ok();
            return; // case-sensitive: the link is dangling here
        }
        let resolved = resolve_ledger_path(&link).expect("the same file resolves");
        assert_eq!(
            std::fs::metadata(&resolved).unwrap().len(),
            0,
            "resolved to the target"
        );
        std::fs::remove_dir_all(&directory).ok();
    }

    /// L-120 (T94, decision (47)): on macOS an access control list can let
    /// every account add and remove entries in a directory whose mode is 0700;
    /// T87 read the mode bits only, so a link there was followed. A directory
    /// carrying an ACL entry is refused; with the ACL removed it resolves.
    ///
    /// Bug-catch: drop the ACL check and the link is followed.
    #[cfg(target_os = "macos")]
    #[test]
    fn l120_a_link_in_a_directory_with_an_acl_is_not_followed() {
        use std::os::unix::fs::PermissionsExt;
        let directory = t87_directory("l120-acl");
        std::fs::write(directory.join("real.bean"), "").unwrap();
        let link = directory.join("ledger.bean");
        std::os::unix::fs::symlink("real.bean", &link).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let chmod = |arguments: &[&str]| {
            let status = std::process::Command::new("chmod")
                .args(arguments)
                .arg(&directory)
                .status()
                .unwrap();
            assert!(status.success(), "chmod {arguments:?}");
        };
        chmod(&[
            "+a",
            "everyone allow add_file,add_subdirectory,delete_child",
        ]);
        let error = resolve_ledger_path(&link).expect_err("refused");
        assert!(error.to_string().contains("L-120"), "{error}");
        chmod(&["-N"]);
        assert!(
            resolve_ledger_path(&link).is_ok(),
            "resolves once the ACL is gone"
        );
        std::fs::remove_dir_all(&directory).ok();
    }

    /// M-60 (T87, decision (24)): one hop. `ledger.bean -> middle -> real` is
    /// refused — `middle`'s owner and directory were never checked (A5 `P5`,
    /// X3 `k4b`: the chain resolved to the far end). A single link resolves,
    /// with a relative or an absolute target, and so does one whose target
    /// sits under a DIRECTORY link, by the documented policy.
    ///
    /// Bug-catch: drop the one-hop comparison and the chain resolves.
    #[cfg(unix)]
    #[test]
    fn m60_a_chain_of_links_is_refused_and_a_directory_link_is_followed() {
        let directory = t87_directory("m60-chain");
        let real_directory = directory.join("volume");
        std::fs::create_dir(&real_directory).unwrap();
        let target = real_directory.join("real.bean");
        std::fs::write(&target, "").unwrap();
        let canonical = std::fs::canonicalize(&target).unwrap();

        let middle = directory.join("middle.bean");
        std::os::unix::fs::symlink(&target, &middle).unwrap();
        let chained = directory.join("chained.bean");
        std::os::unix::fs::symlink("middle.bean", &chained).unwrap();
        let error = resolve_ledger_path(&chained).expect_err("a chain is refused");
        assert!(
            error.to_string().contains("itself a symbolic link"),
            "{error}"
        );

        let relative = directory.join("relative.bean");
        std::os::unix::fs::symlink("volume/real.bean", &relative).unwrap();
        assert_eq!(resolve_ledger_path(&relative).unwrap(), canonical);
        assert_eq!(
            resolve_ledger_path(&middle).unwrap(),
            canonical,
            "absolute target"
        );

        let directory_link = directory.join("mounted");
        std::os::unix::fs::symlink(&real_directory, &directory_link).unwrap();
        let through = directory.join("through.bean");
        std::os::unix::fs::symlink("mounted/real.bean", &through).unwrap();
        assert_eq!(resolve_ledger_path(&through).unwrap(), canonical);
        std::fs::remove_dir_all(&directory).ok();
    }

    /// M-61 (T87, decision (25)): a journal beside the LINK belongs to the
    /// ledger that was at the link's path before it became a link — an unclean
    /// stop, then the README's move-behind-a-link. The node journals at the
    /// target, so it would never read it and its acknowledged records would
    /// be silently absent (X3 `k4f`). Refused, naming both remedies; nothing
    /// is moved. The control: no stray journal, and it resolves.
    ///
    /// Bug-catch: drop the stray-journal check and the link resolves.
    #[cfg(unix)]
    #[test]
    fn m61_a_journal_beside_the_link_is_refused() {
        let directory = t87_directory("m61");
        let target = directory.join("real.bean");
        std::fs::write(&target, "").unwrap();
        let link = directory.join("ledger.bean");
        std::os::unix::fs::symlink("real.bean", &link).unwrap();
        assert!(resolve_ledger_path(&link).is_ok(), "control");
        let stray = journal_path_for(&link);
        std::fs::write(&stray, ";;olj 0 e3b0\n").unwrap();
        let error = resolve_ledger_path(&link).expect_err("refused");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(
            error.to_string().contains("(M-61, H-15)")
                && error.to_string().contains("real.bean.journal"),
            "{error}"
        );
        assert!(stray.exists(), "nothing is moved or deleted");
        std::fs::remove_dir_all(&directory).ok();
    }

    /// L-105 (T86): L-85's shape with the third record torn inside the first
    /// five bytes of its header (`;` … `;;olj`), before a complete `;;olj `
    /// exists to be found. T82's discriminator needed that complete tag, so
    /// the damaged, acknowledged second record was still dropped as a torn
    /// tail (A5 `a5_p4`: cuts of 3 and 5 bytes). It fails closed now, like
    /// every longer cut; the control — the same short tail after an intact
    /// second record — is an ordinary torn tail.
    ///
    /// Bug-catch: drop the no-candidate branch in `has_later_intact_record`
    /// and every cut here reads `Ok` with one intact record.
    #[test]
    fn l105_a_damaged_length_over_an_append_torn_inside_its_tag_is_corrupt() {
        for cut in 1..=5usize {
            let path = temp_journal(&format!("l105-cut-{cut}"));
            let (bytes, second) = three_records(&path);
            let third = second
                + bytes[second..]
                    .windows(6)
                    .skip(1)
                    .position(|window| window == b";;olj ")
                    .unwrap()
                + 1;
            let torn = bytes[..third + cut].to_vec();
            let header_end = second + torn[second..].iter().position(|b| *b == b'\n').unwrap() + 1;
            let damaged = with_length(&torn, second, &(torn.len() - header_end).to_string());
            write_private(&path, &damaged);
            match read_journal(&path, 64 * 1024 * 1024) {
                Err(JournalError::Corrupt { offset, .. }) => {
                    assert_eq!(offset, second as u64, "cut {cut}")
                }
                Ok(scan) => panic!(
                    "cut {cut}: an acknowledged record behind a damaged length was dropped as \
                     torn ({} payloads, {} torn bytes)",
                    scan.payloads.len(),
                    scan.torn_tail_bytes
                ),
                Err(other) => panic!("cut {cut}: expected Corrupt, got {other}"),
            }
            std::fs::remove_file(&path).ok();

            let path = temp_journal(&format!("l105-control-{cut}"));
            write_private(&path, &torn);
            let scan = read_journal(&path, 64 * 1024 * 1024).expect("a torn tail");
            assert_eq!(scan.payloads.len(), 2, "control, cut {cut}");
            assert_eq!(scan.torn_tail_bytes, cut as u64, "control, cut {cut}");
            std::fs::remove_file(&path).ok();
        }
    }

    /// L-122 (T93): L-105's shape in the OTHER arm — the second record's length
    /// damaged to claim MORE bytes than the file holds, over a third append
    /// torn inside the first five bytes of its tag. The over-claim arm failed
    /// closed only on a complete `;;olj ` line, so the acknowledged second
    /// record was dropped as a torn tail (D1 `case_l105b`: cuts 1, 3, 5), where
    /// CHANGELOG says a damaged length over a torn append fails closed. The
    /// control — the same over-claim with no later append — is still a torn
    /// final record (M-43's accepted policy).
    ///
    /// Bug-catch: drop the `has_later_intact_record` term in the over-claim
    /// arm and every cut reads `Ok` with one intact record.
    #[test]
    fn l122_an_over_long_length_over_an_append_torn_inside_its_tag_is_corrupt() {
        for cut in 1..=5usize {
            let path = temp_journal(&format!("l122-cut-{cut}"));
            let (bytes, second) = three_records(&path);
            let third = second
                + bytes[second..]
                    .windows(6)
                    .skip(1)
                    .position(|window| window == b";;olj ")
                    .unwrap()
                + 1;
            let torn = bytes[..third + cut].to_vec();
            let header_end = second + torn[second..].iter().position(|b| *b == b'\n').unwrap() + 1;
            let over = (torn.len() - header_end + 64).to_string();
            write_private(&path, with_length(&torn, second, &over));
            match read_journal(&path, 64 * 1024 * 1024) {
                Err(JournalError::Corrupt { offset, .. }) => {
                    assert_eq!(offset, second as u64, "cut {cut}")
                }
                Ok(scan) => panic!(
                    "cut {cut}: an acknowledged record behind an over-long length was dropped as \
                     torn ({} payloads, {} torn bytes)",
                    scan.payloads.len(),
                    scan.torn_tail_bytes
                ),
                Err(other) => panic!("cut {cut}: expected Corrupt, got {other}"),
            }
            std::fs::remove_file(&path).ok();
        }
        let path = temp_journal("l122-control");
        let (bytes, second) = three_records(&path);
        let third = second
            + bytes[second..]
                .windows(6)
                .skip(1)
                .position(|window| window == b";;olj ")
                .unwrap()
            + 1;
        let two = bytes[..third].to_vec();
        let header_end = second + two[second..].iter().position(|b| *b == b'\n').unwrap() + 1;
        let over = (two.len() - header_end + 64).to_string();
        write_private(&path, with_length(&two, second, &over));
        let scan = read_journal(&path, 64 * 1024 * 1024).expect("a torn final record");
        assert_eq!(scan.payloads.len(), 1, "control");
        std::fs::remove_file(&path).ok();
    }

    /// L-85 (T82): the second of three records has its length damaged to run
    /// to the end of the file, and the third is torn (a crash mid-append).
    /// The torn third's header parses but claims more than is left, and the
    /// second's payload up to it verifies against the second's own hash — so
    /// this is a damaged, acknowledged record, and it fails closed. Before
    /// T82 it was read as a torn tail and the second record was dropped.
    /// The stale-block shape (T78) is unchanged: a region whose prefix does
    /// not verify stays torn.
    ///
    /// Bug-catch: drop the prefix check in `has_later_intact_record` and the
    /// read returns `Ok` with one intact record.
    #[test]
    fn l85_a_damaged_length_over_a_torn_later_append_is_corrupt() {
        let path = temp_journal("l85-torn-successor");
        let (bytes, second) = three_records(&path);
        let third = second
            + bytes[second..]
                .windows(6)
                .skip(1)
                .position(|window| window == b";;olj ")
                .unwrap()
            + 1;
        let torn = bytes[..third + (bytes.len() - third) / 2].to_vec();
        let header_end = second + torn[second..].iter().position(|b| *b == b'\n').unwrap() + 1;
        let to_end = (torn.len() - header_end).to_string();
        let damaged = with_length(&torn, second, &to_end);
        write_private(&path, &damaged);
        match read_journal(&path, 64 * 1024 * 1024) {
            Err(JournalError::Corrupt { offset, .. }) => assert_eq!(offset, second as u64),
            Ok(scan) => panic!(
                "an acknowledged record behind a damaged length was dropped as torn ({} \
                 payloads, {} torn bytes)",
                scan.payloads.len(),
                scan.torn_tail_bytes
            ),
            Err(other) => panic!("expected Corrupt, got {other}"),
        }
        std::fs::remove_file(&path).ok();

        // Control: the same torn third with the second record intact is an
        // ordinary torn tail.
        let path = temp_journal("l85-control");
        let (bytes, second) = three_records(&path);
        let third = second
            + bytes[second..]
                .windows(6)
                .skip(1)
                .position(|window| window == b";;olj ")
                .unwrap()
            + 1;
        write_private(&path, &bytes[..third + (bytes.len() - third) / 2]);
        let scan = read_journal(&path, 64 * 1024 * 1024).expect("a torn tail");
        assert_eq!(scan.payloads.len(), 2);
        assert!(scan.torn_tail_bytes > 0);
        std::fs::remove_file(&path).ok();
    }

    /// 0924 §5 (T83): a followed path (the operator's `.bean` or config) may
    /// be a symbolic link, so a dangling one is refused as DANGLING — the old
    /// message said symbolic links are refused, which they are not.
    #[cfg(unix)]
    #[test]
    fn t83_a_dangling_followed_link_is_named_dangling() {
        let directory =
            std::env::temp_dir().join(format!("openledger-t83-dangling-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let link = directory.join("config.json");
        let _ = std::fs::remove_file(&link);
        std::os::unix::fs::symlink(directory.join("absent.json"), &link).unwrap();
        let mut options = OpenOptions::new();
        options.read(true);
        let error = match open_checked(&link, &options, FileTrust::OperatorConfig, "config file") {
            Ok(_) => panic!("a dangling link must be refused"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("dangling symbolic link"),
            "{error}"
        );
        std::fs::remove_dir_all(&directory).ok();
    }

    // ── T67: file-type discipline (M-36, L-58) ──────────────────────────

    /// Run `body` on its own thread and fail — rather than hang the suite — if
    /// it has not returned within `seconds`. A regression here means an `open`
    /// parked on a FIFO, so the thread is abandoned, not joined.
    fn within<T: Send + 'static>(seconds: u64, body: impl FnOnce() -> T + Send + 'static) -> T {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(body());
        });
        receiver
            .recv_timeout(std::time::Duration::from_secs(seconds))
            .expect("M-36: the call blocked (an open parked on a FIFO?)")
    }

    #[cfg(unix)]
    fn mkfifo(path: &Path) {
        let status = std::process::Command::new("mkfifo")
            .arg(path)
            .status()
            .unwrap();
        assert!(status.success(), "mkfifo {}", path.display());
    }

    /// M-36: a FIFO at the journal path. `append_record` used to block in
    /// `open(O_WRONLY|O_CREAT)` before its own `is_file()` check ran — on the
    /// blocking thread holding the `WritePermit`, forever. `read_journal`
    /// blocked the same way at boot. Both now return `Err` at once.
    ///
    /// Bug-catch: drop `O_NONBLOCK` and the `lstat` type check and the append
    /// blocks until `within` gives up.
    #[cfg(unix)]
    #[test]
    fn m36_a_fifo_journal_is_refused_without_blocking() {
        let path = temp_journal("m36-fifo");
        mkfifo(&path);
        let append_path = path.clone();
        let appended = within(5, move || {
            append_record(&append_path, &record_bytes("x\n")).map_err(|e| e.to_string())
        });
        let error = appended.expect_err("a FIFO is not a journal");
        assert!(error.contains("not a regular file"), "{error}");

        let read_path = path.clone();
        let read = within(5, move || {
            read_journal(&read_path, 1 << 20)
                .map(|_| ())
                .map_err(|e| e.to_string())
        });
        assert!(read.is_err(), "boot's journal read must refuse a FIFO too");
        std::fs::remove_file(path).ok();
    }

    /// T67: the reads refuse a symlink, as the append always has (L-44).
    #[cfg(unix)]
    #[test]
    fn t67_read_journal_refuses_a_symlinked_journal() {
        let path = temp_journal("t67-read-link");
        let target = path.with_extension("target");
        append_record(&target, &record_bytes("elsewhere\n")).unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        let error = read_journal(&path, 1 << 20).unwrap_err().to_string();
        assert!(error.contains("symbolic link"), "{error}");
        std::fs::remove_file(path).ok();
        std::fs::remove_file(target).ok();
    }

    /// L-58: a journal pre-planted as 0644 used to receive every commit in a
    /// file others can read (`mode(0o600)` applies only on create). The append
    /// is refused and the file is left byte-for-byte as it was.
    ///
    /// Bug-catch: drop the mode check in `open_checked` and the record lands.
    #[cfg(unix)]
    #[test]
    fn l58_append_refuses_a_world_readable_journal_and_leaves_it_unchanged() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_journal("l58-mode");
        std::fs::write(&path, b"").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        let error = append_record(&path, &record_bytes("secret\n")).unwrap_err();
        assert!(error.to_string().contains("overly permissive"), "{error}");
        assert!(std::fs::read(&path).unwrap().is_empty(), "nothing appended");
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644,
            "and nothing chmod'ed"
        );

        // The read side tolerates the read bits (records loaded, never
        // appended to) and says so, so the ledger can fold it away.
        let scan = read_journal(&path, 1 << 20).expect("group/world read bits are tolerated");
        assert!(scan.readable_by_others);
        std::fs::remove_file(path).ok();
    }

    /// L-58: a hard link from the journal path to a file elsewhere passed the
    /// regular-file and `(dev, ino)` checks and received every commit. Refused
    /// on append (and on read), both names unchanged.
    ///
    /// Bug-catch: drop the `nlink` check and the record lands in both.
    #[cfg(unix)]
    #[test]
    fn l58_append_refuses_a_hard_linked_journal_and_leaves_it_unchanged() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_journal("l58-link");
        let elsewhere = path.with_extension("elsewhere");
        std::fs::write(&elsewhere, b"").unwrap();
        std::fs::set_permissions(&elsewhere, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::hard_link(&elsewhere, &path).unwrap();

        let error = append_record(&path, &record_bytes("secret\n")).unwrap_err();
        assert!(error.to_string().contains("hard links"), "{error}");
        assert!(
            std::fs::read(&elsewhere).unwrap().is_empty(),
            "nothing appended"
        );
        assert!(read_journal(&path, 1 << 20).is_err(), "nor read");
        std::fs::remove_file(path).ok();
        std::fs::remove_file(elsewhere).ok();
    }

    /// M-36's cap bypass, at the reader: a source of `cap + 1` bytes is refused
    /// with `FileTooLarge` after reading at most one byte past the cap; exactly
    /// `cap` bytes is fine. Run at the real 64 MiB cap, over an endless stream
    /// (the shape a FIFO fed 73 MB used to be) cut to `cap + 1`.
    ///
    /// Bug-catch: read without `take(cap + 1)` / the length check and the
    /// over-cap read succeeds.
    #[test]
    fn m36_a_stream_one_byte_past_the_cap_is_refused() {
        let cap = crate::service::MAX_LEDGER_FILE_BYTES;
        let over = read_to_end_capped(std::io::repeat(b';').take(cap + 1), 0, cap);
        assert_eq!(
            over.expect_err("64 MiB + 1 must be refused").kind(),
            std::io::ErrorKind::FileTooLarge
        );
        let endless = read_to_end_capped(std::io::repeat(b';'), 0, 1024);
        assert!(
            endless.is_err(),
            "an endless stream stops one byte past the cap"
        );
        let exact = read_to_end_capped(std::io::repeat(b';').take(cap), 0, cap).unwrap();
        assert_eq!(exact.len() as u64, cap);
    }

    /// `geteuid` through `libc` (R-17) is the uid the kernel stamps on a file
    /// this process creates — otherwise every owner check would refuse the
    /// node's own files.
    #[cfg(unix)]
    #[test]
    fn r17_effective_uid_owns_the_files_this_process_creates() {
        use std::os::unix::fs::MetadataExt;
        let path = temp_journal("r17-uid");
        append_record(&path, &record_bytes("x\n")).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().uid(), effective_uid());
        std::fs::remove_file(path).ok();
    }
}
