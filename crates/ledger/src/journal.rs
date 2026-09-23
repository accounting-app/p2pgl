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
//!   - the **final** record's payload is complete but fails its checksum and
//!     contains a NUL byte. A node-written payload never contains NUL; a
//!     metadata-first filesystem (XFS, ext4 `data=writeback`) that loses power
//!     between `write_all` and `sync_all` can expose the appended region as
//!     zeros at its new length (M-44). A header line holding NUL with no later
//!     record header is the same artefact one block earlier.
//! * **Anything else fails closed**: a complete-but-malformed header, a
//!   non-final payload whose checksum does not match, a payload that is not
//!   UTF-8, a journal larger than the budget. A crash does not produce these
//!   on the filesystems the NUL rule covers — a hand edit or real corruption
//!   does — and the ledger refuses to boot on top of them rather than silently
//!   discarding directives it was told were durable.
//!
//! The torn rule is a heuristic about bytes, so the bytes it drops are never
//! destroyed on its strength: see the `.torn-*` rename above.
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
            if over_budget || has_later_record_header(&bytes[cursor..]) {
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
            // M-44: the final record, complete by length, whose payload holds
            // a NUL byte — the zero-filled tail a metadata-first filesystem
            // exposes after a power loss between `write_all` and `sync_all`.
            // No node-written payload contains NUL, so this is the crash
            // artefact, not an edit; anywhere but the end it is still corrupt.
            if cursor == bytes.len() && payload.contains(&0) {
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
    // it would take an `fcntl(F_SETFL)`, an `unsafe` FFI call this crate
    // avoids for no behavioural gain.
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
    /// blocks either way (`O_NONBLOCK`). Note what the node WRITES is a
    /// different matter: every full rewrite is temp + `rename` in the link's
    /// directory, so the first compaction replaces the link itself with a
    /// regular `.bean` and leaves the target untouched (it always has). To keep
    /// the ledger elsewhere, symlink the data directory instead.
    OperatorLedger,
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
/// 1. **`lstat`** (or `stat` for [`FileTrust::OperatorLedger`], which follows a
///    symlink by policy) and require a regular file. Refusing here means a
///    FIFO, device or directory is never opened at all.
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

    let follow = trust == FileTrust::OperatorLedger;
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
    if trust != FileTrust::OperatorLedger {
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
/// effective uid. This is the workspace's one production `unsafe` expression.
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
