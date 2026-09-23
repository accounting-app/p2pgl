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
//! warning because a torn record is by definition one whose commit never
//! returned success to a caller.
//!
//! # File layout
//!
//! `<ledger>.bean` keeps its exact format and its exact atomic write path.
//! `<ledger>.bean.journal` holds the directives that are durable but not yet
//! folded into the canonical file. The pair is unioned at boot; compaction
//! rewrites the canonical file from memory and then deletes the journal.
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
//!   Length alone would accept a record whose middle was overwritten.
//!
//! # Failure policy (T44 hard invariant 4)
//!
//! * A **torn final record** — the file ends inside a header line, or inside a
//!   payload whose header promised more bytes than are present — is the normal
//!   crash artefact. It is dropped with a `warn!` and the caller is told, so it
//!   can force the next commit to compact (appending *after* a torn record
//!   would let the scanner read payload bytes as a header, so this is not
//!   merely tidiness).
//! * **Anything else fails closed**: a complete-but-malformed header, a payload
//!   whose hash does not match, a payload that is not UTF-8, a journal larger
//!   than the budget. These cannot be produced by a crash — only by a hand
//!   edit or by real corruption — and the ledger refuses to boot on top of
//!   them rather than silently discarding directives it was told were durable.
//!
//! **Hand-editing the journal is unsupported.** It is node-private state, not
//! an interchange format; the supported way to hand-edit a ledger is the
//! canonical `.bean`, which the T35 adoption path merges in. A journal edited
//! by hand will fail closed on its hash, which is the intended outcome.

use std::io::Write;
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
                write!(f, "ledger journal is {length} bytes (max {budget})")
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
}

/// Frame one commit's canonical text as a journal record.
pub fn record_bytes(payload: &str) -> String {
    let digest = Sha256::digest(payload.as_bytes());
    let hash: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{RECORD_TAG} {} {hash}\n{payload}", payload.len())
}

/// Read and validate a journal, tolerating exactly one torn trailing record.
///
/// `budget` caps the file size — the ledger passes what is left of
/// `MAX_LEDGER_FILE_BYTES` after the canonical file, so canonical ∪ journal can
/// never exceed the cap that bounds the compacted file (T44 hard invariant 5).
///
/// An absent journal is an empty scan, not an error: that is the steady state
/// of every ledger small enough to be compacted on every write.
pub fn read_journal(path: &Path, budget: u64) -> Result<JournalScan, JournalError> {
    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(JournalScan::default())
        }
        Err(error) => return Err(JournalError::Io(error)),
    };
    let length = metadata.len();
    if length > budget {
        return Err(JournalError::TooLarge { length, budget });
    }

    // Read as bytes, not as a `String`: a torn write can split a multi-byte
    // character, and `read_to_string` would turn a tolerable crash artefact
    // into a hard failure.
    let bytes = std::fs::read(path)?;
    let mut scan = JournalScan {
        file_bytes: length,
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
            // The header promised more bytes than the file holds. Only a crash
            // between `write_all` and `sync_all` (or a truncated file) produces
            // this, and only ever at the end. A length too large to be real at
            // all (L-41) takes this same branch: it is the same observation —
            // "claims more than exists" — and the record is dropped as torn,
            // exactly like any other over-long claim.
            scan.torn_tail_bytes = (bytes.len() - record_start) as u64;
            break;
        }
        let payload = &bytes[cursor..cursor + payload_length];
        cursor += payload_length;

        let digest = Sha256::digest(payload);
        let actual_hash: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
        if actual_hash != expected_hash {
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

/// Parse `;;olj <len> <sha256hex>` into its two fields.
///
/// A length that is a well-formed number too large for `usize` saturates to
/// `usize::MAX` rather than failing the parse (L-41). It is still a header that
/// claims more bytes than the file can hold — the file is capped far below
/// `usize::MAX` — so [`read_journal`] must classify it exactly as it classifies
/// every other over-long claim, and that classification belongs in one place
/// (the payload bound check), not split across a parse error here and a torn
/// tail there depending on how many digits were written.
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
pub fn append_record(path: &Path, record: &str) -> Result<(u64, bool), std::io::Error> {
    // L-44's sibling on the append path. `open(O_APPEND|O_CREAT)` follows a
    // symlink planted at the journal path, so a directory-writable attacker
    // could have the node create, and append ledger records to, any file it
    // can reach. `lstat` first — it does not follow the link — and refuse a
    // symlink outright; `Path::exists` (which this used to call) follows it,
    // and so reported a dangling link as "absent, create it".
    let created_now = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return Err(refuse_non_regular_journal(path));
        }
        Ok(_) => false,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => return Err(error),
    };

    let mut options = std::fs::OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // Owner-only, exactly like the `.bean` — the journal carries the same
        // directives and would otherwise be the easier file to read.
        options.mode(0o600);
    }
    let mut file = options.open(path)?;

    // The `lstat` above and the `open` are two syscalls, so a link swapped in
    // between them is still followed by the `open`. Close that window for the
    // WRITE — the part that matters — by checking that the handle is the very
    // inode now sitting at `path`, as a regular file, before a byte is
    // appended. (A true `O_NOFOLLOW` would close it for the create too; std
    // exposes no portable constant for it and this crate takes no `libc`.)
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata()?;
        let at_path = std::fs::symlink_metadata(path)?;
        if !at_path.file_type().is_file()
            || opened.dev() != at_path.dev()
            || opened.ino() != at_path.ino()
        {
            return Err(refuse_non_regular_journal(path));
        }
    }

    file.write_all(record.as_bytes())?;
    file.sync_all()?;
    let length = file.metadata()?.len();

    if created_now {
        sync_parent_directory(path);
    }
    Ok((length, created_now))
}

/// The error an append returns when the journal path is not a plain file this
/// node can own (L-44). An I/O error, so the commit fails and the L-13 reload
/// runs exactly as for any other failed append.
fn refuse_non_regular_journal(path: &Path) -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        format!(
            "refusing to append to ledger journal {}: it is a symlink or was replaced \
             while being opened",
            path.display()
        ),
    )
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

#[cfg(test)]
mod tests {
    use super::*;

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
        std::fs::write(&path, &full[..full.len() - 5]).unwrap();

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
        std::fs::write(&path, &bytes).unwrap();

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
        std::fs::write(&path, &bytes).unwrap();

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
        std::fs::write(&path, b";;olj not-a-number deadbeef\nbody\n").unwrap();
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

    /// L-41: a header claiming `usize::MAX` bytes is an over-long claim like
    /// any other — a torn tail — and never a panic.
    ///
    /// Before the fix `cursor + payload_length` overflowed (`attempt to add
    /// with overflow`; release builds run `overflow-checks = true`), and
    /// `read_journal` is the body of `recover_failed_commit`, so the panic
    /// landed in a live node holding the ledger write lock.
    #[test]
    fn l41_a_usize_max_header_length_is_a_torn_tail_not_a_panic() {
        let path = temp_journal("l41-usize-max");
        let mut bytes = header_claiming(&usize::MAX.to_string()).into_bytes();
        bytes.extend_from_slice(b"a few payload bytes\n");
        std::fs::write(&path, &bytes).unwrap();

        let scan = read_journal(&path, 1 << 20).expect("an over-long claim is torn, not corrupt");
        assert!(scan.payloads.is_empty());
        assert_eq!(
            scan.torn_tail_bytes,
            bytes.len() as u64,
            "the whole unreadable record is the torn tail, exactly as for any header \
             that promises more bytes than exist"
        );
        std::fs::remove_file(path).ok();
    }

    /// L-41, the other shape: a length that is itself representable but that
    /// overflows once added to a non-zero cursor. An intact record precedes it,
    /// so it must survive exactly as it does in the ordinary torn-tail case.
    #[test]
    fn l41_a_header_length_that_overflows_the_cursor_is_a_torn_tail() {
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
        std::fs::write(&path, &bytes).unwrap();

        let scan = read_journal(&path, 1 << 20).expect("an over-long claim is torn, not corrupt");
        assert_eq!(scan.payloads, vec!["kept\n"]);
        assert_eq!(scan.torn_tail_bytes, (bytes.len() - kept.len()) as u64);
        std::fs::remove_file(path).ok();
    }

    /// A length with more digits than `usize` can hold is the same claim, and
    /// gets the same answer — not a parse error on one side of 20 digits and a
    /// torn tail on the other.
    #[test]
    fn l41_a_length_wider_than_usize_is_a_torn_tail_too() {
        let path = temp_journal("l41-wide");
        append_record(&path, &record_bytes("kept\n")).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        let kept = bytes.len();
        bytes.extend_from_slice(header_claiming(&"9".repeat(40)).as_bytes());
        std::fs::write(&path, &bytes).unwrap();

        let scan = read_journal(&path, 1 << 20).unwrap();
        assert_eq!(scan.payloads, vec!["kept\n"]);
        assert_eq!(scan.torn_tail_bytes, (bytes.len() - kept) as u64);
        std::fs::remove_file(path).ok();
    }

    /// The saturation above is for OVERFLOW only: a length that is not a
    /// number at all is still a malformed complete header, and fails closed.
    #[test]
    fn l41_a_non_numeric_length_still_fails_closed() {
        let path = temp_journal("l41-not-a-number");
        std::fs::write(&path, header_claiming("-1")).unwrap();
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
}
