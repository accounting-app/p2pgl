//! A company's bank-feed inbox (build-log 008): the bank transactions fetched
//! from Plaid that no one has booked yet, and the ones a bookkeeper ignored.
//!
//! One file per ledger folder, [`BANK_INBOX_FILE`], on the node that holds the
//! company's banks only: it is not part of the ledger and never replicates. A
//! transaction reaches the books — and the other nodes — only once a person
//! books it (`classifyBankTransactions`). Plain JSON, node-private like the
//! secret store (opened through [`ledger::journal::open_checked`] with
//! [`FileTrust::NodePrivate`]: no symlink, a regular file owned by this uid,
//! mode 0600), and backed up with the ledger's folder: the `.bean` holds the
//! same data once a transaction is booked (008 decision 5).
//!
//! Each change writes the whole file through a fresh temp file, fsync and
//! rename, so a crash leaves the old file or the new one, never half of one.
//! One [`BankInbox`] per folder at a time: `crate::plaid::PlaidService` holds
//! the ledger's one instance behind a mutex for as long as the ledger runs.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use ledger::journal::{open_checked, read_to_end_capped, FileTrust};

/// The inbox's file name inside a ledger folder.
pub(crate) const BANK_INBOX_FILE: &str = "bank-inbox.json";

const FORMAT_VERSION: u32 = 1;

/// The most transactions waiting at once: months of a busy company's banks.
/// A fetch that would pass it stops before storing that page's place at Plaid,
/// so nothing is lost; it goes on once some are booked or ignored.
pub(crate) const MAX_WAITING: usize = 20_000;

/// The most ignored transactions kept (each one is remembered so it is not
/// fetched into the inbox again).
pub(crate) const MAX_IGNORED: usize = 50_000;

/// The largest inbox file written or read: room for the caps with ordinary
/// bank text (a transaction takes a few hundred bytes). A write past it is
/// refused (`Full`) and changes nothing; a larger file is not read.
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

/// A bank transaction waiting to be booked: what the bookkeeper sees, and all
/// booking needs. Only these fields of Plaid's answer are kept.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct InboxTransaction {
    pub transaction_id: String,
    /// The bank (Plaid item) and account it is from.
    pub item_id: String,
    pub account_id: String,
    /// The date the bank posted it.
    pub date: chrono::NaiveDate,
    /// As the bank account's posting will carry it: money out is negative
    /// (Plaid's own sign turned).
    pub amount: rust_decimal::Decimal,
    pub currency: String,
    /// Plaid's merchant name, when it has one.
    #[serde(default)]
    pub payee: Option<String>,
    /// The bank's description of it.
    #[serde(default)]
    pub description: Option<String>,
    /// Plaid's category (`FOOD_AND_DRINK`, …): a hint, never used to book.
    #[serde(default)]
    pub category: Option<String>,
    /// When it was fetched (RFC 3339, UTC).
    pub fetched_at: String,
}

/// A transaction a bookkeeper ignored: never booked, never fetched again.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IgnoredTransaction {
    pub item_id: String,
    /// When (RFC 3339, UTC) and by whom (a user id, or `operator`).
    pub at: String,
    pub by: String,
    #[serde(default)]
    pub reason: Option<String>,
}

/// What the inbox holds, by Plaid transaction id.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct InboxContents {
    pub waiting: BTreeMap<String, InboxTransaction>,
    pub ignored: BTreeMap<String, IgnoredTransaction>,
}

impl InboxContents {
    /// Whether the inbox has `transaction_id` already: waiting or ignored.
    pub(crate) fn holds(&self, transaction_id: &str) -> bool {
        self.waiting.contains_key(transaction_id) || self.ignored.contains_key(transaction_id)
    }

    /// Take what Plaid sent of transactions still waiting — by either fetch,
    /// as they share the bank's place at Plaid: one sent again (a restart of
    /// Plaid's pages) or modified, as it is now; one removed, dropped. A
    /// booked one is never here: the books are not changed by the node. How
    /// many were updated and dropped.
    pub(crate) fn take_plaid_changes<'a>(
        &mut self,
        sent: impl IntoIterator<Item = &'a crate::plaid::PostedTransaction>,
        removed: &[String],
    ) -> (usize, usize) {
        let mut updated = 0;
        for transaction in sent {
            let Some(waiting) = self.waiting.get_mut(&transaction.transaction_id) else {
                continue;
            };
            let Some(currency) = &transaction.currency else {
                continue;
            };
            let now = InboxTransaction {
                date: transaction.date,
                amount: -transaction.amount,
                currency: currency.clone(),
                payee: transaction.merchant_name.clone(),
                description: transaction.name.clone(),
                category: transaction.category.clone(),
                ..waiting.clone()
            };
            if *waiting != now {
                *waiting = now;
                updated += 1;
            }
        }
        let mut dropped = 0;
        for id in removed {
            if self.waiting.remove(id).is_some() {
                dropped += 1;
            }
        }
        (updated, dropped)
    }
}

#[derive(Serialize, Deserialize)]
struct InboxFile {
    version: u32,
    #[serde(flatten)]
    contents: InboxContents,
}

#[derive(Debug)]
pub(crate) enum InboxError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Corrupt {
        path: PathBuf,
        detail: String,
    },
    /// The change would pass [`MAX_WAITING`] or [`MAX_IGNORED`]; nothing was
    /// changed.
    Full(&'static str),
}

impl fmt::Display for InboxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Corrupt { path, detail } => write!(
                f,
                "{} is not a bank inbox this node can read: {detail}",
                path.display()
            ),
            Self::Full(what) => write!(f, "the bank inbox is full: {what}"),
        }
    }
}

impl std::error::Error for InboxError {}

/// How many bookings [`BankInbox::booked_lately`] remembers: far more than are
/// made while one fetch runs.
const BOOKED_LATELY: usize = 100_000;

/// A ledger's bank inbox, as on disk.
pub(crate) struct BankInbox {
    path: PathBuf,
    contents: InboxContents,
    /// Transactions booked since this node started, newest last (in memory
    /// only): a fetch or `syncBank` running meanwhile read the books before
    /// they were booked, and checks here so it does not take one again.
    booked: std::collections::HashSet<String>,
    booked_order: std::collections::VecDeque<String>,
}

impl fmt::Debug for BankInbox {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BankInbox")
            .field("path", &self.path)
            .field("waiting", &self.contents.waiting.len())
            .field("ignored", &self.contents.ignored.len())
            .finish()
    }
}

impl BankInbox {
    /// Open `folder`'s inbox. No file is an empty inbox (nothing is written
    /// until a change). Temp files a crashed write left are deleted first.
    pub(crate) fn open(folder: &Path) -> Result<Self, InboxError> {
        sweep_leftover_temp_files(folder);
        let path = folder.join(BANK_INBOX_FILE);
        let contents = read_inbox_file(&path)?.unwrap_or_default();
        Ok(Self {
            path,
            contents,
            booked: std::collections::HashSet::new(),
            booked_order: std::collections::VecDeque::new(),
        })
    }

    pub(crate) fn contents(&self) -> &InboxContents {
        &self.contents
    }

    /// Remember that `transaction_id` was just booked (see [`Self::booked_lately`]).
    #[allow(dead_code)] // booking comes with 008 unit 2
    pub(crate) fn note_booked(&mut self, transaction_id: &str) {
        if self.booked.insert(transaction_id.to_owned()) {
            self.booked_order.push_back(transaction_id.to_owned());
            if self.booked_order.len() > BOOKED_LATELY {
                if let Some(oldest) = self.booked_order.pop_front() {
                    self.booked.remove(&oldest);
                }
            }
        }
    }

    /// Whether `transaction_id` was booked since this node started — after a
    /// fetch running now read the books.
    pub(crate) fn booked_lately(&self, transaction_id: &str) -> bool {
        self.booked.contains(transaction_id)
    }

    /// Change the inbox and store it: `change` works on a copy, which
    /// replaces the inbox only once it is on disk, so a refused or failed
    /// write changes nothing.
    pub(crate) fn update<T>(
        &mut self,
        change: impl FnOnce(&mut InboxContents) -> T,
    ) -> Result<T, InboxError> {
        let mut next = self.contents.clone();
        let result = change(&mut next);
        if next == self.contents {
            return Ok(result);
        }
        if next.waiting.len() > MAX_WAITING && next.waiting.len() > self.contents.waiting.len() {
            return Err(InboxError::Full(
                "too many transactions waiting; book or ignore some first",
            ));
        }
        if next.ignored.len() > MAX_IGNORED && next.ignored.len() > self.contents.ignored.len() {
            return Err(InboxError::Full("too many ignored transactions"));
        }
        self.persist(&next)?;
        self.contents = next;
        Ok(result)
    }

    /// Write `contents` through a fresh node-private temp file in the same
    /// folder, fsync it, rename it over the inbox, then fsync the folder.
    fn persist(&self, contents: &InboxContents) -> Result<(), InboxError> {
        let file = InboxFile {
            version: FORMAT_VERSION,
            contents: contents.clone(),
        };
        let bytes = serde_json::to_vec(&file).map_err(|error| InboxError::Corrupt {
            path: self.path.clone(),
            detail: error.to_string(),
        })?;
        if bytes.len() as u64 > MAX_FILE_BYTES {
            return Err(InboxError::Full("the inbox file would be too large"));
        }
        let folder = match self.path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let random = crate::access_list::random_bytes();
        let temp = folder.join(format!(
            ".{BANK_INBOX_FILE}.{}.tmp",
            hex::encode(&random[..8])
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let written = open_checked(&temp, &options, FileTrust::NodePrivate, "bank inbox").and_then(
            |mut checked| {
                checked.file.write_all(&bytes)?;
                checked.file.sync_all()?;
                std::fs::rename(&temp, &self.path)
            },
        );
        if let Err(source) = written {
            let _ = std::fs::remove_file(&temp);
            return Err(InboxError::Io { path: temp, source });
        }
        if let Ok(directory) = std::fs::File::open(folder) {
            let _ = directory.sync_all();
        }
        Ok(())
    }
}

/// Read and parse the inbox file at `path`, node-private; `Ok(None)` when
/// there is none.
fn read_inbox_file(path: &Path) -> Result<Option<InboxContents>, InboxError> {
    let io_error = |source| InboxError::Io {
        path: path.to_owned(),
        source,
    };
    let checked = match open_checked(
        path,
        std::fs::OpenOptions::new().read(true),
        FileTrust::NodePrivate,
        "bank inbox",
    ) {
        Ok(checked) => checked,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error(source)),
    };
    let bytes = read_to_end_capped(checked.file, checked.metadata.len(), MAX_FILE_BYTES)
        .map_err(io_error)?;
    let corrupt = |detail| InboxError::Corrupt {
        path: path.to_owned(),
        detail,
    };
    let file: InboxFile =
        serde_json::from_slice(&bytes).map_err(|error| corrupt(error.to_string()))?;
    if file.version != FORMAT_VERSION {
        return Err(corrupt(format!(
            "format version {} (this build reads {FORMAT_VERSION})",
            file.version
        )));
    }
    Ok(Some(file.contents))
}

/// The name of a temp file a crashed write left: `.bank-inbox.json.<hex>.tmp`.
fn is_leftover_temp_file(name: &str) -> bool {
    name.strip_prefix(&format!(".{BANK_INBOX_FILE}."))
        .and_then(|rest| rest.strip_suffix(".tmp"))
        .is_some_and(|middle| !middle.is_empty() && middle.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Delete the temp files a crashed write left in `folder`: regular files this
/// uid owns only.
fn sweep_leftover_temp_files(folder: &Path) {
    let Ok(entries) = std::fs::read_dir(folder) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry
            .file_name()
            .to_str()
            .is_some_and(is_leftover_temp_file)
        {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if !metadata.file_type().is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if metadata.uid() != ledger::journal::effective_uid() {
                continue;
            }
        }
        if let Err(error) = std::fs::remove_file(&path) {
            tracing::warn!(path = %path.display(), %error, "could not delete a temp file a crashed bank inbox write left");
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn waiting(id: &str, amount: &str) -> InboxTransaction {
        InboxTransaction {
            transaction_id: id.to_owned(),
            item_id: "item".to_owned(),
            account_id: "acc1".to_owned(),
            date: chrono::NaiveDate::from_ymd_opt(2026, 11, 2).unwrap(),
            amount: amount.parse().unwrap(),
            currency: "USD".to_owned(),
            payee: Some("Staples".to_owned()),
            description: Some("STAPLES #1234".to_owned()),
            category: Some("GENERAL_MERCHANDISE".to_owned()),
            fetched_at: "2026-11-14T10:00:00Z".to_owned(),
        }
    }

    /// 008: what the inbox holds survives a reopen — the waiting
    /// transactions with their amounts as written, the ignored ones — and the
    /// file is the node's alone (0600); no file is an empty inbox.
    ///
    /// Bug-catch: an inbox kept in memory only loses every fetched
    /// transaction at a restart, while Plaid's place-marker has moved past
    /// them, so they are never fetched again.
    #[test]
    fn the_inbox_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let mut inbox = BankInbox::open(dir.path()).unwrap();
        assert!(inbox.contents().waiting.is_empty());
        inbox
            .update(|contents| {
                contents
                    .waiting
                    .insert("t1".to_owned(), waiting("t1", "-45.20"));
                contents.ignored.insert(
                    "t2".to_owned(),
                    IgnoredTransaction {
                        item_id: "item".to_owned(),
                        at: "2026-11-14T10:00:00Z".to_owned(),
                        by: "u1".to_owned(),
                        reason: Some("a transfer".to_owned()),
                    },
                );
            })
            .unwrap();

        let reopened = BankInbox::open(dir.path()).unwrap();
        assert_eq!(reopened.contents(), inbox.contents());
        assert_eq!(
            reopened.contents().waiting["t1"].amount.to_string(),
            "-45.20"
        );
        assert!(reopened.contents().holds("t2"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path().join(BANK_INBOX_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    /// 008: a file that is not an inbox of this format is refused, not read
    /// as an empty one; a change past the cap is refused and changes
    /// nothing, on disk or in memory.
    ///
    /// Bug-catch: a damaged file read as empty would let every transaction it
    /// held be lost silently; a cap not held lets a stuck bookkeeping queue
    /// grow the file without bound.
    #[test]
    fn a_foreign_file_or_a_full_inbox_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(BANK_INBOX_FILE);
        std::fs::write(&path, br#"{"version":7,"waiting":{},"ignored":{}}"#).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(matches!(
            BankInbox::open(dir.path()),
            Err(InboxError::Corrupt { .. })
        ));
        std::fs::write(&path, b"not json").unwrap();
        assert!(matches!(
            BankInbox::open(dir.path()),
            Err(InboxError::Corrupt { .. })
        ));

        std::fs::remove_file(&path).unwrap();
        let mut inbox = BankInbox::open(dir.path()).unwrap();
        let full = inbox.update(|contents| {
            for n in 0..=MAX_WAITING {
                let id = format!("t{n}");
                contents.waiting.insert(id.clone(), waiting(&id, "-1"));
            }
        });
        assert!(matches!(full, Err(InboxError::Full(_))));
        assert!(inbox.contents().waiting.is_empty());
        assert!(!path.exists());
    }
}
