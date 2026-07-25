//! Ledger service — the unified write + boot layer (§3.5).
//!
//! Ties together parser, serializer, DAG, validation, and file persistence.
//! This is the single entry point for all ledger mutations.

use chrono::NaiveDate;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::dag::{DagError, InsertResult, LedgerDag};
use crate::error::ParseError;
use crate::hash::compute_content_id;
use crate::model::*;
use crate::parse::parse_file;
use crate::serialize::full_file_serialize;
use crate::validate::{AccountState, ValidationError, validate_transaction};

// ─── Service error ───────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum ServiceError {
    /// File parse errors on boot.
    Parse(Vec<ParseError>),
    /// Ledger invariant violation (I1–I3, I9).
    Validation(ValidationError),
    /// DAG structure error (cycle, missing parent).
    Dag(DagError),
    /// Filesystem I/O error.
    Io(std::io::Error),
    /// FR-3 AC1: account is already open.
    AccountAlreadyOpen { account: String },
    /// FR-3 AC2: account has transactions after the proposed close date.
    AccountHasLaterTransactions {
        account: String,
        latest_date: NaiveDate,
    },
    /// Account is not currently open (for close).
    AccountNotOpen { account: String },
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServiceError::Parse(errors) => {
                write!(f, "Parse errors: ")?;
                for (i, e) in errors.iter().enumerate() {
                    if i > 0 {
                        write!(f, "; ")?;
                    }
                    write!(f, "{e}")?;
                }
                Ok(())
            }
            ServiceError::Validation(e) => write!(f, "Validation: {e}"),
            ServiceError::Dag(e) => write!(f, "DAG: {e}"),
            ServiceError::Io(e) => write!(f, "IO: {e}"),
            ServiceError::AccountAlreadyOpen { account } => {
                write!(f, "Account {account} is already open")
            }
            ServiceError::AccountHasLaterTransactions {
                account,
                latest_date,
            } => {
                write!(
                    f,
                    "Cannot close {account}: has transactions as late as {latest_date}"
                )
            }
            ServiceError::AccountNotOpen { account } => {
                write!(f, "Account {account} is not open")
            }
        }
    }
}

impl std::error::Error for ServiceError {}

impl ServiceError {
    /// §2.8 error code for GraphQL error extensions.
    pub fn error_code(&self) -> &'static str {
        match self {
            ServiceError::Parse(_) => "PARSE_ERROR",
            ServiceError::Validation(v) => v.error_code(),
            ServiceError::Dag(DagError::CycleDetected { .. }) => "CYCLE_DETECTED",
            ServiceError::Dag(DagError::MissingParent { .. }) => "MISSING_PARENT",
            ServiceError::Io(_) => "IO_ERROR",
            ServiceError::AccountAlreadyOpen { .. } => "ACCOUNT_ALREADY_OPEN",
            ServiceError::AccountHasLaterTransactions { .. } => "ACCOUNT_HAS_LATER_TRANSACTIONS",
            ServiceError::AccountNotOpen { .. } => "ACCOUNT_NOT_OPEN",
        }
    }
}

impl From<ValidationError> for ServiceError {
    fn from(e: ValidationError) -> Self {
        ServiceError::Validation(e)
    }
}

impl From<DagError> for ServiceError {
    fn from(e: DagError) -> Self {
        ServiceError::Dag(e)
    }
}

impl From<std::io::Error> for ServiceError {
    fn from(e: std::io::Error) -> Self {
        ServiceError::Io(e)
    }
}

// ─── Input types ─────────────────────────────────────────────────────────────

/// Input for appending a transaction (domain-level; GraphQL layer converts to this).
#[derive(Debug, Clone)]
pub struct TransactionInput {
    pub date: NaiveDate,
    pub flag: Flag,
    pub payee: Option<String>,
    pub narration: Option<String>,
    pub tags: Vec<String>,
    pub links: Vec<String>,
    pub postings: Vec<PostingInput>,
}

/// A single posting in a transaction input.
#[derive(Debug, Clone)]
pub struct PostingInput {
    pub account: String,
    pub amount: Option<Amount>,
    pub cost: Option<CostSpec>,
    pub price: Option<PriceSpec>,
}

// ─── Ledger service ──────────────────────────────────────────────────────────

/// The unified ledger service — owns DAG, account state, and file persistence.
///
/// All write operations go through this service. Reads query the DAG directly.
/// Concurrency (RwLock) is handled by the gl-node layer.
pub struct LedgerService {
    dag: LedgerDag,
    accounts: AccountState,
    lamport_clock: u64,
    author_id: String,
    file_path: PathBuf,
    leading_comments: Vec<String>,
}

impl LedgerService {
    // ── Boot ──────────────────────────────────────────────────────────────

    /// Boot the ledger service from a `.bean` file.
    ///
    /// If the file doesn't exist, creates an empty file and starts with an empty ledger.
    /// Parses directives, builds account state, populates the DAG, and initializes
    /// the Lamport clock.
    pub fn boot(file_path: impl Into<PathBuf>, author_id: String) -> Result<Self, ServiceError> {
        let file_path = file_path.into();

        // Read or create the file.
        let content = if file_path.exists() {
            std::fs::read_to_string(&file_path)?
        } else {
            // Create parent dirs + empty file (§3.3).
            if let Some(parent) = file_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&file_path, "")?;
            String::new()
        };

        // Extract leading comments (lines starting with `;` before any directive).
        let leading_comments = extract_leading_comments(&content);

        // Parse directives.
        let directives = if content.trim().is_empty() {
            Vec::new()
        } else {
            parse_file(&content).map_err(ServiceError::Parse)?
        };

        // Sort by canonical order for correct AccountState building.
        let mut sorted: Vec<&Directive> = directives.iter().collect();
        sorted.sort_by(|a, b| {
            a.date()
                .cmp(&b.date())
                .then_with(|| a.type_priority().cmp(&b.type_priority()))
        });

        // Build account state and insert into DAG.
        let mut accounts = AccountState::new();
        let mut dag = LedgerDag::new();
        let mut max_lamport: u64 = 0;

        for directive in &sorted {
            match directive {
                Directive::Open(open) => {
                    // Ignore errors on boot (file may have duplicate opens from merges).
                    let _ = accounts.open_account(&open.account, open.date, &open.currencies);
                }
                Directive::Close(close) => {
                    let _ = accounts.close_account(&close.account, close.date);
                }
                _ => {}
            }

            // Track max Lamport across all directives.
            if let Directive::Transaction(txn) = directive {
                if let Some(lamport) = txn.lamport_clock() {
                    max_lamport = max_lamport.max(lamport);
                }
            }

            // Insert into DAG (lenient mode: parents may not be present yet).
            dag.insert((*directive).clone(), false)?;
        }

        let lamport_clock = if max_lamport > 0 {
            max_lamport + 1
        } else {
            0
        };

        Ok(LedgerService {
            dag,
            accounts,
            lamport_clock,
            author_id,
            file_path,
            leading_comments,
        })
    }

    // ── Mutations ────────────────────────────────────────────────────────

    /// Append a new transaction to the ledger (§3.5 write path).
    ///
    /// Validates I1 (balance), I2 (elision), I3 (lifecycle), I9 (currency),
    /// stamps envelope metadata, inserts into DAG, and persists to file.
    /// Returns the `txid`.
    pub fn append_transaction(
        &mut self,
        input: TransactionInput,
    ) -> Result<String, ServiceError> {
        // Build Transaction from input (no envelope yet).
        let txn = Transaction {
            date: input.date,
            flag: input.flag,
            payee: input.payee,
            narration: input.narration,
            tags: input.tags,
            links: input.links,
            postings: input
                .postings
                .into_iter()
                .map(|p| Posting {
                    account: p.account,
                    amount: p.amount,
                    cost: p.cost,
                    price: p.price,
                    metadata: BTreeMap::new(),
                })
                .collect(),
            metadata: BTreeMap::new(),
        };

        // Validate (I1, I2, I3, I9). Returns resolved txn with elided posting filled.
        let mut resolved = validate_transaction(&txn, &self.accounts)?;

        // Stamp envelope metadata (§3.3.1, §3.4.2).
        self.stamp_transaction_envelope(&mut resolved.metadata);

        // Insert into DAG.
        let directive = Directive::Transaction(resolved);
        let content_id = match self.dag.insert(directive, false)? {
            InsertResult::Inserted { content_id } => content_id,
            InsertResult::Duplicate { content_id } => {
                // FR-1 AC4: idempotent by content. Return existing txid.
                return Ok(content_id);
            }
        };

        // Persist to file.
        self.persist()?;

        Ok(content_id)
    }

    /// Open a new account (FR-3 AC1).
    ///
    /// Validates that the account is not already open, creates the directive,
    /// stamps envelope, inserts into DAG, and persists.
    /// Returns the `directiveId`.
    pub fn open_account(
        &mut self,
        account: String,
        date: NaiveDate,
        currencies: Vec<String>,
    ) -> Result<String, ServiceError> {
        // FR-3 AC1: opening an already-open account errors.
        if self.accounts.is_open(&account) {
            return Err(ServiceError::AccountAlreadyOpen {
                account: account.clone(),
            });
        }

        // Build Open directive.
        let mut metadata = BTreeMap::new();
        self.stamp_directive_envelope(&mut metadata);

        let open = Open {
            date,
            account: account.clone(),
            currencies: currencies.clone(),
            metadata,
        };

        // Insert into DAG.
        let directive = Directive::Open(open);
        let content_id = match self.dag.insert(directive, false)? {
            InsertResult::Inserted { content_id } => content_id,
            InsertResult::Duplicate { content_id } => return Ok(content_id),
        };

        // Update account state.
        self.accounts
            .open_account(&account, date, &currencies)
            .map_err(ServiceError::Validation)?;

        // Persist.
        self.persist()?;

        Ok(content_id)
    }

    /// Close an account (FR-3 AC2).
    ///
    /// Validates that the account is open and has no transactions after the close date.
    /// Returns the `directiveId`.
    pub fn close_account(
        &mut self,
        account: String,
        date: NaiveDate,
    ) -> Result<String, ServiceError> {
        // Must be currently open.
        if !self.accounts.is_open(&account) {
            return Err(ServiceError::AccountNotOpen {
                account: account.clone(),
            });
        }

        // FR-3 AC2: no transactions after the close date.
        if let Some(latest) = self.latest_posting_date(&account) {
            if latest > date {
                return Err(ServiceError::AccountHasLaterTransactions {
                    account: account.clone(),
                    latest_date: latest,
                });
            }
        }

        // Build Close directive.
        let mut metadata = BTreeMap::new();
        self.stamp_directive_envelope(&mut metadata);

        let close = Close {
            date,
            account: account.clone(),
            metadata,
        };

        // Insert into DAG.
        let directive = Directive::Close(close);
        let content_id = match self.dag.insert(directive, false)? {
            InsertResult::Inserted { content_id } => content_id,
            InsertResult::Duplicate { content_id } => return Ok(content_id),
        };

        // Update account state.
        self.accounts
            .close_account(&account, date)
            .map_err(ServiceError::Validation)?;

        // Persist.
        self.persist()?;

        Ok(content_id)
    }

    // ── Envelope stamping (§3.3.1, §3.4.2) ───────────────────────────────

    /// Stamp transaction-level envelope metadata (parents + author + lamport).
    fn stamp_transaction_envelope(&mut self, metadata: &mut Metadata) {
        self.lamport_clock += 1;
        metadata.insert("openledger-author".to_owned(), self.author_id.clone());
        metadata.insert(
            "openledger-lamport".to_owned(),
            self.lamport_clock.to_string(),
        );

        // Parents: current DAG heads, sorted ascending (§3.3.1).
        let mut parents: Vec<&str> = self.dag.heads().iter().map(|s| s.as_str()).collect();
        parents.sort();
        metadata.insert("openledger-parents".to_owned(), parents.join(","));
    }

    /// Stamp non-transaction directive envelope (author + lamport, no parents).
    fn stamp_directive_envelope(&mut self, metadata: &mut Metadata) {
        self.lamport_clock += 1;
        metadata.insert("openledger-author".to_owned(), self.author_id.clone());
        metadata.insert(
            "openledger-lamport".to_owned(),
            self.lamport_clock.to_string(),
        );
    }

    // ── Persistence ──────────────────────────────────────────────────────

    /// Serialize the full ledger to the `.bean` file.
    fn persist(&self) -> Result<(), ServiceError> {
        let directives: Vec<Directive> = self
            .dag
            .directives()
            .into_iter()
            .cloned()
            .collect();
        let content = full_file_serialize(&directives, &self.leading_comments);
        std::fs::write(&self.file_path, content)?;
        Ok(())
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    /// Find the latest transaction date referencing a given account.
    fn latest_posting_date(&self, account: &str) -> Option<NaiveDate> {
        let mut latest: Option<NaiveDate> = None;
        for directive in self.dag.directives() {
            if let Directive::Transaction(txn) = directive {
                if txn.postings.iter().any(|p| p.account == account) {
                    latest = Some(latest.map_or(txn.date, |d| d.max(txn.date)));
                }
            }
        }
        latest
    }

    // ── Accessors ────────────────────────────────────────────────────────

    /// The underlying DAG (for queries and read model).
    pub fn dag(&self) -> &LedgerDag {
        &self.dag
    }

    /// The account state tracker.
    pub fn accounts(&self) -> &AccountState {
        &self.accounts
    }

    /// Current Lamport clock value.
    pub fn lamport_clock(&self) -> u64 {
        self.lamport_clock
    }

    /// The author ID (Iroh EndpointId or placeholder).
    pub fn author_id(&self) -> &str {
        &self.author_id
    }

    /// The file path being managed.
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Total number of directives.
    pub fn directive_count(&self) -> usize {
        self.dag.len()
    }

    /// Current DAG head count.
    pub fn head_count(&self) -> usize {
        self.dag.heads().len()
    }

    /// Get a directive by content ID.
    pub fn get_directive(&self, content_id: &str) -> Option<&Directive> {
        self.dag.get(content_id)
    }

    /// Compute the content ID for a directive (for lookups).
    pub fn content_id(directive: &Directive) -> String {
        compute_content_id(directive)
    }
}

// ─── Comment extraction ──────────────────────────────────────────────────────

/// Extract leading `;` comments from the beginning of a file (before any directive).
fn extract_leading_comments(content: &str) -> Vec<String> {
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

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn test_file_path() -> PathBuf {
        let count = TEST_COUNTER.fetch_add(1, Ordering::SeqCst);
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("openledger-test-{ts}-{count}.bean"))
    }

    fn make_date(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).unwrap()
    }

    fn boot_empty() -> (LedgerService, PathBuf) {
        let path = test_file_path();
        let svc = LedgerService::boot(path.clone(), "test-peer".to_owned()).unwrap();
        (svc, path)
    }

    fn setup_with_accounts() -> (LedgerService, PathBuf) {
        let (mut svc, path) = boot_empty();
        svc.open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec!["USD".to_owned()])
            .unwrap();
        svc.open_account(
            "Equity:Opening".to_owned(),
            make_date(2024, 1, 1),
            vec![],
        )
        .unwrap();
        svc.open_account(
            "Expenses:Food".to_owned(),
            make_date(2024, 1, 1),
            vec!["USD".to_owned()],
        )
        .unwrap();
        (svc, path)
    }

    fn balanced_input() -> TransactionInput {
        TransactionInput {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: Some("Acme".to_owned()),
            narration: Some("Funding".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                PostingInput {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
            ],
        }
    }

    // ── Boot ─────────────────────────────────────────────────────────────

    #[test]
    fn test_boot_creates_empty_file() {
        let path = test_file_path();
        assert!(!path.exists());
        let svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        assert!(path.exists());
        assert_eq!(svc.directive_count(), 0);
        assert_eq!(svc.lamport_clock(), 0);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_boot_from_existing_file() {
        let path = test_file_path();
        std::fs::write(
            &path,
            "2024-01-01 open Assets:Cash USD\n\n2024-01-01 open Equity:Opening\n",
        )
        .unwrap();
        let svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        assert_eq!(svc.directive_count(), 2);
        assert!(svc.accounts().is_open("Assets:Cash"));
        assert!(svc.accounts().is_open("Equity:Opening"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_boot_from_golden_fixture() {
        // Boot from the golden fixture file (copy it to temp).
        let fixture = include_str!("../../../testfixtures/fixture-simple.bean");
        let path = test_file_path();
        std::fs::write(&path, fixture).unwrap();
        let svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        assert_eq!(svc.directive_count(), 16);
        assert!(svc.accounts().is_open("Assets:Cash"));
        assert!(!svc.accounts().is_open("Expenses:Food")); // closed in fixture
        std::fs::remove_file(path).ok();
    }

    // ── Open account ─────────────────────────────────────────────────────

    #[test]
    fn test_open_account() {
        let (mut svc, path) = boot_empty();
        let id = svc
            .open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec!["USD".to_owned()])
            .unwrap();
        assert!(!id.is_empty());
        assert_eq!(svc.directive_count(), 1);
        assert!(svc.accounts().is_open("Assets:Cash"));
        assert_eq!(svc.lamport_clock(), 1);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_open_already_open_rejected() {
        let (mut svc, path) = boot_empty();
        svc.open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        let err = svc
            .open_account("Assets:Cash".to_owned(), make_date(2024, 2, 1), vec![])
            .unwrap_err();
        assert_eq!(err.error_code(), "ACCOUNT_ALREADY_OPEN");
        std::fs::remove_file(path).ok();
    }

    // ── Close account ────────────────────────────────────────────────────

    #[test]
    fn test_close_account() {
        let (mut svc, path) = boot_empty();
        svc.open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        let id = svc
            .close_account("Assets:Cash".to_owned(), make_date(2024, 12, 31))
            .unwrap();
        assert!(!id.is_empty());
        assert!(!svc.accounts().is_open("Assets:Cash"));
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_close_not_open_rejected() {
        let (mut svc, path) = boot_empty();
        let err = svc
            .close_account("Assets:Cash".to_owned(), make_date(2024, 12, 31))
            .unwrap_err();
        assert_eq!(err.error_code(), "ACCOUNT_NOT_OPEN");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_close_with_later_transactions_rejected() {
        let (mut svc, path) = setup_with_accounts();

        // Append a transaction on Jan 15.
        svc.append_transaction(balanced_input()).unwrap();

        // Try to close before that date → error.
        let err = svc
            .close_account("Assets:Cash".to_owned(), make_date(2024, 1, 10))
            .unwrap_err();
        assert_eq!(err.error_code(), "ACCOUNT_HAS_LATER_TRANSACTIONS");
        std::fs::remove_file(path).ok();
    }

    // ── Append transaction ───────────────────────────────────────────────

    #[test]
    fn test_append_balanced_transaction() {
        let (mut svc, path) = setup_with_accounts();
        let txid = svc.append_transaction(balanced_input()).unwrap();
        assert_eq!(txid.len(), 64);
        assert_eq!(svc.head_count(), 1);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_unbalanced_rejected() {
        let (mut svc, path) = setup_with_accounts();
        let mut input = balanced_input();
        input.postings[1].amount = Some(Amount {
            number: dec!(-50),
            currency: "USD".to_owned(),
        });
        let err = svc.append_transaction(input).unwrap_err();
        assert_eq!(err.error_code(), "UNBALANCED_TRANSACTION");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_unopened_account_rejected() {
        let (mut svc, path) = boot_empty();
        // No accounts opened.
        let err = svc.append_transaction(balanced_input()).unwrap_err();
        assert_eq!(err.error_code(), "ACCOUNT_NOT_OPEN");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_currency_mismatch_rejected() {
        let (mut svc, path) = setup_with_accounts();
        let mut input = balanced_input();
        // Assets:Cash only accepts USD.
        input.postings[0].amount = Some(Amount {
            number: dec!(100),
            currency: "EUR".to_owned(),
        });
        input.postings[1].amount = Some(Amount {
            number: dec!(-100),
            currency: "EUR".to_owned(),
        });
        let err = svc.append_transaction(input).unwrap_err();
        assert_eq!(err.error_code(), "ACCOUNT_CURRENCY_MISMATCH");
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_with_elided_posting() {
        let (mut svc, path) = setup_with_accounts();
        let input = TransactionInput {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Elided test".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                PostingInput {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Equity:Opening".to_owned(),
                    amount: None, // elided
                    cost: None,
                    price: None,
                },
            ],
        };
        let txid = svc.append_transaction(input).unwrap();
        assert_eq!(txid.len(), 64);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_append_idempotent_by_content() {
        let (mut svc, path) = setup_with_accounts();
        let txid1 = svc.append_transaction(balanced_input()).unwrap();

        // Same economic body again → same txid (G-Set dedup).
        // Note: envelope differs (different parents/lamport), but economic body is same.
        // However, the resolved txn now has envelope metadata, so the second insert
        // will have different metadata → different content ID if metadata enters hash.
        // But economic_canonical_serialize excludes envelope, so txid should be the same.
        // The DAG insert deduplicates by content_id, which IS the economic hash.
        // Wait — compute_content_id uses economic_canonical_serialize which EXCLUDES
        // envelope metadata. So the content_id will be the same for both.
        // But the Directive objects have different metadata, so they're different objects
        // being inserted into the DAG. The DAG deduplicates by content_id.
        // So the second insert should return Duplicate.
        let txid2 = svc.append_transaction(balanced_input()).unwrap();
        assert_eq!(txid1, txid2, "Same economic body → same txid");
        std::fs::remove_file(path).ok();
    }

    // ── Envelope stamping ────────────────────────────────────────────────

    #[test]
    fn test_lamport_increments() {
        let (mut svc, path) = boot_empty();
        assert_eq!(svc.lamport_clock(), 0);

        svc.open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        assert_eq!(svc.lamport_clock(), 1);

        svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        assert_eq!(svc.lamport_clock(), 2);

        svc.append_transaction(TransactionInput {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Test".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                PostingInput {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
            ],
        })
        .unwrap();
        assert_eq!(svc.lamport_clock(), 3);
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_genesis_has_empty_parents() {
        let (mut svc, path) = setup_with_accounts();
        assert_eq!(svc.head_count(), 0); // Only opens, no transaction heads.

        let txid = svc.append_transaction(balanced_input()).unwrap();
        let directive = svc.get_directive(&txid).unwrap();
        if let Directive::Transaction(txn) = directive {
            assert!(
                txn.parent_ids().is_empty(),
                "Genesis transaction should have empty parents"
            );
        } else {
            panic!("Expected Transaction");
        }
        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_second_txn_references_first_as_parent() {
        let (mut svc, path) = setup_with_accounts();
        let txid1 = svc.append_transaction(balanced_input()).unwrap();

        let input2 = TransactionInput {
            date: make_date(2024, 1, 20),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Second".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                PostingInput {
                    account: "Expenses:Food".to_owned(),
                    amount: Some(Amount {
                        number: dec!(25),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-25),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
            ],
        };
        let txid2 = svc.append_transaction(input2).unwrap();

        let directive = svc.get_directive(&txid2).unwrap();
        if let Directive::Transaction(txn) = directive {
            assert_eq!(
                txn.parent_ids(),
                vec![txid1.as_str()],
                "Second txn should reference first as parent"
            );
        } else {
            panic!("Expected Transaction");
        }
        std::fs::remove_file(path).ok();
    }

    // ── File persistence ─────────────────────────────────────────────────

    #[test]
    fn test_persist_and_reboot() {
        let path = test_file_path();

        // First session: create accounts + transaction.
        {
            let mut svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
            svc.open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec!["USD".to_owned()])
                .unwrap();
            svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
                .unwrap();
            svc.append_transaction(TransactionInput {
                date: make_date(2024, 1, 15),
                flag: Flag::Complete,
                payee: Some("Test".to_owned()),
                narration: Some("Persist test".to_owned()),
                tags: vec![],
                links: vec![],
                postings: vec![
                    PostingInput {
                        account: "Assets:Cash".to_owned(),
                        amount: Some(Amount {
                            number: dec!(500),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                    },
                    PostingInput {
                        account: "Equity:Opening".to_owned(),
                        amount: Some(Amount {
                            number: dec!(-500),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                    },
                ],
            })
            .unwrap();
        }

        // Second session: reboot from file.
        {
            let svc = LedgerService::boot(path.clone(), "peer-2".to_owned()).unwrap();
            assert_eq!(svc.directive_count(), 3); // 2 opens + 1 txn
            assert!(svc.accounts().is_open("Assets:Cash"));
            assert!(svc.accounts().is_open("Equity:Opening"));
            assert_eq!(svc.head_count(), 1);
        }

        std::fs::remove_file(path).ok();
    }

    #[test]
    fn test_file_round_trip_stable() {
        let path = test_file_path();

        // Create a ledger with some content.
        let mut svc = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        svc.open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec!["USD".to_owned()])
            .unwrap();
        svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        svc.append_transaction(TransactionInput {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: Some("Acme".to_owned()),
            narration: Some("Round trip".to_owned()),
            tags: vec!["test".to_owned()],
            links: vec!["ref-1".to_owned()],
            postings: vec![
                PostingInput {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(1000),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
                PostingInput {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-1000),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                },
            ],
        })
        .unwrap();

        // Read what was written.
        let content1 = std::fs::read_to_string(&path).unwrap();

        // Reboot and re-persist (should produce identical output).
        let svc2 = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        // Persist again (internally during boot, state was rebuilt).
        drop(svc2);
        let svc3 = LedgerService::boot(path.clone(), "peer-1".to_owned()).unwrap();
        svc3.persist().unwrap();
        let content2 = std::fs::read_to_string(&path).unwrap();

        assert_eq!(content1, content2, "Re-serialization should be stable");
        std::fs::remove_file(path).ok();
    }

    // ── Comment extraction ───────────────────────────────────────────────

    #[test]
    fn test_extract_leading_comments() {
        let content = "; Comment 1\n; Comment 2\n\n2024-01-01 open Assets:Cash\n";
        let comments = extract_leading_comments(content);
        assert_eq!(comments, vec!["Comment 1", "Comment 2"]);
    }

    #[test]
    fn test_extract_no_comments() {
        let content = "2024-01-01 open Assets:Cash\n";
        let comments = extract_leading_comments(content);
        assert!(comments.is_empty());
    }

    // ── Full genesis flow ────────────────────────────────────────────────

    #[test]
    fn test_full_genesis_flow() {
        let (mut svc, path) = boot_empty();

        // Step 1: Open accounts.
        svc.open_account("Assets:Cash".to_owned(), make_date(2024, 1, 1), vec!["USD".to_owned()])
            .unwrap();
        svc.open_account("Equity:Opening".to_owned(), make_date(2024, 1, 1), vec![])
            .unwrap();
        assert_eq!(svc.directive_count(), 2);

        // Step 2: Genesis transaction.
        let txid = svc.append_transaction(balanced_input()).unwrap();
        assert_eq!(svc.directive_count(), 3);
        assert_eq!(svc.head_count(), 1);

        // Step 3: Verify genesis has empty parents.
        if let Some(Directive::Transaction(txn)) = svc.get_directive(&txid) {
            assert!(txn.parent_ids().is_empty());
            assert_eq!(txn.author(), Some("test-peer"));
            assert_eq!(txn.lamport_clock(), Some(3)); // 2 opens + 1 txn
        }

        // Step 4: File was written.
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("open Assets:Cash"));
        assert!(content.contains("* \"Acme\" \"Funding\""));
        assert!(content.contains("openledger-author: \"test-peer\""));

        std::fs::remove_file(path).ok();
    }
}
