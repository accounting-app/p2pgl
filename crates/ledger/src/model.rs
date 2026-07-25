//! Domain model types for the ledger — aligned 1:1 with Beancount directives (§2.3).

use chrono::NaiveDate;
use rust_decimal::Decimal;
use std::collections::BTreeMap;

/// Key-value metadata. All values are strings per §3.3.2.
pub type Metadata = BTreeMap<String, String>;

// ─── Primitives ──────────────────────────────────────────────────────────────

/// Transaction completion flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    /// `*` — transaction is complete / cleared.
    Complete,
    /// `!` — transaction is pending / incomplete.
    Incomplete,
}

impl Flag {
    /// Returns the canonical single-character representation.
    pub fn as_char(self) -> char {
        match self {
            Flag::Complete => '*',
            Flag::Incomplete => '!',
        }
    }
}

/// A monetary amount: a decimal number paired with a currency code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Amount {
    pub number: Decimal,
    pub currency: String,
}

/// Cost specification for a posting (lot cost basis).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostSpec {
    /// Per-unit cost amount. `None` for empty cost `{}`.
    pub amount: Option<Amount>,
    /// Acquisition date override.
    pub date: Option<NaiveDate>,
}

/// Price annotation on a posting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PriceSpec {
    /// `@ NUMBER CURRENCY` — per-unit price.
    Unit(Amount),
    /// `@@ NUMBER CURRENCY` — total price for the lot.
    Total(Amount),
}

// ─── Posting ─────────────────────────────────────────────────────────────────

/// A single posting (line) within a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Posting {
    pub account: String,
    /// `None` when the amount is elided (I2 — at most one per transaction).
    pub amount: Option<Amount>,
    pub cost: Option<CostSpec>,
    pub price: Option<PriceSpec>,
    pub metadata: Metadata,
}

// ─── Transaction ─────────────────────────────────────────────────────────────

/// A dated transaction with postings (the core ledger event).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    pub date: NaiveDate,
    pub flag: Flag,
    pub payee: Option<String>,
    pub narration: Option<String>,
    pub tags: Vec<String>,
    pub links: Vec<String>,
    pub postings: Vec<Posting>,
    pub metadata: Metadata,
}

/// Envelope metadata helpers (§3.3.1).
impl Transaction {
    /// The `openledger-author` value (Iroh EndpointId).
    pub fn author(&self) -> Option<&str> {
        self.metadata.get("openledger-author").map(|s| s.as_str())
    }

    /// The `openledger-parents` value as a list of parent txid strings.
    pub fn parent_ids(&self) -> Vec<&str> {
        self.metadata
            .get("openledger-parents")
            .map(|s| {
                s.split(',')
                    .map(|p| p.trim())
                    .filter(|p| !p.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The `openledger-lamport` clock value.
    pub fn lamport_clock(&self) -> Option<u64> {
        self.metadata
            .get("openledger-lamport")
            .and_then(|s| s.parse().ok())
    }

    /// The `openledger-signature` value (hex Ed25519).
    pub fn signature(&self) -> Option<&str> {
        self.metadata
            .get("openledger-signature")
            .map(|s| s.as_str())
    }
}

// ─── Non-transaction directives ──────────────────────────────────────────────

/// `open` — open an account, optionally constraining to specific currencies (I9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Open {
    pub date: NaiveDate,
    pub account: String,
    /// Currency constraints. Empty = accepts any currency.
    pub currencies: Vec<String>,
    pub metadata: Metadata,
}

/// `close` — close an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Close {
    pub date: NaiveDate,
    pub account: String,
    pub metadata: Metadata,
}

/// `commodity` — declare a currency.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commodity {
    pub date: NaiveDate,
    pub currency: String,
    pub metadata: Metadata,
}

/// `pad` — insert a balancing transaction against a source account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pad {
    pub date: NaiveDate,
    pub account: String,
    pub source_account: String,
    pub metadata: Metadata,
}

/// `balance` — assert an account equals an amount at a date (checkpoint).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Balance {
    pub date: NaiveDate,
    pub account: String,
    pub amount: Amount,
    pub metadata: Metadata,
}

/// `note` — attach a comment to an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub date: NaiveDate,
    pub account: String,
    pub comment: String,
    pub metadata: Metadata,
}

/// `document` — attach a document path to an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub date: NaiveDate,
    pub account: String,
    pub path: String,
    pub metadata: Metadata,
}

/// `event` — record a named event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub date: NaiveDate,
    pub event_type: String,
    pub description: String,
    pub metadata: Metadata,
}

/// `price` — declare a currency price.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Price {
    pub date: NaiveDate,
    pub currency: String,
    pub amount: Amount,
    pub metadata: Metadata,
}

// ─── Directive (enum over all types) ─────────────────────────────────────────

/// A single parsed Beancount directive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Directive {
    Transaction(Transaction),
    Open(Open),
    Close(Close),
    Commodity(Commodity),
    Pad(Pad),
    Balance(Balance),
    Note(Note),
    Document(Document),
    Event(Event),
    Price(Price),
}

impl Directive {
    /// The date of this directive.
    pub fn date(&self) -> NaiveDate {
        match self {
            Directive::Transaction(d) => d.date,
            Directive::Open(d) => d.date,
            Directive::Close(d) => d.date,
            Directive::Commodity(d) => d.date,
            Directive::Pad(d) => d.date,
            Directive::Balance(d) => d.date,
            Directive::Note(d) => d.date,
            Directive::Document(d) => d.date,
            Directive::Event(d) => d.date,
            Directive::Price(d) => d.date,
        }
    }

    /// The metadata map for this directive.
    pub fn metadata(&self) -> &Metadata {
        match self {
            Directive::Transaction(d) => &d.metadata,
            Directive::Open(d) => &d.metadata,
            Directive::Close(d) => &d.metadata,
            Directive::Commodity(d) => &d.metadata,
            Directive::Pad(d) => &d.metadata,
            Directive::Balance(d) => &d.metadata,
            Directive::Note(d) => &d.metadata,
            Directive::Document(d) => &d.metadata,
            Directive::Event(d) => &d.metadata,
            Directive::Price(d) => &d.metadata,
        }
    }

    /// The type priority for canonical ordering (§3.3.2).
    pub fn type_priority(&self) -> u8 {
        match self {
            Directive::Open(_) => 0,
            Directive::Commodity(_) => 1,
            Directive::Pad(_) => 2,
            Directive::Balance(_) => 3,
            Directive::Transaction(_) => 4,
            Directive::Note(_) => 5,
            Directive::Document(_) => 6,
            Directive::Event(_) => 7,
            Directive::Price(_) => 8,
            Directive::Close(_) => 9,
        }
    }
}
