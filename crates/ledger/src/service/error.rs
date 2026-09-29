//! `ServiceError` and its conversions.

use super::*;

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
    /// §3.12: a resource limit was exceeded.
    ResourceLimitExceeded { message: String },
    /// Account name violates §2.3.
    InvalidAccountName { account: String },
    /// Currency code violates §2.3.
    InvalidCurrency { currency: String },
    /// Tag name violates §2.3.
    InvalidTag { tag: String },
    /// Link name violates §2.3.
    InvalidLink { link: String },
    /// Payee/narration contains control characters (H-8).
    InvalidInput { message: String },
    /// H-04: a date outside the range the `.bean` file grammar can re-parse.
    DateOutOfRange { date: NaiveDate },
    /// H-06: an `openledger-*` key in the economic body, where the envelope
    /// rules permit none (unknown at directive level, or any at posting level).
    BodyEnvelopeKey { key: String },
    /// T44: the append-only commit journal could not be read — it is over
    /// budget, or corrupt in a way a crash cannot produce. Fails closed.
    Journal { message: String },
    /// T44: a durable commit prepared earlier has not been finished or
    /// recovered yet.
    ///
    /// Unreachable when callers honour the single-writer contract documented on
    /// [`LedgerService::prepare_commit`]; it exists so a caller that violates it
    /// gets a loud refusal instead of an interleaved write.
    CommitInFlight,
    /// H-07 / H-12: a Lamport value that is not legal under
    /// [`lamport_value_is_legal`] (`value + 1 >= LAMPORT_CEILING`). Stamping or
    /// adopting it would take this node's clock outside the range every peer
    /// accepts, so the write is refused rather than made invisibly.
    ///
    /// `author` names the author whose directive carried the value this far,
    /// where it is known (always on adoption; on a stamp, the author of the
    /// highest-lamport directive this node holds), because the remedy is
    /// mesh-wide and starts with that author — see the `Display` text.
    LamportCeiling { next: u64, author: Option<String> },
    /// T63 / H-12: the adoption ratchet. Adopting this directive would advance
    /// this node's clock from `local` by more than [`MAX_LAMPORT_ADVANCE`] in
    /// one step. State-dependent — it is judged against this node's clock, and
    /// becomes acceptable once the clock has caught up through the intervening
    /// history — so it is never a permanent verdict on the directive. It is,
    /// however, a pure function of `(remote, local)`: while the clock has not
    /// moved past `remote − MAX_LAMPORT_ADVANCE` the verdict cannot change,
    /// which is what lets the node skip re-fetching it (T72 / L-69). Whether
    /// the clock CAN get there is a property of the history, not of this
    /// node — see [`check_lamport_advance`] and [`BOOTSTRAP_JOIN_REMEDY`].
    LamportAdvance {
        remote: u64,
        local: u64,
        author: Option<String>,
    },
    /// L-114 (decision (41) (b)): every signature this node checked failed —
    /// its signature domain or key differs from the history's — so a record it
    /// wrote now would be signed under the wrong domain, and at the next boot
    /// would verify and hide that verdict. Refused unless the operator set the
    /// override ([`LedgerService::set_write_despite_signature_verdict`]).
    SignatureVerdict { failed: usize },
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
            ServiceError::ResourceLimitExceeded { message } => {
                write!(f, "Resource limit exceeded: {message}")
            }
            ServiceError::InvalidAccountName { account } => {
                write!(f, "Invalid account name: {account}")
            }
            ServiceError::InvalidCurrency { currency } => {
                write!(f, "Invalid currency: {currency}")
            }
            ServiceError::InvalidTag { tag } => write!(f, "Invalid tag: {tag}"),
            ServiceError::InvalidLink { link } => write!(f, "Invalid link: {link}"),
            ServiceError::InvalidInput { message } => write!(f, "{message}"),
            ServiceError::DateOutOfRange { date } => {
                write!(
                    f,
                    "date '{date}' is outside the supported range 0001-01-01..9999-12-31"
                )
            }
            ServiceError::BodyEnvelopeKey { key } => {
                write!(
                    f,
                    "metadata key '{key}' is not an envelope key permitted in this position"
                )
            }
            ServiceError::Journal { message } => write!(f, "{message}"),
            ServiceError::CommitInFlight => {
                write!(f, "a durable ledger commit is already in flight")
            }
            ServiceError::LamportCeiling { next, author } => {
                write!(
                    f,
                    "openledger-lamport {next} is past the last legal value {} (ceiling \
                     {LAMPORT_CEILING}): a directive stamped there is refused by every \
                     peer, so this node will not author or adopt one. ",
                    LAMPORT_CEILING - 2
                )?;
                match author {
                    Some(author) => write!(
                        f,
                        "The clock was carried there by a directive from author {author}. "
                    )?,
                    None => write!(f, "The author that carried the clock there is unknown. ")?,
                }
                write!(
                    f,
                    "Remedy, mesh-wide: remove that author from the allowlist on every node, \
                     then stop every node and remove the directive(s) carrying that \
                     openledger-lamport from each node's .bean — removing it on one node \
                     alone is undone by the next anti-entropy round from any peer that still \
                     holds it (H-12). Removing an author whose directives are already in the \
                     history has a second consequence: {BOOTSTRAP_JOIN_REMEDY}"
                )
            }
            ServiceError::SignatureVerdict { failed } => write!(
                f,
                "refused: every signature this node checked failed ({failed} of them), so its \
                 signature domain (p2p.meshId, or p2p.swarmTopic when meshId is unset) or its \
                 node key differs from the one the history was signed under. A record written \
                 now would be signed under the wrong domain, and at the next boot it would \
                 verify and hide that verdict. Fix the domain or the key and restart — the \
                 history loads again — or set signing.allowWritesWhenEverySignatureFails to \
                 write anyway (L-114)"
            ),
            ServiceError::LamportAdvance {
                remote,
                local,
                author,
            } => {
                let author = author.as_deref().unwrap_or("(unknown)");
                write!(
                    f,
                    "openledger-lamport {remote} from author {author} would advance this \
                     node's clock from {local} by more than {MAX_LAMPORT_ADVANCE} in one step; \
                     refused (H-12 adoption ratchet). Honest traffic advances clocks one step \
                     at a time, so this is either a peer jumping the mesh toward the Lamport \
                     ceiling or history this node has not caught up with yet. In the second \
                     case it is accepted once this node's clock has climbed to within \
                     {MAX_LAMPORT_ADVANCE} of it through the intervening directives — which \
                     never happens when the gap below it was made by a directive this node \
                     refuses, such as one from an author since removed from the allowlist. \
                     {BOOTSTRAP_JOIN_REMEDY}"
                )
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
            // L-14: the acyclicity check gave up on a crafted parent graph. It
            // is a refusal to answer, not a proven cycle, so it gets its own
            // code rather than being reported as CYCLE_DETECTED.
            ServiceError::Dag(DagError::CycleCheckExhausted { .. }) => "CYCLE_CHECK_EXHAUSTED",
            ServiceError::Io(_) => "IO_ERROR",
            ServiceError::AccountAlreadyOpen { .. } => "ACCOUNT_ALREADY_OPEN",
            ServiceError::AccountHasLaterTransactions { .. } => "ACCOUNT_HAS_LATER_TRANSACTIONS",
            ServiceError::AccountNotOpen { .. } => "ACCOUNT_NOT_OPEN",
            ServiceError::ResourceLimitExceeded { .. } => "RESOURCE_LIMIT_EXCEEDED",
            ServiceError::InvalidAccountName { .. } => "INVALID_ACCOUNT_NAME",
            ServiceError::InvalidCurrency { .. } => "INVALID_CURRENCY",
            ServiceError::InvalidTag { .. } => "INVALID_TAG",
            ServiceError::InvalidLink { .. } => "INVALID_LINK",
            ServiceError::InvalidInput { .. } => "INVALID_INPUT",
            ServiceError::DateOutOfRange { .. } => "DATE_OUT_OF_RANGE",
            ServiceError::BodyEnvelopeKey { .. } => "BODY_ENVELOPE_KEY",
            ServiceError::Journal { .. } => "LEDGER_JOURNAL",
            ServiceError::CommitInFlight => "COMMIT_IN_FLIGHT",
            ServiceError::LamportCeiling { .. } => "LAMPORT_CEILING",
            ServiceError::LamportAdvance { .. } => "LAMPORT_ADVANCE",
            ServiceError::SignatureVerdict { .. } => "EVERY_SIGNATURE_FAILED",
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

impl From<crate::journal::JournalError> for ServiceError {
    fn from(e: crate::journal::JournalError) -> Self {
        match e {
            // An unreadable journal is an unreadable ledger: it is routed to the
            // same `Io` arm the `.bean` uses so the L-13 reload path and the
            // GraphQL error mapping (which redacts paths, L3) treat it alike.
            crate::journal::JournalError::Io(error) => ServiceError::Io(error),
            other => ServiceError::Journal {
                message: other.to_string(),
            },
        }
    }
}
