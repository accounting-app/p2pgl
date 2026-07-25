//! Structured parse errors with source location.

/// A parse error with line/column information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// 1-based line number in the source file.
    pub line: usize,
    /// 1-based column number (byte offset within the line).
    pub column: usize,
    /// Human-readable error description.
    pub message: String,
    /// Machine-readable error classification.
    pub kind: ParseErrorKind,
}

/// Classification of parse errors, mapping to §2.8 GraphQL error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseErrorKind {
    /// A date was syntactically wrong or represents an impossible calendar date.
    InvalidDate,
    /// An account name does not match `[A-Z][a-zA-Z0-9-]*` segments under a valid root.
    InvalidAccountName,
    /// A currency code does not match `[A-Z][A-Z0-9'._-]{0,22}[A-Z0-9]`.
    InvalidCurrency,
    /// A number could not be parsed as a decimal.
    InvalidNumber,
    /// A directive keyword is recognized but not in the supported set (§2.3).
    UnsupportedDirective,
    /// An unexpected character or token was encountered.
    UnexpectedToken,
    /// A quoted string was not terminated.
    UnterminatedString,
    /// A non-string metadata value was encountered (§3.3.2: strings only).
    InvalidMetadataValue,
    /// A tag did not match `#[a-zA-Z0-9_-]+`.
    InvalidTag,
    /// A link did not match `^[a-zA-Z0-9_-]+`.
    InvalidLink,
    /// A structural error in the file (e.g., indented line without a directive).
    BadStructure,
}

impl ParseError {
    pub fn new(line: usize, column: usize, message: impl Into<String>, kind: ParseErrorKind) -> Self {
        ParseError {
            line,
            column,
            message: message.into(),
            kind,
        }
    }
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "line {}:{}: {} ({:?})",
            self.line, self.column, self.message, self.kind
        )
    }
}

impl std::error::Error for ParseError {}
