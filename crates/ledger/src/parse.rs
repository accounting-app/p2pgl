//! Hand-written recursive-descent parser for the Beancount directive subset (§2.3, §3.3.2).
//!
//! Entry point: [`parse_file`].

use chrono::NaiveDate;
use rust_decimal::Decimal;
use std::collections::BTreeMap;

use crate::error::{ParseError, ParseErrorKind};
use crate::model::*;

// ─── Scanner ─────────────────────────────────────────────────────────────────

/// Character-level scanner for a single line of text.
///
/// ## Materialised lazily (T75 / M-48)
///
/// `chars` holds only the characters the scanner has consumed or peeked at —
/// it grows as the readers advance, and `rest` is the untouched remainder of
/// the line. It used to be `line.chars().collect()` up front: four bytes per
/// character of the WHOLE line, and up to six at the `Vec`'s last doubling,
/// paid before the first token was read. That was the "6× floor" under every
/// long-line shape on the wire — and it was paid in full even when the line
/// was refused at its second character, or when the parser's cardinality caps
/// ([`ParseLimits`]) stop reading at the 101st tag of a 349,518-tag header.
/// Now a line costs what the scanner actually walks.
///
/// Every reader indexes `chars` only over what it has already consumed
/// (`self.chars[start..self.position]`), so the lazy fill is invisible to
/// them; the three methods that look ahead without consuming — [`Self::at_eol`],
/// [`Self::rest_of_line`], [`Self::column_of_rest`] — walk a clone of `rest`
/// instead of materialising it.
struct Scanner<'line> {
    /// The characters consumed or peeked at so far (see the type docs).
    chars: Vec<char>,
    /// The part of the line not yet in `chars`.
    rest: std::str::Chars<'line>,
    position: usize,
}

impl<'line> Scanner<'line> {
    fn new(line: &'line str) -> Self {
        Scanner {
            chars: Vec::new(),
            rest: line.chars(),
            position: 0,
        }
    }

    /// Make `chars[index]` exist if the line is long enough; `false` if not.
    fn fill_to(&mut self, index: usize) -> bool {
        while self.chars.len() <= index {
            match self.rest.next() {
                Some(character) => self.chars.push(character),
                None => return false,
            }
        }
        true
    }

    /// The characters from the current position to the end of the line,
    /// without materialising any of them.
    fn remaining(&self) -> impl Iterator<Item = char> + '_ {
        self.chars[self.position..]
            .iter()
            .copied()
            .chain(self.rest.clone())
    }

    fn peek(&mut self) -> Option<char> {
        if self.fill_to(self.position) {
            Some(self.chars[self.position])
        } else {
            None
        }
    }

    fn advance(&mut self) -> Option<char> {
        let character = self.peek();
        if character.is_some() {
            self.position += 1;
        }
        character
    }

    fn skip_whitespace(&mut self) {
        while let Some(character) = self.peek() {
            if character == ' ' || character == '\t' {
                self.advance();
            } else {
                break;
            }
        }
    }

    /// True if remaining content is empty, whitespace-only, or a comment.
    fn at_eol(&self) -> bool {
        for character in self.remaining() {
            if character == ';' {
                return true;
            }
            if character != ' ' && character != '\t' {
                return false;
            }
        }
        true
    }

    /// 1-based column number.
    fn column(&self) -> usize {
        self.position + 1
    }

    /// The unconsumed remainder of the line, with surrounding whitespace
    /// trimmed. Empty exactly when [`Self::at_eol`] is true (M-25).
    ///
    /// Only used to quote the offending text back to the operator; nothing
    /// parses it.
    fn rest_of_line(&self) -> String {
        self.remaining().collect::<String>().trim().to_owned()
    }

    /// 1-based column of the first unconsumed NON-blank character (M-25).
    ///
    /// [`Self::column`] would point at the run of spaces that separates the
    /// last token from the junk after it, which is not where the operator
    /// needs to look.
    fn column_of_rest(&self) -> usize {
        let blanks = self
            .remaining()
            .take_while(|character| matches!(character, ' ' | '\t'))
            .count();
        self.position + blanks + 1
    }

    // ── Token readers ────────────────────────────────────────────────────

    fn read_date(&mut self) -> Result<NaiveDate, String> {
        let start = self.position;
        // Read YYYY-MM-DD (exactly 10 characters).
        for expected_digit_count in [4usize, 2, 2] {
            for _ in 0..expected_digit_count {
                match self.advance() {
                    Some(c) if c.is_ascii_digit() => {}
                    _ => return Err("Expected date in YYYY-MM-DD format".to_owned()),
                }
            }
            // After year and month, expect a dash (but not after day).
            if (expected_digit_count == 4 || expected_digit_count == 2)
                && self.position - start < 10
            {
                match self.advance() {
                    Some('-') => {}
                    _ => return Err("Expected '-' in date".to_owned()),
                }
            }
        }
        let date_string: String = self.chars[start..self.position].iter().collect();
        NaiveDate::parse_from_str(&date_string, "%Y-%m-%d")
            .map_err(|_| format!("Invalid date: {date_string}"))
    }

    fn read_word(&mut self) -> String {
        let start = self.position;
        while let Some(character) = self.peek() {
            if character.is_alphanumeric() || character == '_' || character == '-' {
                self.advance();
            } else {
                break;
            }
        }
        self.chars[start..self.position].iter().collect()
    }

    fn read_quoted_string(&mut self) -> Result<String, String> {
        match self.advance() {
            Some('"') => {}
            _ => return Err("Expected opening '\"'".to_owned()),
        }
        let mut result = String::new();
        loop {
            match self.advance() {
                Some('\\') => match self.advance() {
                    Some('"') => result.push('"'),
                    Some('\\') => result.push('\\'),
                    Some(other) => {
                        result.push('\\');
                        result.push(other);
                    }
                    None => return Err("Unterminated string (escape at end)".to_owned()),
                },
                Some('"') => return Ok(result),
                Some(character) => result.push(character),
                None => return Err("Unterminated string".to_owned()),
            }
        }
    }

    fn read_number(&mut self) -> Result<Decimal, String> {
        let start = self.position;
        // Optional sign.
        if self.peek() == Some('-') || self.peek() == Some('+') {
            self.advance();
        }
        // Digits (with optional comma separators).
        let mut has_digits = false;
        while let Some(character) = self.peek() {
            if character.is_ascii_digit() || character == ',' {
                if character.is_ascii_digit() {
                    has_digits = true;
                }
                self.advance();
            } else {
                break;
            }
        }
        // Optional decimal point + fractional digits.
        if self.peek() == Some('.') {
            self.advance();
            while let Some(character) = self.peek() {
                if character.is_ascii_digit() {
                    has_digits = true;
                    self.advance();
                } else {
                    break;
                }
            }
        }
        if !has_digits {
            return Err("Expected a number".to_owned());
        }
        let number_string: String = self.chars[start..self.position]
            .iter()
            .filter(|c| **c != ',')
            .collect();
        // H-17: `from_str_exact`, not `from_str`. The latter silently rounds a
        // fraction longer than 28 digits, so the number held — and hashed, and
        // judged against the cap in `read_summed_amount` — was not the number
        // the file says.
        Decimal::from_str_exact(&number_string).map_err(|e| format!("Invalid number: {e}"))
    }

    fn read_currency(&mut self) -> Result<String, String> {
        let start = self.position;
        while let Some(character) = self.peek() {
            if character.is_ascii_uppercase()
                || character.is_ascii_digit()
                || character == '\''
                || character == '.'
                || character == '_'
                || character == '-'
            {
                self.advance();
            } else {
                break;
            }
        }
        let currency: String = self.chars[start..self.position].iter().collect();
        if currency.is_empty() {
            return Err("Expected a currency code".to_owned());
        }
        validate_currency(&currency)?;
        Ok(currency)
    }

    /// An amount that is never summed — a `balance` assertion's or a `price`
    /// directive's — so the amount cap does not apply (T76).
    fn read_amount(&mut self) -> Result<Amount, String> {
        let number = self.read_number()?;
        self.skip_whitespace();
        let currency = self.read_currency()?;
        Ok(Amount { number, currency })
    }

    /// An amount that is summed into a balance or feeds one — posting units,
    /// `{cost}`, `@`/`@@` price — under the amount cap
    /// ([`crate::limits::MAX_AMOUNT_MAGNITUDE`], `|amount| ≤ 10^21`, H-17 /
    /// T76).
    ///
    /// Every `.bean` body is read here, so this is the cap on the wire
    /// (`validate_supply_entry` re-parses the body), in journal replay and on
    /// the file path at boot and on reconcile — where the refused block is
    /// quarantined rather than loaded. Boot applies no transaction-level
    /// validation to a whole-file load, so for history this is the check.
    /// Checked on the number as held — spelling and scale untouched — and on
    /// its magnitude, so trailing zeros are never counted against it.
    fn read_summed_amount(&mut self, label: &'static str) -> Result<Amount, String> {
        let amount = self.read_amount()?;
        crate::validate::check_amount_cap(label, amount.number)
            .map_err(|error| error.to_string())?;
        Ok(amount)
    }

    /// Reject a just-read token that carries a character outside `allowed`, and
    /// rewind to that character so the caller's `column()` points at it (L-25).
    ///
    /// The token readers below deliberately *consume* Unicode alphanumerics
    /// before checking them: stopping the scan at the first non-ASCII character
    /// would truncate `Assets:Cаsh` to the perfectly valid `Assets:C` and
    /// surface some unrelated complaint about the rest of the line. Reading the
    /// whole word first lets the error name the offending character, quote the
    /// word it appeared in, and point at its column.
    ///
    /// `start` is the scanner position the token began at; positions are char
    /// indices into `chars`, so `start + offset` is the character itself.
    fn reject_disallowed_character(
        &mut self,
        token: &str,
        start: usize,
        label: &str,
        allowed: fn(char) -> bool,
    ) -> Result<(), String> {
        let Some((offset, character)) = token.chars().enumerate().find(|(_, c)| !allowed(*c))
        else {
            return Ok(());
        };
        self.position = start + offset;
        Err(format!(
            "Invalid character '{character}' (U+{:04X}) in {label} '{token}': \
             {label}s are ASCII-only",
            character as u32
        ))
    }

    fn read_account(&mut self) -> Result<String, String> {
        let start = self.position;
        // Read segments separated by colons.
        while let Some(character) = self.peek() {
            if character.is_alphanumeric() || character == ':' || character == '-' {
                self.advance();
            } else {
                break;
            }
        }
        let account: String = self.chars[start..self.position].iter().collect();
        if account.is_empty() {
            return Err("Expected an account name".to_owned());
        }
        self.reject_disallowed_character(&account, start, "account name", |character| {
            is_account_segment_character(character) || character == ':'
        })?;
        validate_account_name(&account)?;
        Ok(account)
    }

    fn read_tag(&mut self) -> Result<String, String> {
        match self.advance() {
            Some('#') => {}
            _ => return Err("Expected '#' for tag".to_owned()),
        }
        let start = self.position;
        while let Some(character) = self.peek() {
            if character.is_alphanumeric() || character == '_' || character == '-' {
                self.advance();
            } else {
                break;
            }
        }
        let tag: String = self.chars[start..self.position].iter().collect();
        if tag.is_empty() {
            return Err("Tag name cannot be empty".to_owned());
        }
        self.reject_disallowed_character(&tag, start, "tag", is_label_character)?;
        validate_tag(&tag)?;
        Ok(tag)
    }

    fn read_link(&mut self) -> Result<String, String> {
        match self.advance() {
            Some('^') => {}
            _ => return Err("Expected '^' for link".to_owned()),
        }
        let start = self.position;
        while let Some(character) = self.peek() {
            if character.is_alphanumeric() || character == '_' || character == '-' {
                self.advance();
            } else {
                break;
            }
        }
        let link: String = self.chars[start..self.position].iter().collect();
        if link.is_empty() {
            return Err("Link name cannot be empty".to_owned());
        }
        self.reject_disallowed_character(&link, start, "link", is_label_character)?;
        validate_link(&link)?;
        Ok(link)
    }
}

// ─── Validation ──────────────────────────────────────────────────────────────

const VALID_ROOTS: [&str; 5] = ["Assets", "Liabilities", "Equity", "Income", "Expenses"];

/// Characters legal after the first one in an account segment: `[A-Za-z0-9-]`.
///
/// ASCII-only, deliberately (L-25). `char::is_alphanumeric` is Unicode-aware, so
/// it used to admit `Assets:Cаsh` with a Cyrillic `а` (U+0430) as an account
/// distinct from — and pixel-identical to — `Assets:Cash`. Account names are
/// identity in this system: they key the read model, the trial balance and every
/// I3/I9 lifecycle check, and they are hashed into the content id. Two spellings
/// that no reviewer can tell apart are a confusable-account forgery, so the
/// grammar §2.3 already documented (`[A-Z][a-zA-Z0-9-]*`) is now enforced
/// literally. This predicate is the single source of that rule for both the
/// parser and [`validate_account_name`], which is also the API-side validator.
fn is_account_segment_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '-'
}

/// Characters legal in a tag or link body: `[A-Za-z0-9_-]` (§2.3).
///
/// Already what [`validate_tag`]/[`validate_link`] enforced on the API side;
/// shared here so the parser's token readers cannot drift laxer again (L-25).
fn is_label_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_' || character == '-'
}

/// Validate account name per §2.3: `Root:Segment:Segment` where each segment
/// matches `[A-Z][a-zA-Z0-9-]*` — ASCII only (L-25, see
/// [`is_account_segment_character`]).
pub fn validate_account_name(name: &str) -> Result<(), String> {
    let segments: Vec<&str> = name.split(':').collect();
    if segments.len() < 2 {
        return Err(format!(
            "Account name must have at least two segments (root:sub), got: {name}"
        ));
    }
    if !VALID_ROOTS.contains(&segments[0]) {
        return Err(format!(
            "Account root must be one of {:?}, got: {}",
            VALID_ROOTS, segments[0]
        ));
    }
    for (index, segment) in segments.iter().enumerate() {
        if segment.is_empty() {
            return Err(format!("Account segment {index} is empty in: {name}"));
        }
        let first_character = segment.chars().next().unwrap();
        if !first_character.is_ascii_uppercase() {
            return Err(format!(
                "Account segment must start with uppercase letter, got '{first_character}' in: {name}"
            ));
        }
        for character in segment.chars().skip(1) {
            if !is_account_segment_character(character) {
                return Err(format!(
                    "Invalid character '{character}' (U+{:04X}) in account segment: {name}",
                    character as u32
                ));
            }
        }
    }
    Ok(())
}

/// Validate currency per §2.3: `[A-Z][A-Z0-9'._-]{0,22}[A-Z0-9]` (min 2 chars).
pub fn validate_currency(currency: &str) -> Result<(), String> {
    // T75: the length is decided before anything is collected, and an
    // over-long code is excerpted rather than echoed. A 1 MiB currency on the
    // wire used to cost a 4 MiB `Vec<char>` here plus a 1 MiB error message on
    // top of the parser's own copy — 11× the body, for a refusal.
    let length = currency.chars().count();
    if length < 2 {
        return Err(format!(
            "Currency must be at least 2 characters, got: {currency}"
        ));
    }
    if length > 24 {
        return Err(format!(
            "Currency must be at most 24 characters, got {length}: {}",
            excerpt_token(currency)
        ));
    }
    let chars: Vec<char> = currency.chars().collect();
    if !chars[0].is_ascii_uppercase() {
        return Err(format!(
            "Currency must start with uppercase letter, got: {currency}"
        ));
    }
    let last = chars[chars.len() - 1];
    if !last.is_ascii_uppercase() && !last.is_ascii_digit() {
        return Err(format!(
            "Currency must end with uppercase letter or digit, got: {currency}"
        ));
    }
    for &character in &chars[1..chars.len() - 1] {
        if !character.is_ascii_uppercase()
            && !character.is_ascii_digit()
            && character != '\''
            && character != '.'
            && character != '_'
            && character != '-'
        {
            return Err(format!(
                "Invalid character '{character}' in currency: {currency}"
            ));
        }
    }
    Ok(())
}

/// Validate a tag name per §2.3: `[a-zA-Z0-9_-]+`.
pub fn validate_tag(tag: &str) -> Result<(), String> {
    if tag.is_empty() {
        return Err("Tag name cannot be empty".to_owned());
    }
    if !tag.chars().all(is_label_character) {
        return Err(format!("Invalid character in tag: {tag}"));
    }
    Ok(())
}

/// Validate a link name per §2.3: `^[a-zA-Z0-9_-]+`.
pub fn validate_link(link: &str) -> Result<(), String> {
    if link.is_empty() {
        return Err("Link name cannot be empty".to_owned());
    }
    if !link.chars().all(is_label_character) {
        return Err(format!("Invalid character in link: {link}"));
    }
    Ok(())
}

/// Validate a metadata key: `[a-z][a-zA-Z0-9_-]*`, ASCII only (T41).
///
/// The same rule L-25 applied to accounts, tags and links, for the same reason
/// and by the same mechanism — `read_word` uses Unicode-aware
/// `char::is_alphanumeric`, so `nаrration:` with a Cyrillic `а` (U+0430) parsed
/// as a metadata key distinct from, and pixel-identical to, `narration:`. A
/// metadata key is not decoration: it is part of the serialized body, so it is
/// hashed into the content id, and the `openledger-` prefix check that decides
/// whether a key is envelope or body (H-06) is a byte comparison against a
/// key the reviewer cannot read reliably.
///
/// The leading-lowercase requirement is not new here — [`is_metadata_line`]
/// already dispatches on `is_ascii_lowercase`, so a key that failed it was
/// never read as metadata in the first place. This is the single source of the
/// rule for the parser and for `service::validate_body_strings`, matching
/// [`is_account_segment_character`]'s role for L-25.
pub fn validate_metadata_key(key: &str) -> Result<(), String> {
    if key.is_empty() {
        return Err("Metadata key cannot be empty".to_owned());
    }
    let first = key.chars().next().expect("non-empty, checked above");
    if !first.is_ascii_lowercase() {
        return Err(format!(
            "Metadata key must start with a lowercase ASCII letter, got '{first}' in: {key}"
        ));
    }
    if let Some(character) = key.chars().find(|c| !is_label_character(*c)) {
        return Err(format!(
            "Invalid character '{character}' (U+{:04X}) in metadata key: {key}",
            character as u32
        ));
    }
    Ok(())
}

/// The L-16 rule, in one place: a cost or price number must be **strictly
/// positive**.
///
/// A cost/price is a conversion rate between the posting's stated currency and
/// the currency its I1 weight is booked in, so zero or below has no economic
/// reading — see `crate::weights::check_cost_and_price_numbers` for what each
/// sign actually does to the balance identity. This predicate is shared by the
/// parser (so a hand-edited or peer-supplied `.bean` cannot carry one) and by
/// the weight computation (so no in-memory `Directive` built by a library caller
/// can either), exactly as [`is_account_segment_character`] is shared for L-25.
pub fn is_valid_cost_or_price_number(number: Decimal) -> bool {
    number > Decimal::ZERO
}

/// Reject ASCII control characters that can break `.bean` serialization (H-8).
pub fn reject_control_characters(label: &str, value: &str) -> Result<(), String> {
    if value.chars().any(char::is_control) {
        return Err(format!("{label} contains control characters"));
    }
    Ok(())
}

// ─── Unsupported directives ──────────────────────────────────────────────────

const UNSUPPORTED_DIRECTIVES: [&str; 8] = [
    "include", "option", "plugin", "query", "pushtag", "poptag", "pushmeta", "popmeta",
];

// ─── Byte-order mark ─────────────────────────────────────────────────────────

/// The UTF-8 byte-order mark: `U+FEFF`, encoded as the bytes `EF BB BF`.
pub const BYTE_ORDER_MARK: char = '\u{FEFF}';

/// Strip exactly one leading UTF-8 byte-order mark from file content (L-28).
///
/// A BOM is not data — it is an encoding hint some editors (Notepad, VS Code's
/// "UTF-8 with BOM", anything saving a file on Windows) prepend the moment a
/// human opens and saves a `.bean` file. `str::lines` hands it back glued to the
/// front of the first line, so the first directive header no longer starts with
/// a date and fails to parse; because [`parse_file`] fails the *whole* file when
/// any line fails, one editor visit bricked every subsequent boot.
///
/// Exactly one mark is removed. A second `U+FEFF` is a genuine zero-width
/// no-break space inside the content and still fails to parse, so this cannot be
/// used to smuggle invisible characters past the parser.
pub fn strip_byte_order_mark(input: &str) -> &str {
    input.strip_prefix(BYTE_ORDER_MARK).unwrap_or(input)
}

// ─── Top-level ───────────────────────────────────────────────────────────────

/// Parse a complete `.bean` file into a list of directives.
///
/// A single leading UTF-8 BOM is stripped first (L-28, see
/// [`strip_byte_order_mark`]); the resulting directives — and therefore their
/// content ids — are identical to the same file without one.
///
/// Returns `Err` with all accumulated errors if any line fails to parse.
///
/// This is the FILE loader's entry point and it deliberately keeps every
/// error: an operator fixing a hand-edited `.bean` wants the whole list. The
/// remote path must not use it — see [`parse_file_bounded`] (H-18).
///
/// It applies no [`ParseLimits`] either (T75): a file is this ledger's own
/// history, and boot's standing rule is that it applies no write caps. The
/// write paths that admit NEW records from a file (`reconcile_content`) hold
/// them to `service::enforce_resource_limits` after the parse instead.
pub fn parse_file(input: &str) -> Result<Vec<Directive>, Vec<ParseError>> {
    parse_file_with_cap(input, None, ParseLimits::UNLIMITED).map_err(|bounded| bounded.errors)
}

/// The errors of a [`parse_file_bounded`] run: the first `max_errors` in
/// source order, plus how many there were in all (H-18).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedParseErrors {
    /// At most the `max_errors` the caller asked for, in source order.
    pub errors: Vec<ParseError>,
    /// Every block that failed, counted whether or not it was kept.
    pub total: usize,
    /// The [`ParseLimits`] cap the parse stopped at, if it stopped at one
    /// (T75). The parse ends there — no later block is read — so `errors` and
    /// `total` describe only what came before it. A cap is not a syntax error
    /// and is not counted in `total`.
    pub limit: Option<ParseLimitExceeded>,
}

/// Cardinality caps the parser enforces WHILE it reads (T75 / M-48).
///
/// The §3.12 caps used to run only after a whole directive had been
/// materialised — on the wire, not until `stage_remote_directive`, after
/// `validate_supply_entry` had built the directive and the batch had queued it.
/// A valid 1 MiB body of 41,941 postings with one metadata line each peaked at
/// 41.7× its size in the parser and was refused only at stage; a 15-entry
/// `Supply` of them held 546 MB. Counting inside the block loop stops the parse
/// at the first item past a cap, so what a body can make the parser hold is
/// bounded by the caps, not by the body's length.
///
/// Every cap here is one `service::enforce_resource_limits` also applies — the
/// parser refuses sooner, never more: a directive this node may write through
/// its local API can never be refused by a peer's parser (the L-02 rule).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseLimits {
    /// Postings in one transaction.
    pub max_postings: usize,
    /// Tags on one transaction header.
    pub max_tags: usize,
    /// Links on one transaction header.
    pub max_links: usize,
    /// Distinct keys in one directive's own metadata map.
    pub max_metadata_keys: usize,
    /// Distinct posting-level metadata keys, summed over one transaction's
    /// postings.
    pub max_posting_metadata_keys: usize,
    /// Currencies in one `open` directive's constraint list.
    pub max_currencies: usize,
}

impl ParseLimits {
    /// No caps — [`parse_file`], the file loader.
    pub const UNLIMITED: ParseLimits = ParseLimits {
        max_postings: usize::MAX,
        max_tags: usize::MAX,
        max_links: usize::MAX,
        max_metadata_keys: usize::MAX,
        max_posting_metadata_keys: usize::MAX,
        max_currencies: usize::MAX,
    };

    /// The §3.12 resource limits, each the constant
    /// `service::enforce_resource_limits` refuses by — referenced here, never
    /// restated. The wire's parser (`validate_supply_entry`) uses this.
    pub const RESOURCE: ParseLimits = ParseLimits {
        max_postings: crate::service::MAX_POSTINGS_PER_TRANSACTION,
        max_tags: crate::service::MAX_TAGS_PER_TRANSACTION,
        max_links: crate::service::MAX_LINKS_PER_TRANSACTION,
        max_metadata_keys: crate::service::MAX_METADATA_KEYS_PER_DIRECTIVE,
        max_posting_metadata_keys: crate::limits::MAX_POSTING_METADATA_KEYS_PER_TRANSACTION,
        max_currencies: crate::limits::MAX_CURRENCIES_PER_OPEN,
    };

    /// The most non-blank, non-comment body lines one block can have and still
    /// be within every cap.
    ///
    /// Every such line is a posting, a directive metadata line or a posting
    /// metadata line (anything else is a parse error), so a block with more
    /// lines than the three caps together is over one of them, is a parse
    /// error, or repeats a metadata key — which no canonical body does. The
    /// block loop refuses it while COLLECTING the lines, before any of them is
    /// parsed: the 16 bytes per line of `body_lines` were themselves 9× a body
    /// of 262,144 four-byte lines.
    fn max_body_lines(&self) -> usize {
        self.max_postings
            .saturating_add(self.max_metadata_keys)
            .saturating_add(self.max_posting_metadata_keys)
    }
}

/// Which [`ParseLimits`] cap a parse stopped at, and where (T75).
///
/// Carries no peer text — a fixed-size rendering whatever the body was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseLimitExceeded {
    /// 1-based line the count went past the cap on.
    pub line: usize,
    /// What was counted, e.g. `"postings"`.
    pub what: &'static str,
    /// The cap.
    pub max: usize,
}

impl std::fmt::Display for ParseLimitExceeded {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "Too many {}: more than {} (max {}), at line {}; parsing stopped there",
            self.what, self.max, self.max, self.line
        )
    }
}

/// The [`ParseLimits`] of one parse run, and the cap it tripped (T75).
///
/// A tripped cap is returned up the parser as an ordinary `ParseError` so every
/// reader's `?` carries it out unchanged; `tripped` is what tells the block
/// loop that the error was a cap, and that the parse must stop.
struct LimitGate {
    limits: ParseLimits,
    tripped: Option<ParseLimitExceeded>,
}

impl LimitGate {
    /// Refuse once `count` exceeds `max`.
    fn check(
        &mut self,
        count: usize,
        max: usize,
        what: &'static str,
        line: usize,
    ) -> Result<(), ParseError> {
        if count <= max {
            return Ok(());
        }
        let exceeded = ParseLimitExceeded { line, what, max };
        let error = ParseError::new(line, 1, exceeded.to_string(), ParseErrorKind::BadStructure);
        self.tripped = Some(exceeded);
        Err(error)
    }
}

/// [`parse_file`] for input a PEER wrote: keep at most `max_errors` errors,
/// count the rest (T66 / H-18).
///
/// `parse_file` pushes one `ParseError` per failed block with no cap, and a
/// 1 MiB body of `"x\n"` × 524,288 is 524,288 failed blocks — measured at
/// ~195 MB of transient allocation and a 55 MB error string per entry, after
/// every frame cap had already been paid. The block loop is the same one the
/// file loader runs; the only difference is that an error past the cap is
/// dropped as soon as it is made, so the live set is `max_errors` deep no
/// matter how long the body is. The count still covers every block, so the
/// caller can say "524,288 parse errors; first: …" rather than pretend there
/// were three.
///
/// `max_errors == 0` keeps nothing and only counts.
///
/// `limits` (T75 / M-48) are counted inside the block loop: the parse STOPS at
/// the first posting, tag, link, metadata key, currency or body line past its
/// cap and reports it in [`BoundedParseErrors::limit`]. The wire passes
/// [`ParseLimits::RESOURCE`]; [`ParseLimits::UNLIMITED`] is `parse_file`'s
/// behaviour with the error cap.
pub fn parse_file_bounded(
    input: &str,
    max_errors: usize,
    limits: ParseLimits,
) -> Result<Vec<Directive>, BoundedParseErrors> {
    parse_file_with_cap(input, Some(max_errors), limits)
}

/// How many directive blocks [`parse_file`] would see in `input` (T66 / H-18).
///
/// A block is one non-indented, non-blank, non-comment line plus the indented
/// lines under it. Every block yields exactly one directive or one error, so
/// for a body with no stray indented lines this is `directives.len() +
/// errors.len()` of a `parse_file` run — without parsing, allocating, or
/// keeping anything. (A stray indented line before any header is an error but
/// not a block; it is under-counted, never over-counted, which is the safe
/// direction for a refusal gate.) The wire path expects exactly one directive
/// per entry and uses this to refuse a many-block body BEFORE paying to parse
/// it; `count_directive_headers_agrees_with_parse_file` pins the two to the
/// same rule.
pub fn count_directive_headers(input: &str) -> usize {
    strip_byte_order_mark(input)
        .lines()
        .filter(|line| {
            let trimmed = line.trim();
            !trimmed.is_empty()
                && !trimmed.starts_with(';')
                && !line.starts_with(' ')
                && !line.starts_with('\t')
        })
        .count()
}

/// The one block loop behind [`parse_file`] and [`parse_file_bounded`].
///
/// `max_errors` of `None` keeps every error (the file loader); `Some(n)` keeps
/// the first `n` and counts the rest (the wire path, H-18). `limits` stop the
/// parse at the first count past a cap (the wire path, T75).
fn parse_file_with_cap(
    input: &str,
    max_errors: Option<usize>,
    limits: ParseLimits,
) -> Result<Vec<Directive>, BoundedParseErrors> {
    let input = strip_byte_order_mark(input);
    let mut gate = LimitGate {
        limits,
        tripped: None,
    };
    let max_body_lines = limits.max_body_lines();

    let mut directives = Vec::new();
    let mut errors = Vec::new();
    let mut total_errors = 0usize;
    let mut note_error = |errors: &mut Vec<ParseError>, error: ParseError| {
        total_errors += 1;
        if max_errors.is_none_or(|cap| errors.len() < cap) {
            errors.push(error);
        }
    };

    // H-18 (T66): the lines are walked, not collected. `input.lines().collect()`
    // was a 16-byte `&str` per line — 5× the body for three-byte lines, 12×
    // at the `Vec`'s last doubling with the old buffer still live — paid before
    // a single block was parsed, on the wire path as on the file path. A
    // peekable iterator sees exactly what the indexed loop saw: a block's body
    // is consumed line by line, and the blank or non-indented line that ends it
    // is left for the outer loop.
    let mut lines = input.lines().enumerate().peekable();

    while let Some((index, line)) = lines.next() {
        let trimmed = line.trim();

        // Skip blank lines and comment-only lines.
        if trimmed.is_empty() || trimmed.starts_with(';') {
            continue;
        }

        // A directive header starts at column 0 (not indented).
        if !line.starts_with(' ') && !line.starts_with('\t') {
            let header_line_number = index + 1; // 1-based
            let header = line;

            // Collect indented body lines (postings + metadata).
            let mut body_lines: Vec<(usize, &str)> = Vec::new();
            while let Some(&(body_index, body_line)) = lines.peek() {
                if body_line.is_empty() {
                    // Blank line ends the block.
                    break;
                }
                if body_line.starts_with(' ') || body_line.starts_with('\t') {
                    let body_trimmed = body_line.trim();
                    if !body_trimmed.is_empty() && !body_trimmed.starts_with(';') {
                        // T75: refused while collecting, before a line is parsed.
                        if gate
                            .check(
                                body_lines.len() + 1,
                                max_body_lines,
                                "body lines in one directive",
                                body_index + 1,
                            )
                            .is_err()
                        {
                            return Err(BoundedParseErrors {
                                errors,
                                total: total_errors,
                                limit: gate.tripped,
                            });
                        }
                        body_lines.push((body_index + 1, body_line));
                    }
                    lines.next();
                } else {
                    // Next non-indented line = next directive.
                    break;
                }
            }

            match parse_directive_block(header, &body_lines, header_line_number, &mut gate) {
                Ok(directive) => directives.push(directive),
                // T75: a cap is not a syntax error — the parse stops here.
                Err(_) if gate.tripped.is_some() => {
                    return Err(BoundedParseErrors {
                        errors,
                        total: total_errors,
                        limit: gate.tripped,
                    });
                }
                Err(error) => note_error(&mut errors, error),
            }
        } else {
            note_error(
                &mut errors,
                ParseError::new(
                    index + 1,
                    1,
                    "Unexpected indented line without a preceding directive",
                    ParseErrorKind::BadStructure,
                ),
            );
        }
    }

    if total_errors == 0 {
        Ok(directives)
    } else {
        Err(BoundedParseErrors {
            errors,
            total: total_errors,
            limit: None,
        })
    }
}

/// Quote at most [`TRAILING_CONTENT_EXCERPT_CHARS`] of a peer-chosen token
/// back in an error message (M-41).
///
/// The same excerpting `reject_trailing_content` does, and for the same
/// reason: a token is attacker text on the wire path, and `Unsupported
/// directive: '<1 MiB>'` was a 1 MiB error string — then a 1 MiB log line.
fn excerpt_token(token: &str) -> String {
    if token.chars().count() > TRAILING_CONTENT_EXCERPT_CHARS {
        token
            .chars()
            .take(TRAILING_CONTENT_EXCERPT_CHARS)
            .chain(std::iter::once('\u{2026}'))
            .collect()
    } else {
        token.to_owned()
    }
}

// ─── Trailing-content check (M-25) ───────────────────────────────────────────

/// How much of the offending text a rejection quotes back.
const TRAILING_CONTENT_EXCERPT_CHARS: usize = 60;

/// Refuse a line that still carries tokens after its grammar is satisfied (M-25).
///
/// Every line form in this grammar used to stop scanning the moment it had what
/// it came for and simply **drop the rest of the line**. That is not a cosmetic
/// leniency, because the `.bean` is a read-write interface: a half-finished
/// hand edit was not rejected and not logged, it was re-read as a *different,
/// valid* directive, adopted, signed with this node's key and written back
/// truncated. `2024-01-01 close Assets:Cash 2020-01-01` became
/// `2024-01-01 close Assets:Cash`; `Assets:Cash 1 USD this is dropped` lost its
/// tail without a trace; a third quoted string on a transaction header
/// vanished. The rejection tally that exists so an operator "has a way to find
/// out what they lost" (L-12) never fired, because nothing was ever refused.
///
/// So the rule is now: after the last token a form legitimately accepts, the
/// line must be at end-of-line. [`Scanner::at_eol`] — not a bare
/// `position == len` — is what makes that safe, because it is the established
/// shape here (`parse_open`'s optional currency list and `parse_posting_line`'s
/// elided-posting check both use it): trailing spaces, tabs and a `;` comment
/// are end-of-line, so every legitimate trailing form still parses. Anything
/// else is a refusal, and a refusal surfaces — a file that does not parse
/// blocks writes until a human repairs it rather than being canonicalised on
/// top of a half-saved edit, which is the trade `reconcile_content` already
/// documents and the only one that does not lose data.
fn reject_trailing_content(
    scanner: &Scanner,
    line_number: usize,
    form: &str,
) -> Result<(), ParseError> {
    if scanner.at_eol() {
        return Ok(());
    }
    let excerpt = excerpt_token(&scanner.rest_of_line());
    Err(ParseError::new(
        line_number,
        scanner.column_of_rest(),
        format!("Unexpected trailing content after {form}: '{excerpt}'"),
        ParseErrorKind::UnexpectedToken,
    ))
}

// ─── Directive block parsing ─────────────────────────────────────────────────

fn parse_directive_block(
    header: &str,
    body_lines: &[(usize, &str)],
    line_number: usize,
    gate: &mut LimitGate,
) -> Result<Directive, ParseError> {
    let directive = parse_directive_block_counted(header, body_lines, line_number, gate)?;
    // T75: the directive-level metadata cap for every kind. Transactions are
    // counted as their body is read (`parse_transaction_body`); the other kinds
    // hold nothing but metadata in their body, which the block loop's body-line
    // cap has already bounded, so checking the finished map is as early as it
    // needs to be.
    gate.check(
        directive.metadata().len(),
        gate.limits.max_metadata_keys,
        "metadata keys",
        line_number,
    )?;
    Ok(directive)
}

fn parse_directive_block_counted(
    header: &str,
    body_lines: &[(usize, &str)],
    line_number: usize,
    gate: &mut LimitGate,
) -> Result<Directive, ParseError> {
    let mut scanner = Scanner::new(header);

    // Read date.
    let date = scanner.read_date().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::InvalidDate,
        )
    })?;

    scanner.skip_whitespace();

    // Read directive keyword or transaction flag.
    let next_char = scanner.peek().ok_or_else(|| {
        ParseError::new(
            line_number,
            scanner.column(),
            "Expected directive keyword after date",
            ParseErrorKind::UnexpectedToken,
        )
    })?;

    match next_char {
        '*' | '!' => {
            let flag = if next_char == '*' {
                Flag::Complete
            } else {
                Flag::Incomplete
            };
            scanner.advance();
            parse_transaction(&mut scanner, date, flag, body_lines, line_number, gate)
                .map(Directive::Transaction)
        }
        _ => {
            let keyword = scanner.read_word();
            if keyword.is_empty() {
                return Err(ParseError::new(
                    line_number,
                    scanner.column(),
                    format!("Unexpected character: '{next_char}'"),
                    ParseErrorKind::UnexpectedToken,
                ));
            }

            // Check for unsupported directives (CT-15).
            if UNSUPPORTED_DIRECTIVES.contains(&keyword.as_str()) || keyword == "custom" {
                return Err(ParseError::new(
                    line_number,
                    scanner.column(),
                    format!("Unsupported directive: '{}'", excerpt_token(&keyword)),
                    ParseErrorKind::UnsupportedDirective,
                ));
            }

            match keyword.as_str() {
                "txn" => parse_transaction(
                    &mut scanner,
                    date,
                    Flag::Complete,
                    body_lines,
                    line_number,
                    gate,
                )
                .map(Directive::Transaction),
                "open" => parse_open(&mut scanner, date, body_lines, line_number, gate)
                    .map(Directive::Open),
                "close" => {
                    parse_close(&mut scanner, date, body_lines, line_number).map(Directive::Close)
                }
                "commodity" => parse_commodity(&mut scanner, date, body_lines, line_number)
                    .map(Directive::Commodity),
                "pad" => parse_pad(&mut scanner, date, body_lines, line_number).map(Directive::Pad),
                "balance" => parse_balance(&mut scanner, date, body_lines, line_number)
                    .map(Directive::Balance),
                "note" => {
                    parse_note(&mut scanner, date, body_lines, line_number).map(Directive::Note)
                }
                "document" => parse_document(&mut scanner, date, body_lines, line_number)
                    .map(Directive::Document),
                "event" => {
                    parse_event(&mut scanner, date, body_lines, line_number).map(Directive::Event)
                }
                "price" => {
                    parse_price(&mut scanner, date, body_lines, line_number).map(Directive::Price)
                }
                _ => Err(ParseError::new(
                    line_number,
                    scanner.column(),
                    format!("Unsupported directive: '{}'", excerpt_token(&keyword)),
                    ParseErrorKind::UnsupportedDirective,
                )),
            }
        }
    }
}

// ─── Transaction ─────────────────────────────────────────────────────────────

fn parse_transaction(
    scanner: &mut Scanner,
    date: NaiveDate,
    flag: Flag,
    body_lines: &[(usize, &str)],
    line_number: usize,
    gate: &mut LimitGate,
) -> Result<Transaction, ParseError> {
    scanner.skip_whitespace();

    // Read optional payee and narration (0, 1, or 2 quoted strings).
    let mut payee = None;
    let mut narration = None;

    if scanner.peek() == Some('"') {
        let first_string = scanner.read_quoted_string().map_err(|message| {
            ParseError::new(
                line_number,
                scanner.column(),
                message,
                ParseErrorKind::UnterminatedString,
            )
        })?;
        scanner.skip_whitespace();
        if scanner.peek() == Some('"') {
            let second_string = scanner.read_quoted_string().map_err(|message| {
                ParseError::new(
                    line_number,
                    scanner.column(),
                    message,
                    ParseErrorKind::UnterminatedString,
                )
            })?;
            payee = Some(first_string);
            narration = Some(second_string);
        } else {
            narration = Some(first_string);
        }
    }

    // Read tags and links (any order, interleaved).
    let mut tags = Vec::new();
    let mut links = Vec::new();
    loop {
        scanner.skip_whitespace();
        match scanner.peek() {
            Some('#') => {
                let tag = scanner.read_tag().map_err(|message| {
                    ParseError::new(
                        line_number,
                        scanner.column(),
                        message,
                        ParseErrorKind::InvalidTag,
                    )
                })?;
                tags.push(tag);
                // T75: counted as read — a 349,518-tag header stops at the 101st.
                gate.check(tags.len(), gate.limits.max_tags, "tags", line_number)?;
            }
            Some('^') => {
                let link = scanner.read_link().map_err(|message| {
                    ParseError::new(
                        line_number,
                        scanner.column(),
                        message,
                        ParseErrorKind::InvalidLink,
                    )
                })?;
                links.push(link);
                gate.check(links.len(), gate.limits.max_links, "links", line_number)?;
            }
            _ => break,
        }
    }

    // M-25: a third quoted string, a stray word, a half-typed tag — anything
    // after the tags and links — used to be dropped, leaving a DIFFERENT
    // transaction to be adopted and re-signed.
    reject_trailing_content(scanner, line_number, "a transaction header")?;

    // Parse body lines into transaction metadata and postings.
    let (metadata, postings) = parse_transaction_body(body_lines, gate)?;

    Ok(Transaction {
        date,
        flag,
        payee,
        narration,
        tags,
        links,
        postings,
        metadata,
    })
}

// ─── Non-transaction directive parsers ───────────────────────────────────────

fn parse_open(
    scanner: &mut Scanner,
    date: NaiveDate,
    body_lines: &[(usize, &str)],
    line_number: usize,
    gate: &mut LimitGate,
) -> Result<Open, ParseError> {
    scanner.skip_whitespace();
    let account = scanner.read_account().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::InvalidAccountName,
        )
    })?;

    // Optional comma-separated currency list.
    let mut currencies = Vec::new();
    scanner.skip_whitespace();
    if !scanner.at_eol() {
        // First currency (no leading comma).
        let currency = scanner.read_currency().map_err(|message| {
            ParseError::new(
                line_number,
                scanner.column(),
                message,
                ParseErrorKind::InvalidCurrency,
            )
        })?;
        currencies.push(currency);

        // Subsequent currencies after commas.
        loop {
            scanner.skip_whitespace();
            if scanner.peek() == Some(',') {
                scanner.advance();
                scanner.skip_whitespace();
                let currency = scanner.read_currency().map_err(|message| {
                    ParseError::new(
                        line_number,
                        scanner.column(),
                        message,
                        ParseErrorKind::InvalidCurrency,
                    )
                })?;
                currencies.push(currency);
                // T75 / L-78: counted as read — a 262,137-currency list stops
                // at the first currency past the cap.
                gate.check(
                    currencies.len(),
                    gate.limits.max_currencies,
                    "currencies in one open",
                    line_number,
                )?;
            } else {
                break;
            }
        }
    }

    // M-25. Note this is reached on both arms: an `open` with no currency list
    // at all took the `at_eol` branch above, which already proved the line is
    // finished, so the check is a no-op there rather than a second rule.
    reject_trailing_content(scanner, line_number, "an open directive")?;

    let metadata = parse_metadata_body(body_lines)?;

    Ok(Open {
        date,
        account,
        currencies,
        metadata,
    })
}

fn parse_close(
    scanner: &mut Scanner,
    date: NaiveDate,
    body_lines: &[(usize, &str)],
    line_number: usize,
) -> Result<Close, ParseError> {
    scanner.skip_whitespace();
    let account = scanner.read_account().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::InvalidAccountName,
        )
    })?;
    // M-25: `close Assets:Cash 2020-01-01` used to parse as `close Assets:Cash`.
    reject_trailing_content(scanner, line_number, "a close directive")?;
    let metadata = parse_metadata_body(body_lines)?;
    Ok(Close {
        date,
        account,
        metadata,
    })
}

fn parse_commodity(
    scanner: &mut Scanner,
    date: NaiveDate,
    body_lines: &[(usize, &str)],
    line_number: usize,
) -> Result<Commodity, ParseError> {
    scanner.skip_whitespace();
    let currency = scanner.read_currency().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::InvalidCurrency,
        )
    })?;
    reject_trailing_content(scanner, line_number, "a commodity directive")?; // M-25
    let metadata = parse_metadata_body(body_lines)?;
    Ok(Commodity {
        date,
        currency,
        metadata,
    })
}

fn parse_pad(
    scanner: &mut Scanner,
    date: NaiveDate,
    body_lines: &[(usize, &str)],
    line_number: usize,
) -> Result<Pad, ParseError> {
    scanner.skip_whitespace();
    let account = scanner.read_account().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::InvalidAccountName,
        )
    })?;
    scanner.skip_whitespace();
    let source_account = scanner.read_account().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::InvalidAccountName,
        )
    })?;
    reject_trailing_content(scanner, line_number, "a pad directive")?; // M-25
    let metadata = parse_metadata_body(body_lines)?;
    Ok(Pad {
        date,
        account,
        source_account,
        metadata,
    })
}

fn parse_balance(
    scanner: &mut Scanner,
    date: NaiveDate,
    body_lines: &[(usize, &str)],
    line_number: usize,
) -> Result<Balance, ParseError> {
    scanner.skip_whitespace();
    let account = scanner.read_account().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::InvalidAccountName,
        )
    })?;
    scanner.skip_whitespace();
    let amount = scanner.read_amount().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::InvalidNumber,
        )
    })?;
    reject_trailing_content(scanner, line_number, "a balance directive")?; // M-25
    let metadata = parse_metadata_body(body_lines)?;
    Ok(Balance {
        date,
        account,
        amount,
        metadata,
    })
}

fn parse_note(
    scanner: &mut Scanner,
    date: NaiveDate,
    body_lines: &[(usize, &str)],
    line_number: usize,
) -> Result<Note, ParseError> {
    scanner.skip_whitespace();
    let account = scanner.read_account().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::InvalidAccountName,
        )
    })?;
    scanner.skip_whitespace();
    let comment = scanner.read_quoted_string().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::UnterminatedString,
        )
    })?;
    reject_trailing_content(scanner, line_number, "a note directive")?; // M-25
    let metadata = parse_metadata_body(body_lines)?;
    Ok(Note {
        date,
        account,
        comment,
        metadata,
    })
}

fn parse_document(
    scanner: &mut Scanner,
    date: NaiveDate,
    body_lines: &[(usize, &str)],
    line_number: usize,
) -> Result<Document, ParseError> {
    scanner.skip_whitespace();
    let account = scanner.read_account().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::InvalidAccountName,
        )
    })?;
    scanner.skip_whitespace();
    let path = scanner.read_quoted_string().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::UnterminatedString,
        )
    })?;
    reject_trailing_content(scanner, line_number, "a document directive")?; // M-25
    let metadata = parse_metadata_body(body_lines)?;
    Ok(Document {
        date,
        account,
        path,
        metadata,
    })
}

fn parse_event(
    scanner: &mut Scanner,
    date: NaiveDate,
    body_lines: &[(usize, &str)],
    line_number: usize,
) -> Result<Event, ParseError> {
    scanner.skip_whitespace();
    let event_type = scanner.read_quoted_string().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::UnterminatedString,
        )
    })?;
    scanner.skip_whitespace();
    let description = scanner.read_quoted_string().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::UnterminatedString,
        )
    })?;
    reject_trailing_content(scanner, line_number, "an event directive")?; // M-25
    let metadata = parse_metadata_body(body_lines)?;
    Ok(Event {
        date,
        event_type,
        description,
        metadata,
    })
}

/// Parse a `price` DIRECTIVE: `DATE price CURRENCY AMOUNT` (§2.3).
///
/// ## Why a zero or negative number is tolerated here (T41, verified)
///
/// [`is_valid_cost_or_price_number`] is deliberately NOT applied to this
/// number, unlike the `{…}` cost and `@`/`@@` price *annotations* on a posting
/// that L-16 refuses. The two look alike and are not the same thing.
///
/// A posting annotation is an input to the balance identity: `posting_weight`
/// multiplies by it, so `{0 USD}` gives a weight of exactly zero whatever the
/// posting says, and `1 AAPL {0 USD}` balances against the same counter-posting
/// as `10_000_000 AAPL {0 USD}` — units minted at will with I1 perfectly
/// satisfied. That is why L-16 refuses it, and refuses it fail-closed.
///
/// A `price` directive has no such path. Verified by inspection of every
/// consumer of `Directive::Price`: the parser builds it, the serializer writes
/// it back (so it round-trips and is covered by the content hash), and
/// `DirectiveKind::Price` labels it on the wire. Nothing else reads
/// `Price::amount` — not `weights`, not `validate`, not `read_model`, not
/// `checkpoint`. It is inert reference data: it contributes no weight, converts
/// nothing, and cannot move a balance or a balance assertion.
///
/// So the L-16 argument does not transfer, and applying the rule anyway would
/// cost something real: a previously-persisted file carrying
/// `2024-01-01 price AAPL 0.00 USD` would fail boot, fail-closed, over a number
/// that cannot affect any computed value. A zero or negative quotation is also
/// not obviously wrong as *data* — a delisted or written-off instrument is a
/// real thing to record.
///
/// If `Price::amount` ever becomes an input to conversion or reporting, this
/// stops being true and the rule must be applied here at the same time.
fn parse_price(
    scanner: &mut Scanner,
    date: NaiveDate,
    body_lines: &[(usize, &str)],
    line_number: usize,
) -> Result<Price, ParseError> {
    scanner.skip_whitespace();
    let currency = scanner.read_currency().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::InvalidCurrency,
        )
    })?;
    scanner.skip_whitespace();
    let amount = scanner.read_amount().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::InvalidNumber,
        )
    })?;
    reject_trailing_content(scanner, line_number, "a price directive")?; // M-25
    let metadata = parse_metadata_body(body_lines)?;
    Ok(Price {
        date,
        currency,
        amount,
        metadata,
    })
}

// ─── Body line helpers ───────────────────────────────────────────────────────

/// Parse body lines for a transaction: split into directive-level metadata and postings.
fn parse_transaction_body(
    body_lines: &[(usize, &str)],
    gate: &mut LimitGate,
) -> Result<(Metadata, Vec<Posting>), ParseError> {
    let mut metadata = BTreeMap::new();
    let mut postings = Vec::new();
    let mut current_posting: Option<Posting> = None;
    // T75: every count is checked as it grows, so the parse stops at the first
    // item past a cap. Postings count the one being read (`current_posting`),
    // metadata counts DISTINCT keys — what the map, and so
    // `enforce_resource_limits`, will hold.
    let mut posting_count = 0usize;
    let mut posting_metadata_keys = 0usize;

    for &(line_number, line) in body_lines {
        let trimmed = line.trim();
        if is_metadata_line(trimmed) {
            let (key, value) = parse_metadata_line(trimmed, line_number)?;
            if let Some(ref mut posting) = current_posting {
                if posting.metadata.insert(key, value).is_none() {
                    posting_metadata_keys += 1;
                }
                gate.check(
                    posting_metadata_keys,
                    gate.limits.max_posting_metadata_keys,
                    "posting metadata keys in one transaction",
                    line_number,
                )?;
            } else {
                metadata.insert(key, value);
                gate.check(
                    metadata.len(),
                    gate.limits.max_metadata_keys,
                    "metadata keys",
                    line_number,
                )?;
            }
        } else {
            posting_count += 1;
            gate.check(
                posting_count,
                gate.limits.max_postings,
                "postings",
                line_number,
            )?;
            // Finish previous posting if any.
            if let Some(posting) = current_posting.take() {
                postings.push(posting);
            }
            // Parse new posting line.
            let posting = parse_posting_line(trimmed, line_number)?;
            current_posting = Some(posting);
        }
    }

    // Don't forget the last posting.
    if let Some(posting) = current_posting {
        postings.push(posting);
    }

    Ok((metadata, postings))
}

/// Parse body lines that should only contain metadata (for non-transaction directives).
fn parse_metadata_body(body_lines: &[(usize, &str)]) -> Result<Metadata, ParseError> {
    let mut metadata = BTreeMap::new();
    for &(line_number, line) in body_lines {
        let trimmed = line.trim();
        if is_metadata_line(trimmed) {
            let (key, value) = parse_metadata_line(trimmed, line_number)?;
            metadata.insert(key, value);
        } else {
            return Err(ParseError::new(
                line_number,
                1,
                "Expected metadata line for this directive, got posting-like content",
                ParseErrorKind::BadStructure,
            ));
        }
    }
    Ok(metadata)
}

/// Check if a trimmed line looks like metadata (`key: value`).
fn is_metadata_line(trimmed: &str) -> bool {
    // Metadata keys start with a lowercase letter and contain a colon.
    if let Some(first_character) = trimmed.chars().next() {
        first_character.is_ascii_lowercase() && trimmed.contains(':')
    } else {
        false
    }
}

/// Parse a metadata line like `key: "value"`.
fn parse_metadata_line(trimmed: &str, line_number: usize) -> Result<(String, String), ParseError> {
    let mut scanner = Scanner::new(trimmed);

    // Read key. `read_word` consumes Unicode alphanumerics and the charset is
    // checked afterwards, exactly as the L-25 token readers do — stopping the
    // scan at the offending character would truncate `nаrration` to `n` and
    // surface an unrelated complaint about the rest of the line (T41).
    let key = scanner.read_word();
    if key.is_empty() {
        return Err(ParseError::new(
            line_number,
            1,
            "Expected metadata key",
            ParseErrorKind::UnexpectedToken,
        ));
    }
    if let Err(message) =
        scanner.reject_disallowed_character(&key, 0, "metadata key", |character| {
            is_label_character(character)
        })
    {
        return Err(ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::InvalidMetadataKey,
        ));
    }
    validate_metadata_key(&key).map_err(|message| {
        ParseError::new(line_number, 1, message, ParseErrorKind::InvalidMetadataKey)
    })?;

    // Expect colon.
    scanner.skip_whitespace();
    match scanner.advance() {
        Some(':') => {}
        _ => {
            return Err(ParseError::new(
                line_number,
                scanner.column(),
                "Expected ':' after metadata key",
                ParseErrorKind::UnexpectedToken,
            ))
        }
    }

    scanner.skip_whitespace();

    // Value must be a quoted string (§3.3.2: strings only).
    if scanner.peek() != Some('"') {
        return Err(ParseError::new(
            line_number,
            scanner.column(),
            "Metadata values must be quoted strings",
            ParseErrorKind::InvalidMetadataValue,
        ));
    }

    let value = scanner.read_quoted_string().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::UnterminatedString,
        )
    })?;

    reject_trailing_content(&scanner, line_number, "a metadata value")?; // M-25

    Ok((key, value))
}

/// Parse a single posting line (already trimmed).
fn parse_posting_line(trimmed: &str, line_number: usize) -> Result<Posting, ParseError> {
    let mut scanner = Scanner::new(trimmed);

    // Read account name.
    let account = scanner.read_account().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::InvalidAccountName,
        )
    })?;

    scanner.skip_whitespace();

    // Remaining content is optional: amount [cost] [price].
    if scanner.at_eol() {
        // Elided posting (I2).
        return Ok(Posting {
            account,
            amount: None,
            cost: None,
            price: None,
            metadata: BTreeMap::new(),
        });
    }

    // Read amount.
    let amount = scanner
        .read_summed_amount("posting amount")
        .map_err(|message| {
            ParseError::new(
                line_number,
                scanner.column(),
                message,
                ParseErrorKind::InvalidNumber,
            )
        })?;

    scanner.skip_whitespace();

    // Optional cost: `{...}`.
    let cost = if scanner.peek() == Some('{') {
        Some(parse_cost_spec(&mut scanner, line_number)?)
    } else {
        None
    };

    scanner.skip_whitespace();

    // Optional price: `@ ...` or `@@ ...`.
    let price = if scanner.peek() == Some('@') {
        Some(parse_price_spec(&mut scanner, line_number)?)
    } else {
        None
    };

    // M-25. The elided-posting arm above already returned on `at_eol`, so this
    // is the only exit that could have carried junk — and it is the one that
    // mattered most: `Assets:Cash 1 USD this is dropped` was adopted as a plain
    // `Assets:Cash 1 USD` with no trace of what went missing.
    reject_trailing_content(&scanner, line_number, "a posting")?;

    Ok(Posting {
        account,
        amount: Some(amount),
        cost,
        price,
        metadata: BTreeMap::new(),
    })
}

/// Parse a cost specification: `{[AMOUNT [, DATE]]}`.
fn parse_cost_spec(scanner: &mut Scanner, line_number: usize) -> Result<CostSpec, ParseError> {
    // Consume opening `{`.
    scanner.advance();
    scanner.skip_whitespace();

    // Empty cost `{}`.
    if scanner.peek() == Some('}') {
        scanner.advance();
        return Ok(CostSpec {
            amount: None,
            date: None,
        });
    }

    // Read cost amount.
    let amount = scanner.read_summed_amount("cost").map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::InvalidNumber,
        )
    })?;

    // L-16: refuse a zero/negative cost here, on the file path, so it cannot
    // reach the DAG at boot — boot deliberately applies no transaction-level
    // validation, so the weight-computation check never runs on it.
    if !is_valid_cost_or_price_number(amount.number) {
        return Err(ParseError::new(
            line_number,
            scanner.column(),
            format!(
                "Cost must be greater than zero, got {} {}",
                amount.number, amount.currency
            ),
            ParseErrorKind::InvalidNumber,
        ));
    }

    scanner.skip_whitespace();

    // Optional date after comma.
    let date = if scanner.peek() == Some(',') {
        scanner.advance();
        scanner.skip_whitespace();
        let cost_date = scanner.read_date().map_err(|message| {
            ParseError::new(
                line_number,
                scanner.column(),
                message,
                ParseErrorKind::InvalidDate,
            )
        })?;
        scanner.skip_whitespace();
        Some(cost_date)
    } else {
        None
    };

    // Consume closing `}`.
    match scanner.advance() {
        Some('}') => {}
        _ => {
            return Err(ParseError::new(
                line_number,
                scanner.column(),
                "Expected '}' to close cost specification",
                ParseErrorKind::UnexpectedToken,
            ))
        }
    }

    Ok(CostSpec {
        amount: Some(amount),
        date,
    })
}

/// Parse a price annotation: `@ AMOUNT` or `@@ AMOUNT`.
fn parse_price_spec(scanner: &mut Scanner, line_number: usize) -> Result<PriceSpec, ParseError> {
    // Consume `@`.
    scanner.advance();

    let is_total = scanner.peek() == Some('@');
    if is_total {
        scanner.advance();
    }

    scanner.skip_whitespace();

    let amount = scanner.read_summed_amount("price").map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::InvalidNumber,
        )
    })?;

    // L-16, as in `parse_cost_spec`. `@@` matters most: `price_weight`'s total
    // arm re-signs the absolute value from the posting, so `@@ -110 USD` and
    // `@@ 110 USD` weigh the same but serialize — and hash — differently.
    if !is_valid_cost_or_price_number(amount.number) {
        return Err(ParseError::new(
            line_number,
            scanner.column(),
            format!(
                "{} must be greater than zero, got {} {}",
                if is_total { "Total price" } else { "Price" },
                amount.number,
                amount.currency
            ),
            ParseErrorKind::InvalidNumber,
        ));
    }

    if is_total {
        Ok(PriceSpec::Total(amount))
    } else {
        Ok(PriceSpec::Unit(amount))
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    #[test]
    fn test_parse_empty_file() {
        let result = parse_file("").unwrap();
        assert!(result.is_empty());
    }

    // ── L-28: UTF-8 byte-order mark ──────────────────────────────────────

    /// The sample every BOM test below works from: a comment, an open, and a
    /// transaction, i.e. all three things that can start a `.bean` file.
    fn bom_sample_file() -> &'static str {
        "; ledger\n\
         2024-01-01 open Assets:Cash USD\n\
         \n\
         2024-01-01 open Equity:Opening\n\
         \n\
         2024-01-15 * \"Acme\" \"Funding\"\n\
         \x20 Assets:Cash                                      100.00 USD\n\
         \x20 Equity:Opening                                   -100.00 USD\n"
    }

    #[test]
    fn test_bom_prefixed_file_parses_to_identical_directives() {
        let plain = parse_file(bom_sample_file()).expect("the plain file parses");
        let with_mark = parse_file(&format!("\u{FEFF}{}", bom_sample_file()))
            .expect("L-28: a leading BOM must not fail the parse");

        assert_eq!(
            plain.len(),
            with_mark.len(),
            "L-28: a BOM must not change how many directives a file holds"
        );
        let plain_ids: Vec<String> = plain.iter().map(crate::hash::compute_content_id).collect();
        let marked_ids: Vec<String> = with_mark
            .iter()
            .map(crate::hash::compute_content_id)
            .collect();
        assert_eq!(
            plain_ids, marked_ids,
            "L-28: a BOM must not change any content id"
        );
    }

    #[test]
    fn test_byte_order_mark_bytes_are_ef_bb_bf() {
        // Guard the constant against a future edit that swaps in some other
        // zero-width character: the finding is specifically about EF BB BF.
        let mut encoded = [0u8; 4];
        let encoded = BYTE_ORDER_MARK.encode_utf8(&mut encoded);
        assert_eq!(encoded.as_bytes(), [0xEF, 0xBB, 0xBF]);
    }

    #[test]
    fn test_only_one_byte_order_mark_is_stripped() {
        // Exactly one mark is an encoding artefact. A second one is a genuine
        // zero-width no-break space in the content and must stay an error, so
        // this cannot be used to smuggle invisible characters past the parser.
        let doubled = format!("\u{FEFF}\u{FEFF}{}", bom_sample_file());
        assert!(
            parse_file(&doubled).is_err(),
            "L-28: only the first BOM is an encoding artefact"
        );
        assert_eq!(
            strip_byte_order_mark(&doubled),
            format!("\u{FEFF}{}", bom_sample_file()),
            "strip removes exactly one mark"
        );
    }

    #[test]
    fn test_strip_byte_order_mark_leaves_other_content_alone() {
        assert_eq!(strip_byte_order_mark(""), "");
        assert_eq!(
            strip_byte_order_mark("2024-01-01 open Assets:Cash\n"),
            "2024-01-01 open Assets:Cash\n"
        );
        // A BOM that is not leading is content, not an encoding artefact.
        assert_eq!(
            strip_byte_order_mark("2024-01-01 open A\u{FEFF}ssets:Cash\n"),
            "2024-01-01 open A\u{FEFF}ssets:Cash\n"
        );
    }

    #[test]
    fn test_parse_comment_only_file() {
        let result = parse_file("; This is a comment\n; Another comment\n").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_parse_open_simple() {
        let input = "2024-01-01 open Assets:Cash\n";
        let directives = parse_file(input).unwrap();
        assert_eq!(directives.len(), 1);
        match &directives[0] {
            Directive::Open(open) => {
                assert_eq!(open.date, NaiveDate::from_ymd_opt(2024, 1, 1).unwrap());
                assert_eq!(open.account, "Assets:Cash");
                assert!(open.currencies.is_empty());
            }
            other => panic!("Expected Open, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_open_with_currencies() {
        let input = "2024-01-01 open Assets:Bank USD, EUR\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Open(open) => {
                assert_eq!(open.currencies, vec!["USD", "EUR"]);
            }
            other => panic!("Expected Open, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_close() {
        let input = "2024-12-31 close Expenses:Food\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Close(close) => {
                assert_eq!(close.account, "Expenses:Food");
            }
            other => panic!("Expected Close, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_commodity() {
        let input = "2024-01-01 commodity USD\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Commodity(commodity) => {
                assert_eq!(commodity.currency, "USD");
            }
            other => panic!("Expected Commodity, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_balance() {
        let input = "2024-02-01 balance Assets:Cash 1000.00 USD\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Balance(balance) => {
                assert_eq!(balance.account, "Assets:Cash");
                assert_eq!(balance.amount.number, dec!(1000.00));
                assert_eq!(balance.amount.currency, "USD");
            }
            other => panic!("Expected Balance, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_pad() {
        let input = "2024-01-01 pad Assets:Cash Equity:Opening\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Pad(pad) => {
                assert_eq!(pad.account, "Assets:Cash");
                assert_eq!(pad.source_account, "Equity:Opening");
            }
            other => panic!("Expected Pad, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_note() {
        let input = "2024-01-01 note Assets:Cash \"Account opened\"\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Note(note) => {
                assert_eq!(note.account, "Assets:Cash");
                assert_eq!(note.comment, "Account opened");
            }
            other => panic!("Expected Note, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_document() {
        let input = "2024-01-01 document Assets:Cash \"/docs/statement.pdf\"\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Document(document) => {
                assert_eq!(document.path, "/docs/statement.pdf");
            }
            other => panic!("Expected Document, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_event() {
        let input = "2024-01-01 event \"location\" \"New York\"\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Event(event) => {
                assert_eq!(event.event_type, "location");
                assert_eq!(event.description, "New York");
            }
            other => panic!("Expected Event, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_price() {
        let input = "2024-01-01 price EUR 1.10 USD\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Price(price) => {
                assert_eq!(price.currency, "EUR");
                assert_eq!(price.amount.number, dec!(1.10));
                assert_eq!(price.amount.currency, "USD");
            }
            other => panic!("Expected Price, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_simple_transaction() {
        let input = "\
2024-01-15 * \"Grocery Store\" \"Weekly shopping\"
  Expenses:Food                                    50.00 USD
  Assets:Cash                                     -50.00 USD
";
        let directives = parse_file(input).unwrap();
        assert_eq!(directives.len(), 1);
        match &directives[0] {
            Directive::Transaction(txn) => {
                assert_eq!(txn.date, NaiveDate::from_ymd_opt(2024, 1, 15).unwrap());
                assert_eq!(txn.flag, Flag::Complete);
                assert_eq!(txn.payee.as_deref(), Some("Grocery Store"));
                assert_eq!(txn.narration.as_deref(), Some("Weekly shopping"));
                assert_eq!(txn.postings.len(), 2);
                assert_eq!(txn.postings[0].account, "Expenses:Food");
                assert_eq!(txn.postings[0].amount.as_ref().unwrap().number, dec!(50.00));
                assert_eq!(
                    txn.postings[1].amount.as_ref().unwrap().number,
                    dec!(-50.00)
                );
            }
            other => panic!("Expected Transaction, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_transaction_narration_only() {
        let input = "2024-01-15 * \"Just narration\"\n  Assets:Cash 100.00 USD\n  Equity:Opening\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Transaction(txn) => {
                assert!(txn.payee.is_none());
                assert_eq!(txn.narration.as_deref(), Some("Just narration"));
            }
            other => panic!("Expected Transaction, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_transaction_no_strings() {
        let input = "2024-01-15 *\n  Assets:Cash 100.00 USD\n  Equity:Opening -100.00 USD\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Transaction(txn) => {
                assert!(txn.payee.is_none());
                assert!(txn.narration.is_none());
            }
            other => panic!("Expected Transaction, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_transaction_with_tags_and_links() {
        let input =
            "2024-01-15 * \"Shopping\" #groceries #weekly ^receipt-001\n  Assets:Cash -50.00 USD\n  Expenses:Food 50.00 USD\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Transaction(txn) => {
                assert_eq!(txn.tags, vec!["groceries", "weekly"]);
                assert_eq!(txn.links, vec!["receipt-001"]);
            }
            other => panic!("Expected Transaction, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_transaction_incomplete_flag() {
        let input = "2024-01-15 ! \"Pending\"\n  Assets:Cash 100.00 USD\n  Equity:Opening\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Transaction(txn) => {
                assert_eq!(txn.flag, Flag::Incomplete);
            }
            other => panic!("Expected Transaction, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_transaction_txn_keyword() {
        let input = "2024-01-15 txn \"Using txn keyword\"\n  Assets:Cash 100.00 USD\n  Equity:Opening -100.00 USD\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Transaction(txn) => {
                assert_eq!(txn.flag, Flag::Complete); // txn defaults to *
                assert_eq!(txn.narration.as_deref(), Some("Using txn keyword"));
            }
            other => panic!("Expected Transaction, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_elided_posting() {
        let input = "2024-01-15 * \"Test\"\n  Assets:Cash 100.00 USD\n  Equity:Opening\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Transaction(txn) => {
                assert!(txn.postings[0].amount.is_some());
                assert!(txn.postings[1].amount.is_none()); // elided
            }
            other => panic!("Expected Transaction, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_posting_with_cost() {
        let input =
            "2024-01-15 *\n  Assets:Stock 10 AAPL {150.00 USD}\n  Assets:Cash -1500.00 USD\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Transaction(txn) => {
                let posting = &txn.postings[0];
                assert!(posting.cost.is_some());
                let cost = posting.cost.as_ref().unwrap();
                assert_eq!(cost.amount.as_ref().unwrap().number, dec!(150.00));
                assert_eq!(cost.amount.as_ref().unwrap().currency, "USD");
                assert!(cost.date.is_none());
            }
            other => panic!("Expected Transaction, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_posting_with_cost_and_date() {
        let input =
            "2024-06-15 *\n  Assets:Stock 10 AAPL {150.00 USD, 2024-01-01}\n  Assets:Cash -1500.00 USD\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Transaction(txn) => {
                let cost = txn.postings[0].cost.as_ref().unwrap();
                assert_eq!(
                    cost.date,
                    Some(NaiveDate::from_ymd_opt(2024, 1, 1).unwrap())
                );
            }
            other => panic!("Expected Transaction, got {other:?}"),
        }
    }

    // ── L-16: non-positive cost/price numbers on the file path ───────────

    #[test]
    fn test_parse_rejects_non_positive_cost_and_price() {
        // The file path is the one ingress `validate_transaction` does not
        // guard: boot deliberately applies no transaction-level validation, so
        // without this a hand-edited or pre-hardening `{0 USD}` would load into
        // the DAG and be served to every peer.
        for (annotation, expected) in [
            ("{0 USD}", "Cost must be greater than zero"),
            ("{0.00 USD}", "Cost must be greater than zero"),
            ("{-150.00 USD}", "Cost must be greater than zero"),
            ("@ 0 USD", "Price must be greater than zero"),
            ("@ -1.10 USD", "Price must be greater than zero"),
            ("@@ 0 USD", "Total price must be greater than zero"),
            ("@@ -110 USD", "Total price must be greater than zero"),
        ] {
            let input = format!(
                "2024-01-15 *\n  Assets:Stock 10 AAPL {annotation}\n  Assets:Cash -1500.00 USD\n"
            );
            let errors = parse_file(&input).expect_err(&format!("{annotation} must be refused"));
            assert!(
                errors.iter().any(
                    |e| e.kind == ParseErrorKind::InvalidNumber && e.message.contains(expected)
                ),
                "{annotation}: expected {expected:?}, got {errors:?}"
            );
        }
    }

    #[test]
    fn test_parse_still_accepts_positive_cost_and_price() {
        // No over-rejection, including the empty `{}` that carries no number.
        for annotation in [
            "{150.00 USD}",
            "{0.0000000001 USD}",
            "{}",
            "@ 1.10 USD",
            "@@ 110 USD",
        ] {
            let input = format!(
                "2024-01-15 *\n  Assets:Stock 10 AAPL {annotation}\n  Assets:Cash -1500.00 USD\n"
            );
            assert!(
                parse_file(&input).is_ok(),
                "{annotation} must still parse: {:?}",
                parse_file(&input).err()
            );
        }
    }

    #[test]
    fn test_parse_posting_with_unit_price() {
        let input =
            "2024-01-15 *\n  Assets:Foreign 100.00 EUR @ 1.10 USD\n  Assets:Cash -110.00 USD\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Transaction(txn) => {
                let price = txn.postings[0].price.as_ref().unwrap();
                match price {
                    PriceSpec::Unit(amount) => {
                        assert_eq!(amount.number, dec!(1.10));
                        assert_eq!(amount.currency, "USD");
                    }
                    other => panic!("Expected Unit price, got {other:?}"),
                }
            }
            other => panic!("Expected Transaction, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_posting_with_total_price() {
        let input =
            "2024-01-15 *\n  Assets:Foreign 100.00 EUR @@ 110.00 USD\n  Assets:Cash -110.00 USD\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Transaction(txn) => {
                let price = txn.postings[0].price.as_ref().unwrap();
                match price {
                    PriceSpec::Total(amount) => {
                        assert_eq!(amount.number, dec!(110.00));
                    }
                    other => panic!("Expected Total price, got {other:?}"),
                }
            }
            other => panic!("Expected Transaction, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_transaction_metadata() {
        let input = "\
2024-01-15 * \"Test\"
  openledger-author: \"local-peer\"
  openledger-parents: \"\"
  openledger-lamport: \"1\"
  Assets:Cash 100.00 USD
  Equity:Opening -100.00 USD
";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Transaction(txn) => {
                assert_eq!(txn.author(), Some("local-peer"));
                assert!(txn.parent_ids().is_empty());
                assert_eq!(txn.lamport_clock(), Some(1));
            }
            other => panic!("Expected Transaction, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_posting_metadata() {
        let input = "\
2024-01-15 * \"Test\"
  Assets:Cash 100.00 USD
    category: \"revenue\"
  Equity:Opening -100.00 USD
";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Transaction(txn) => {
                assert_eq!(txn.postings[0].metadata.get("category").unwrap(), "revenue");
            }
            other => panic!("Expected Transaction, got {other:?}"),
        }
    }

    #[test]
    fn test_unsupported_directive_option() {
        let input = "2024-01-01 option \"title\" \"My Ledger\"\n";
        let errors = parse_file(input).unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].kind, ParseErrorKind::UnsupportedDirective);
        assert!(errors[0].message.contains("option"));
    }

    #[test]
    fn test_unsupported_directive_include() {
        let input = "2024-01-01 include \"other.bean\"\n";
        let errors = parse_file(input).unwrap_err();
        assert_eq!(errors[0].kind, ParseErrorKind::UnsupportedDirective);
    }

    #[test]
    fn test_unsupported_directive_plugin() {
        let input = "2024-01-01 plugin \"beancount.plugins.auto_accounts\"\n";
        let errors = parse_file(input).unwrap_err();
        assert_eq!(errors[0].kind, ParseErrorKind::UnsupportedDirective);
    }

    #[test]
    fn test_unsupported_directive_custom() {
        let input = "2024-01-01 custom \"budget\" \"1000 USD\"\n";
        let errors = parse_file(input).unwrap_err();
        assert_eq!(errors[0].kind, ParseErrorKind::UnsupportedDirective);
    }

    #[test]
    fn test_invalid_date() {
        let input = "2024-13-01 open Assets:Cash\n";
        let errors = parse_file(input).unwrap_err();
        assert_eq!(errors[0].kind, ParseErrorKind::InvalidDate);
    }

    #[test]
    fn test_invalid_account_root() {
        let input = "2024-01-01 open Foo:Cash\n";
        let errors = parse_file(input).unwrap_err();
        assert_eq!(errors[0].kind, ParseErrorKind::InvalidAccountName);
    }

    #[test]
    fn test_invalid_account_lowercase_segment() {
        let input = "2024-01-01 open Assets:cash\n";
        let errors = parse_file(input).unwrap_err();
        assert_eq!(errors[0].kind, ParseErrorKind::InvalidAccountName);
    }

    // ── L-25: confusable (mixed-script) names are a normal parse error ────
    //
    // `char::is_alphanumeric` is Unicode-aware, so the parser used to accept
    // `Assets:Cаsh` (Cyrillic а, U+0430) as an account distinct from — and
    // pixel-identical to — `Assets:Cash`, and it never charset-checked tags or
    // links at all. The API-side validators were always ASCII; these pin the
    // parser to the same rule, as ordinary per-line errors with a location.

    #[test]
    fn test_mixed_script_account_rejected_on_directive_header() {
        // `2024-01-01 open Assets:Cаsh` — the Cyrillic а is char index 24.
        let input = "2024-01-01 open Assets:C\u{0430}sh\n";
        let errors = parse_file(input).unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].kind, ParseErrorKind::InvalidAccountName);
        assert_eq!(errors[0].line, 1);
        assert_eq!(
            errors[0].column, 25,
            "column must point at the offending character, not the end of the token"
        );
        assert!(
            errors[0].message.contains('\u{0430}') && errors[0].message.contains("U+0430"),
            "message must name the offending character: {}",
            errors[0].message
        );
        // Not a panic, and not a silently-accepted second account.
        assert!(errors[0].message.contains("ASCII-only"));
    }

    #[test]
    fn test_mixed_script_account_rejected_on_posting_line() {
        let input = "2024-01-15 * \"Shop\" \"Groceries\"\n  \
                     Assets:C\u{0430}sh -50.00 USD\n  \
                     Expenses:Food 50.00 USD\n";
        let errors = parse_file(input).unwrap_err();
        assert_eq!(errors[0].kind, ParseErrorKind::InvalidAccountName);
        assert_eq!(errors[0].line, 2);
        // Posting lines are scanned after trimming (pre-existing behaviour), so
        // the column is relative to the first non-blank character.
        assert_eq!(errors[0].column, 9);
        assert!(errors[0].message.contains("U+0430"));
    }

    #[test]
    fn test_mixed_script_tag_rejected() {
        // `#grоceries` with a Cyrillic о (U+043E) at char index 23.
        let input = "2024-01-15 * \"Shop\" #gr\u{043E}ceries\n  \
                     Assets:Cash -50.00 USD\n  Expenses:Food 50.00 USD\n";
        let errors = parse_file(input).unwrap_err();
        assert_eq!(errors[0].kind, ParseErrorKind::InvalidTag);
        assert_eq!(errors[0].line, 1);
        assert_eq!(errors[0].column, 24);
        assert!(
            errors[0].message.contains("U+043E") && errors[0].message.contains("tag"),
            "message: {}",
            errors[0].message
        );
    }

    #[test]
    fn test_mixed_script_link_rejected() {
        // `^rеceipt` with a Cyrillic е (U+0435) at char index 22.
        let input = "2024-01-15 * \"Shop\" ^r\u{0435}ceipt\n  \
                     Assets:Cash -50.00 USD\n  Expenses:Food 50.00 USD\n";
        let errors = parse_file(input).unwrap_err();
        assert_eq!(errors[0].kind, ParseErrorKind::InvalidLink);
        assert_eq!(errors[0].line, 1);
        assert_eq!(errors[0].column, 23);
        assert!(
            errors[0].message.contains("U+0435") && errors[0].message.contains("link"),
            "message: {}",
            errors[0].message
        );
    }

    #[test]
    fn test_confusable_and_lookalike_account_spellings_all_rejected() {
        // Every shape `is_alphanumeric` used to wave through: Cyrillic,
        // fullwidth Latin, fullwidth digits, Greek, and accented Latin.
        for account in [
            "Assets:C\u{0430}sh",  // Cyrillic а
            "Assets:Ca\u{FF53}h",  // fullwidth s
            "Assets:Cash\u{FF11}", // fullwidth 1
            "Assets:C\u{03B1}sh",  // Greek alpha
            "Assets:Caf\u{00E9}",  // é
        ] {
            let input = format!("2024-01-01 open {account}\n");
            let errors = parse_file(&input).unwrap_err();
            assert_eq!(
                errors[0].kind,
                ParseErrorKind::InvalidAccountName,
                "{account} must be rejected, got {:?}",
                errors[0]
            );
        }
    }

    #[test]
    fn test_ascii_account_tag_and_link_still_parse() {
        // The control: the tightened readers must not touch legal ASCII names,
        // including digits, hyphens and underscores.
        let input = "2024-01-15 * \"Shop\" #gro-ceries_2024 ^receipt-001\n  \
                     Assets:Cash-2 -50.00 USD\n  Expenses:Food 50.00 USD\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Transaction(txn) => {
                assert_eq!(txn.tags, vec!["gro-ceries_2024"]);
                assert_eq!(txn.links, vec!["receipt-001"]);
                assert_eq!(txn.postings[0].account, "Assets:Cash-2");
            }
            other => panic!("Expected Transaction, got {other:?}"),
        }
    }

    #[test]
    fn test_ascii_golden_fixture_content_ids_are_unchanged() {
        // L-25 compatibility pin: restricting the charset must leave every
        // existing ASCII ledger identical, ids included. The fixture covers all
        // ten directive types plus an ASCII tag (`#setup`) and link
        // (`^opening-001`), which the tightened readers now validate.
        let fixture = include_str!("../../../testfixtures/fixture-simple.bean");
        let directives = parse_file(fixture).unwrap();
        assert_eq!(directives.len(), 16);

        let joined = directives
            .iter()
            .map(crate::hash::compute_content_id)
            .collect::<Vec<_>>()
            .join("\n");
        use sha2::Digest;
        let digest: String = sha2::Sha256::digest(joined.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            digest, "1ca0e9fdd90a3d89f62c54fc83ed0e9046ae7d412195f63758e6da50dfdb77d0",
            "the golden fixture's 16 content ids must not move"
        );
    }

    #[test]
    fn test_invalid_metadata_non_string() {
        let input = "2024-01-01 open Assets:Cash\n  category: 42\n";
        let errors = parse_file(input).unwrap_err();
        assert_eq!(errors[0].kind, ParseErrorKind::InvalidMetadataValue);
    }

    // ── T41: the L-25 charset rule, extended to metadata KEYS ────────────
    //
    // `read_word` is Unicode-aware too, so `nаrration:` (Cyrillic а) was a
    // distinct metadata key — and metadata keys are serialized into the body,
    // so they are hashed into the content id and are what the H-06
    // `openledger-` prefix check reads.

    #[test]
    fn test_mixed_script_metadata_key_rejected() {
        // `nаrration` with a Cyrillic а (U+0430) at char index 1 of the key.
        let input = "2024-01-01 open Assets:Cash\n  n\u{0430}rration: \"hi\"\n";
        let errors = parse_file(input).unwrap_err();
        assert_eq!(errors[0].kind, ParseErrorKind::InvalidMetadataKey);
        assert_eq!(errors[0].line, 2);
        assert!(
            errors[0].message.contains("U+0430") && errors[0].message.contains("metadata key"),
            "message must name the character and the field: {}",
            errors[0].message
        );
        assert!(errors[0].message.contains("ASCII-only"));
    }

    #[test]
    fn test_confusable_metadata_keys_all_rejected() {
        for key in [
            "n\u{0430}rration", // Cyrillic а
            "categ\u{03BF}ry",  // Greek omicron
            "inv\u{FF4F}ice",   // fullwidth o
            "caf\u{00E9}",      // é
        ] {
            let input = format!("2024-01-01 open Assets:Cash\n  {key}: \"x\"\n");
            let errors = parse_file(&input).unwrap_err();
            assert_eq!(
                errors[0].kind,
                ParseErrorKind::InvalidMetadataKey,
                "{key} must be rejected, got {:?}",
                errors[0]
            );
        }
    }

    #[test]
    fn test_ascii_metadata_keys_still_parse() {
        // The control: legal ASCII keys — including digits, hyphens and
        // underscores, and the `openledger-` envelope prefix — are untouched.
        let input = "2024-01-01 open Assets:Cash\n  \
                     category: \"ops\"\n  \
                     ref-2024_a: \"x\"\n  \
                     openledger-author: \"peer-1\"\n";
        let directives = parse_file(input).unwrap();
        let metadata = directives[0].metadata();
        assert_eq!(metadata.get("category").map(String::as_str), Some("ops"));
        assert_eq!(metadata.get("ref-2024_a").map(String::as_str), Some("x"));
        assert_eq!(
            metadata.get("openledger-author").map(String::as_str),
            Some("peer-1")
        );
    }

    #[test]
    fn test_validate_metadata_key_rules() {
        assert!(validate_metadata_key("narration").is_ok());
        assert!(validate_metadata_key("openledger-lamport").is_ok());
        assert!(validate_metadata_key("a_1-b").is_ok());
        assert!(validate_metadata_key("").is_err());
        assert!(validate_metadata_key("Narration").is_err());
        assert!(validate_metadata_key("1narration").is_err());
        assert!(validate_metadata_key("n\u{0430}rration").is_err());
    }

    #[test]
    fn test_parse_multi_directive_file() {
        let input = "\
2024-01-01 open Assets:Cash USD
2024-01-01 open Expenses:Food USD
2024-01-01 open Equity:Opening USD

2024-01-15 * \"Store\" \"Groceries\"
  Expenses:Food 50.00 USD
  Assets:Cash -50.00 USD

2024-02-01 balance Assets:Cash -50.00 USD

2024-12-31 close Expenses:Food
";
        let directives = parse_file(input).unwrap();
        assert_eq!(directives.len(), 6);
        assert!(matches!(directives[0], Directive::Open(_)));
        assert!(matches!(directives[1], Directive::Open(_)));
        assert!(matches!(directives[2], Directive::Open(_)));
        assert!(matches!(directives[3], Directive::Transaction(_)));
        assert!(matches!(directives[4], Directive::Balance(_)));
        assert!(matches!(directives[5], Directive::Close(_)));
    }

    #[test]
    fn test_parse_open_with_metadata() {
        let input = "2024-01-01 open Assets:Cash USD\n  description: \"Main cash account\"\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Open(open) => {
                assert_eq!(
                    open.metadata.get("description").unwrap(),
                    "Main cash account"
                );
            }
            other => panic!("Expected Open, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_negative_balance() {
        let input = "2024-02-01 balance Assets:Cash -500.25 USD\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Balance(balance) => {
                assert_eq!(balance.amount.number, dec!(-500.25));
            }
            other => panic!("Expected Balance, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_comma_separated_number() {
        let input = "2024-02-01 balance Assets:Cash 1,000,000.00 USD\n";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Balance(balance) => {
                assert_eq!(balance.amount.number, dec!(1000000.00));
            }
            other => panic!("Expected Balance, got {other:?}"),
        }
    }

    /// H-17 / T76: the amount reader refuses a summed amount past the
    /// magnitude cap (`|amount| ≤ 10^21`), with an error that names it,
    /// wherever in a transaction the amount sits — this reader is the gate on
    /// the wire and at boot, where nothing else checks history.
    #[test]
    fn test_parse_refuses_an_amount_over_the_cap() {
        for over in ["1000000000000000000001", "1000000000000000000000.0000001"] {
            for (what, input) in [
                (
                    "posting",
                    format!("2024-01-15 *\n  Assets:Cash {over} USD\n  Equity:Opening -1 USD\n"),
                ),
                (
                    "negative posting",
                    format!("2024-01-15 *\n  Assets:Cash 1 USD\n  Equity:Opening -{over} USD\n"),
                ),
                (
                    "cost",
                    format!(
                        "2024-01-15 *\n  Assets:Stock 1 AAPL {{{over} USD}}\n  Assets:Cash -1 USD\n"
                    ),
                ),
                (
                    "unit price",
                    format!(
                        "2024-01-15 *\n  Assets:Stock 1 AAPL @ {over} USD\n  Assets:Cash -1 USD\n"
                    ),
                ),
                (
                    "total price",
                    format!(
                        "2024-01-15 *\n  Assets:Stock 1 AAPL @@ {over} USD\n  Assets:Cash -1 USD\n"
                    ),
                ),
                (
                    "Decimal::MAX",
                    "2024-01-15 *\n  Assets:Cash 79228162514264337593543950335 USD\n  \
                     Equity:Opening -1 USD\n"
                        .to_owned(),
                ),
            ] {
                let errors =
                    parse_file(&input).expect_err(&format!("{what} {over} must be refused"));
                assert!(
                    errors
                        .iter()
                        .any(|error| error.kind == ParseErrorKind::InvalidNumber
                            && error.message.contains("H-17")),
                    "{what}: expected an H-17 InvalidNumber error, got {errors:?}"
                );
            }
        }
    }

    /// H-17 / T76: the largest in-cap amounts still parse, exactly as
    /// written — `10^21` itself (inclusive), at any precision, trailing zeros
    /// kept — and a `balance` or `price` directive's amount is not capped at
    /// all, because it is never summed (the M-50 fixture's pre-T65
    /// `balance … 1000000000000000000014 USD`).
    #[test]
    fn test_parse_accepts_the_largest_in_cap_amounts() {
        for number in [
            "1000000000000000000000",
            "-1,000,000,000,000,000,000,000",
            "1000000000000000000000.0000000",
            "999999999999999999999.9999999",
            "10000000000000.00000000",
            "792281625142643.37593543950335",
            "0.0000000000000000000000000001",
        ] {
            let input =
                format!("2024-01-15 *\n  Assets:Cash {number} USD\n  Equity:Opening -1 USD\n");
            let directives =
                parse_file(&input).unwrap_or_else(|e| panic!("{number} must parse: {e:?}"));
            let Directive::Transaction(transaction) = &directives[0] else {
                panic!("expected a transaction");
            };
            let amount = transaction.postings[0].amount.as_ref().expect("amount");
            assert_eq!(amount.number.to_string(), number.replace(',', ""));
        }
        for number in [
            "79228162514264337593543950335",
            "-79228162514264337593543950335",
            "1000000000000000000014",
        ] {
            for input in [
                format!("2024-01-15 balance Assets:Cash {number} USD\n"),
                format!("2024-01-15 price EUR {number} USD\n"),
            ] {
                let directives =
                    parse_file(&input).unwrap_or_else(|e| panic!("{input} must parse: {e:?}"));
                let spelled = match &directives[0] {
                    Directive::Balance(balance) => balance.amount.number.to_string(),
                    Directive::Price(price) => price.amount.number.to_string(),
                    other => panic!("unexpected {other:?}"),
                };
                assert_eq!(spelled, number);
            }
        }
    }

    /// H-17: a fraction longer than `Decimal` can hold is refused, not rounded
    /// — `from_str` used to turn this into `0.0000000000000000000000000000`,
    /// so the number held (and hashed) was not the number in the file.
    #[test]
    fn test_parse_refuses_rather_than_rounds_an_overlong_fraction() {
        let input = "2024-01-15 balance Assets:Cash 0.00000000000000000000000000001 USD\n";
        let errors = parse_file(input).expect_err("29 fractional digits cannot be held exactly");
        assert!(
            errors
                .iter()
                .any(|error| error.kind == ParseErrorKind::InvalidNumber),
            "{errors:?}"
        );
    }

    #[test]
    fn test_inline_comment_ignored() {
        let input = "2024-01-01 open Assets:Cash ; this is a comment\n";
        let directives = parse_file(input).unwrap();
        assert_eq!(directives.len(), 1);
        match &directives[0] {
            Directive::Open(open) => {
                assert_eq!(open.account, "Assets:Cash");
                assert!(open.currencies.is_empty());
            }
            other => panic!("Expected Open, got {other:?}"),
        }
    }

    #[test]
    fn test_directive_type_priority() {
        assert_eq!(
            Directive::Open(Open {
                date: NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
                account: String::new(),
                currencies: Vec::new(),
                metadata: BTreeMap::new()
            })
            .type_priority(),
            0
        );
        assert_eq!(
            Directive::Close(Close {
                date: NaiveDate::from_ymd_opt(2024, 1, 1).unwrap(),
                account: String::new(),
                metadata: BTreeMap::new()
            })
            .type_priority(),
            9
        );
    }

    #[test]
    fn test_envelope_parent_ids_parsing() {
        let input = "\
2024-01-15 * \"Test\"
  openledger-parents: \"abc123,def456,789abc\"
  Assets:Cash 100.00 USD
  Equity:Opening -100.00 USD
";
        let directives = parse_file(input).unwrap();
        match &directives[0] {
            Directive::Transaction(txn) => {
                let parents = txn.parent_ids();
                assert_eq!(parents, vec!["abc123", "def456", "789abc"]);
            }
            other => panic!("Expected Transaction, got {other:?}"),
        }
    }

    #[test]
    fn test_golden_fixture_file() {
        let fixture = include_str!("../../../testfixtures/fixture-simple.bean");
        let directives = parse_file(fixture).unwrap();

        // 5 opens + 1 commodity + 1 pad + 2 transactions + 1 balance +
        // 1 note + 1 document + 1 event + 1 price + 1 close = 15 directives
        // But the stock buy transaction is also there, so let's count carefully:
        // open Assets:Cash, open Assets:Stock, open Expenses:Food,
        // open Income:Salary, open Equity:Opening = 5
        // commodity EUR = 1
        // pad = 1
        // transaction "Initial funding" = 1
        // transaction "Pending refund" = 1
        // balance = 1
        // note = 1
        // document = 1
        // event = 1
        // transaction "Buy stock" = 1
        // price EUR = 1
        // close = 1
        // Total = 16
        assert_eq!(
            directives.len(),
            16,
            "Expected 16 directives, got {}",
            directives.len()
        );

        // Verify first directive is an open.
        assert!(matches!(&directives[0], Directive::Open(o) if o.account == "Assets:Cash"));

        // Verify the open with currencies.
        match &directives[0] {
            Directive::Open(open) => {
                assert_eq!(open.currencies, vec!["USD", "EUR"]);
            }
            other => panic!("Expected Open, got {other:?}"),
        }

        // Verify the funded transaction has envelope metadata.
        let funding_txn = directives.iter().find_map(|d| match d {
            Directive::Transaction(t) if t.narration.as_deref() == Some("Initial funding") => {
                Some(t)
            }
            _ => None,
        });
        let txn = funding_txn.expect("Should find 'Initial funding' transaction");
        assert_eq!(txn.author(), Some("local"));
        assert_eq!(txn.lamport_clock(), Some(1));
        assert!(txn.parent_ids().is_empty());
        assert_eq!(txn.tags, vec!["setup"]);
        assert_eq!(txn.links, vec!["opening-001"]);

        // Verify the stock purchase has a cost spec.
        let stock_txn = directives.iter().find_map(|d| match d {
            Directive::Transaction(t) if t.narration.as_deref() == Some("Buy stock") => Some(t),
            _ => None,
        });
        let stock = stock_txn.expect("Should find 'Buy stock' transaction");
        let cost = stock.postings[0]
            .cost
            .as_ref()
            .expect("Should have cost spec");
        assert_eq!(cost.amount.as_ref().unwrap().number, dec!(150.00));
        assert_eq!(cost.amount.as_ref().unwrap().currency, "USD");
    }

    // ── Golden corpus tests (§5.1) ──────────────────────────────────────

    #[test]
    fn test_golden_fixture_multicurrency() {
        let fixture = include_str!("../../../testfixtures/fixture-multicurrency.bean");
        let directives = parse_file(fixture).unwrap();
        // 4 opens + 4 transactions = 8
        assert!(
            directives.len() >= 8,
            "Multi-currency fixture: expected ≥8 directives, got {}",
            directives.len()
        );

        // Verify USD and EUR transactions exist.
        let currencies: Vec<_> = directives
            .iter()
            .filter_map(|d| {
                if let Directive::Transaction(t) = d {
                    Some(
                        t.postings
                            .iter()
                            .filter_map(|p| p.amount.as_ref().map(|a| a.currency.clone()))
                            .collect::<Vec<_>>(),
                    )
                } else {
                    None
                }
            })
            .flatten()
            .collect();
        assert!(currencies.contains(&"USD".to_owned()), "Must contain USD");
        assert!(currencies.contains(&"EUR".to_owned()), "Must contain EUR");
    }

    #[test]
    fn test_golden_fixture_cost_price() {
        let fixture = include_str!("../../../testfixtures/fixture-cost-price.bean");
        let directives = parse_file(fixture).unwrap();
        // Should have opens + transactions with cost specs.
        assert!(
            directives.len() >= 6,
            "Cost-price fixture: expected ≥6 directives, got {}",
            directives.len()
        );

        // Find a posting with a cost.
        let has_cost = directives.iter().any(|d| {
            if let Directive::Transaction(t) = d {
                t.postings.iter().any(|p| p.cost.is_some())
            } else {
                false
            }
        });
        assert!(
            has_cost,
            "Cost-price fixture must contain at least one posting with cost spec"
        );
    }

    #[test]
    fn test_golden_fixture_pad_balance() {
        let fixture = include_str!("../../../testfixtures/fixture-pad-balance.bean");
        let directives = parse_file(fixture).unwrap();
        // Should have opens + transaction + pad + balance.
        let has_pad = directives.iter().any(|d| matches!(d, Directive::Pad(_)));
        let has_balance = directives
            .iter()
            .any(|d| matches!(d, Directive::Balance(_)));
        assert!(has_pad, "Pad-balance fixture must contain a pad directive");
        assert!(
            has_balance,
            "Pad-balance fixture must contain a balance directive"
        );
    }

    #[test]
    fn test_golden_fixture_unsupported_include() {
        let fixture = include_str!("../../../testfixtures/fixture-unsupported-include.bean");
        let result = parse_file(fixture);
        assert!(
            result.is_err(),
            "CT-15: Unsupported include fixture must fail to parse"
        );
    }

    // ── M-25: trailing tokens are refused, not dropped ───────────────────

    /// The four truncations the finding proved, verbatim.
    ///
    /// Each one used to parse **successfully** into a different, shorter
    /// directive — which reconcile then adopted, signed with this node's key
    /// and wrote back over the operator's text. Nothing was rejected, so
    /// nothing was logged. Now each is a parse error, which is what stops the
    /// canonical rewrite from running at all.
    #[test]
    fn m25_the_four_proven_truncations_are_refused() {
        let cases: [(&str, &str, &str); 4] = [
            (
                "2024-01-01 open Assets:Cash USD AND MORE JUNK",
                "an open directive",
                "AND MORE JUNK",
            ),
            (
                "2024-01-01 close Assets:Cash 2020-01-01",
                "a close directive",
                "2020-01-01",
            ),
            (
                "2024-01-01 * \"p\" \"n\" \"third string dropped\"\n\
                 \x20 Assets:Cash                                       1.00 USD\n\
                 \x20 Equity:Opening                                   -1.00 USD\n",
                "a transaction header",
                "\"third string dropped\"",
            ),
            (
                "2024-01-01 * \"p\" \"n\"\n\
                 \x20 Assets:Cash                                       1.00 USD this is dropped\n\
                 \x20 Equity:Opening                                   -1.00 USD\n",
                "a posting",
                "this is dropped",
            ),
        ];

        for (input, form, dropped) in cases {
            let errors = match parse_file(input) {
                Ok(directives) => panic!(
                    "M-25: {input:?} must not parse; it silently became {:?}",
                    crate::serialize::full_file_serialize(&directives, &[])
                ),
                Err(errors) => errors,
            };
            let rendered = errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ");
            assert!(
                rendered.contains(form),
                "the rejection must name the line form it was refusing ({form}): {rendered}"
            );
            assert!(
                rendered.contains(dropped),
                "the rejection must quote back the text that used to be dropped \
                 ({dropped}): {rendered}"
            );
            assert!(
                errors
                    .iter()
                    .any(|error| error.kind == ParseErrorKind::UnexpectedToken),
                "classified as UnexpectedToken: {rendered}"
            );
        }
    }

    /// Every line form, not just the four that were proven.
    ///
    /// The finding's list was what someone happened to try; the defect was that
    /// `at_eol` had three call sites in the whole grammar. This walks each form
    /// so a new one cannot be added without the check.
    #[test]
    fn m25_every_line_form_refuses_trailing_junk() {
        let cases = [
            "2024-01-01 open Assets:Cash USD junk",
            "2024-01-01 close Assets:Cash junk",
            "2024-01-01 commodity USD junk",
            "2024-01-01 pad Assets:Cash Equity:Opening junk",
            "2024-01-01 balance Assets:Cash 1.00 USD junk",
            "2024-01-01 note Assets:Cash \"hi\" junk",
            "2024-01-01 document Assets:Cash \"/a.pdf\" junk",
            "2024-01-01 event \"location\" \"here\" junk",
            "2024-01-01 price EUR 1.10 USD junk",
            "2024-01-01 txn \"p\" \"n\" junk\n  Assets:Cash   1.00 USD\n",
            "2024-01-01 * \"p\" \"n\"\n  Assets:Cash   1.00 USD {1.00 USD} @ 2.00 USD junk\n",
            "2024-01-01 * \"p\" \"n\"\n  key: \"value\" junk\n  Assets:Cash   1.00 USD\n",
        ];
        for input in cases {
            assert!(
                parse_file(input).is_err(),
                "M-25: trailing junk must be refused, not dropped: {input:?}"
            );
        }
    }

    /// The other half of M-25: what the grammar genuinely allows must still
    /// parse. `at_eol` treats spaces, tabs and a `;` comment as end-of-line, so
    /// a comment after ANY line form is still legal — which is the whole reason
    /// the check is written in terms of `at_eol` rather than "nothing left".
    #[test]
    fn m25_comments_and_whitespace_are_still_end_of_line() {
        let input = "2024-01-01 open Assets:Cash USD, EUR   ; multi-currency  \n\
                     2024-01-01 open Equity:Opening\t\t; tabs then a comment\n\
                     2024-01-01 commodity EUR ; a commodity\n\
                     2024-01-01 pad Assets:Cash Equity:Opening ; a pad\n\
                     2024-02-01 balance Assets:Cash 1.00 USD ; an assertion\n\
                     2024-03-01 note Assets:Cash \"n\" ; a note\n\
                     2024-03-01 document Assets:Cash \"/a.pdf\" ; a document\n\
                     2024-06-01 event \"location\" \"here\" ; an event\n\
                     2024-12-01 price EUR 1.10 USD ; a quote\n\
                     2024-01-15 * \"p\" \"n\" #tag ^link   ; a transaction\n\
                     \x20 key: \"value\"  ; posting-less metadata\n\
                     \x20 Assets:Cash    1.00 USD {1.00 USD} @ 2.00 USD  ; a full posting\n\
                     \x20 Equity:Opening\t; an elided posting with a comment\n\
                     2024-12-31 close Assets:Cash ; done\n";
        let directives = parse_file(input).unwrap_or_else(|errors| {
            panic!(
                "M-25 must not reject legal trailing content: {}",
                errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ")
            )
        });
        assert_eq!(directives.len(), 11);
    }

    /// The check must not perturb what the serializer writes: every fixture
    /// round-trips through `parse → serialize → parse` to the same text, so a
    /// canonical file this node wrote can always be read back (M-25).
    #[test]
    fn m25_every_fixture_still_round_trips() {
        for (name, fixture) in [
            (
                "fixture-simple",
                include_str!("../../../testfixtures/fixture-simple.bean"),
            ),
            (
                "fixture-multicurrency",
                include_str!("../../../testfixtures/fixture-multicurrency.bean"),
            ),
            (
                "fixture-cost-price",
                include_str!("../../../testfixtures/fixture-cost-price.bean"),
            ),
            (
                "fixture-pad-balance",
                include_str!("../../../testfixtures/fixture-pad-balance.bean"),
            ),
        ] {
            let once = parse_file(fixture)
                .unwrap_or_else(|errors| panic!("{name} must parse: {errors:?}"));
            let text = crate::serialize::full_file_serialize(&once, &[]);
            let twice = parse_file(&text)
                .unwrap_or_else(|errors| panic!("{name} must re-parse: {errors:?}"));
            assert_eq!(
                text,
                crate::serialize::full_file_serialize(&twice, &[]),
                "{name} must round-trip"
            );
        }
    }

    // ── T66 / H-18: the bounded parse entry point for the wire path ──────

    /// `parse_file_bounded` keeps the first `max_errors` in source order and
    /// counts every failed block, while `parse_file` still keeps them all.
    #[test]
    fn parse_file_bounded_keeps_the_first_errors_and_counts_the_rest() {
        let body = "x\n".repeat(1000);
        let bounded = parse_file_bounded(&body, 3, ParseLimits::RESOURCE).unwrap_err();
        assert_eq!(bounded.errors.len(), 3);
        assert_eq!(bounded.total, 1000);
        assert_eq!(
            bounded.errors.iter().map(|e| e.line).collect::<Vec<_>>(),
            vec![1, 2, 3],
            "the kept errors are the FIRST ones, in source order"
        );
        // The file loader keeps every error, byte for byte the same ones.
        let all = parse_file(&body).unwrap_err();
        assert_eq!(all.len(), 1000);
        assert_eq!(&all[..3], &bounded.errors[..]);
        // A cap of zero only counts.
        let counted = parse_file_bounded(&body, 0, ParseLimits::RESOURCE).unwrap_err();
        assert!(counted.errors.is_empty());
        assert_eq!(counted.total, 1000);
        // Fewer errors than the cap: the cap is invisible.
        let two = parse_file_bounded(
            "x\n2024-01-01 open Assets:Cash USD\ny\n",
            3,
            ParseLimits::RESOURCE,
        )
        .unwrap_err();
        assert_eq!(two.errors.len(), 2);
        assert_eq!(two.total, 2);
        // A clean body is `Ok` on both.
        assert_eq!(
            parse_file_bounded(
                "2024-01-01 open Assets:Cash USD\n",
                3,
                ParseLimits::RESOURCE
            )
            .unwrap(),
            parse_file("2024-01-01 open Assets:Cash USD\n").unwrap()
        );
    }

    /// `count_directive_headers` is `directives + errors` of a `parse_file` run
    /// for every block shape the loop distinguishes: blank, comment, tab- and
    /// space-indented, a leading BOM, CRLF, and bodies that fail.
    #[test]
    fn count_directive_headers_agrees_with_parse_file() {
        // Every block parses: the count is the directive count.
        let all_parse = [
            "",
            "\n\n",
            "; only a comment\n   ; indented comment\n",
            "\u{feff}2024-01-01 open Assets:Cash USD\n",
            "2024-01-01 open Assets:Cash USD\n2024-01-02 open Assets:Bank USD\n",
            "2024-01-01 * \"payee\" \"narr\"\n  Assets:Cash  1 USD\n  Equity:Open\n",
            "2024-01-01 * \"payee\" \"narr\"\n\tAssets:Cash  1 USD\n\tEquity:Open\n",
            "2024-01-01 open Assets:Cash USD\r\n2024-01-02 open Assets:Bank USD\r\n",
            "2024-01-01 open Assets:Cash USD\n  meta: \"v\"\n; c\n2024-01-02 note Assets:Cash \"n\"\n",
        ];
        for input in all_parse {
            let directives = parse_file(input).unwrap_or_else(|e| panic!("{input:?}: {e:?}"));
            assert_eq!(
                count_directive_headers(input),
                directives.len(),
                "header count disagrees with parse_file for {input:?}"
            );
        }
        // Every block fails: the count is the error count.
        let x50 = "x\n".repeat(50);
        let x_blank50 = "x\n\n".repeat(50);
        let all_fail = [x50.as_str(), x_blank50.as_str()];
        for input in all_fail {
            let errors = parse_file(input).unwrap_err();
            let bounded = parse_file_bounded(input, usize::MAX, ParseLimits::RESOURCE).unwrap_err();
            assert_eq!(bounded.total, errors.len());
            assert_eq!(
                count_directive_headers(input),
                errors.len(),
                "header count disagrees with parse_file for {input:?}"
            );
        }
        // A good block, an orphaned indented line after a blank, a bad block:
        // two headers; two errors (the orphan and the bad date).
        let orphaned = "2024-01-01 open Assets:Cash USD\n  meta: \"v\"\n\n  orphaned: \"v\"\n2024-13-01 open A:B USD\n";
        assert_eq!(parse_file(orphaned).unwrap_err().len(), 2);
        assert_eq!(count_directive_headers(orphaned), 2);
        // A stray indented line before any header is an ERROR but not a
        // block: under-counted, which only ever makes the wire gate lenient
        // and leaves the bounded parser to refuse it.
        let stray = "  stray indented line\nx\n\n y\n";
        assert_eq!(parse_file(stray).unwrap_err().len(), 3);
        assert_eq!(count_directive_headers(stray), 1);
        let indented50 = " x\n".repeat(50);
        assert_eq!(parse_file(&indented50).unwrap_err().len(), 50);
        assert_eq!(count_directive_headers(&indented50), 0);
        // Mixed: a bad-date block, a note block with a bad body line, and a
        // stray indented line after a blank — two headers, three errors.
        let mixed = "2024-13-01 open Assets:Cash USD\n; comment\n2024-01-01 note Assets:Cash \"n\"\n  x\n\n  y\n";
        let errors = parse_file(mixed).unwrap_err();
        assert_eq!(errors.len(), 3, "{errors:?}");
        assert_eq!(count_directive_headers(mixed), 2);
    }

    /// T66 / M-41: an unsupported keyword is quoted back at most 60 characters
    /// long, exactly as a trailing-content excerpt is — a 1 MiB keyword was a
    /// 1 MiB error message and then a 1 MiB log line.
    #[test]
    fn unsupported_directive_message_excerpts_the_keyword() {
        let keyword = "k".repeat(1024 * 1024);
        let input = format!("2024-01-01 {keyword}\n");
        let errors = parse_file(&input).unwrap_err();
        assert_eq!(errors.len(), 1);
        assert_eq!(errors[0].kind, ParseErrorKind::UnsupportedDirective);
        assert!(errors[0].message.len() < 128, "{}", errors[0].message.len());
        assert!(errors[0].message.ends_with("\u{2026}'"));
        // A short keyword is still quoted whole.
        let errors = parse_file("2024-01-01 option \"t\" \"v\"\n").unwrap_err();
        assert_eq!(errors[0].message, "Unsupported directive: 'option'");
        // The unlisted-keyword arm bounds the same way.
        let errors = parse_file(&format!("2024-01-01 {}\n", "z".repeat(500))).unwrap_err();
        assert_eq!(errors[0].kind, ParseErrorKind::UnsupportedDirective);
        assert_eq!(
            errors[0].message.chars().count(),
            "Unsupported directive: ''".len() + 61
        );
    }

    // ── T75 / M-48, L-78: cardinality caps counted inside the block loop ─

    use crate::limits::{MAX_CURRENCIES_PER_OPEN, MAX_POSTING_METADATA_KEYS_PER_TRANSACTION};
    use crate::service::{
        MAX_LINKS_PER_TRANSACTION, MAX_METADATA_KEYS_PER_DIRECTIVE, MAX_POSTINGS_PER_TRANSACTION,
        MAX_TAGS_PER_TRANSACTION,
    };

    /// A transaction of `postings` single-unit postings under one header.
    fn transaction_with_postings(postings: usize) -> String {
        let mut body = String::from("2024-01-01 * \"n\"\n");
        for _ in 0..postings {
            body.push_str("  Assets:Cash  1 USD\n");
        }
        body
    }

    /// Parse `input` under [`ParseLimits::RESOURCE`] and return the cap it
    /// stopped at, or `None` if it parsed.
    fn tripped(input: &str) -> Option<ParseLimitExceeded> {
        match parse_file_bounded(input, 3, ParseLimits::RESOURCE) {
            Ok(_) => None,
            Err(bounded) => Some(
                bounded
                    .limit
                    .unwrap_or_else(|| panic!("a parse error, not a cap: {:?}", bounded.errors)),
            ),
        }
    }

    /// Each cap admits exactly its maximum and stops the parse at one more,
    /// naming the cap and the line it was crossed on — the same constants
    /// `service::enforce_resource_limits` refuses by, referenced, not restated.
    #[test]
    fn parse_limits_admit_the_cap_and_stop_one_past_it() {
        // Postings.
        assert_eq!(
            tripped(&transaction_with_postings(MAX_POSTINGS_PER_TRANSACTION)),
            None
        );
        let over = tripped(&transaction_with_postings(MAX_POSTINGS_PER_TRANSACTION + 1)).unwrap();
        assert_eq!(
            (over.what, over.max),
            ("postings", MAX_POSTINGS_PER_TRANSACTION)
        );
        assert_eq!(
            over.line,
            MAX_POSTINGS_PER_TRANSACTION + 2,
            "the 1,001st posting's line"
        );

        // Tags and links, on the header.
        let header = |sigil: &str, count: usize| {
            format!(
                "2024-01-01 * \"n\"{}\n  Assets:Cash  1 USD\n  Equity:Open  -1 USD\n",
                format!(" {sigil}t").repeat(count)
            )
        };
        assert_eq!(tripped(&header("#", MAX_TAGS_PER_TRANSACTION)), None);
        let over = tripped(&header("#", MAX_TAGS_PER_TRANSACTION + 1)).unwrap();
        assert_eq!(
            (over.what, over.max, over.line),
            ("tags", MAX_TAGS_PER_TRANSACTION, 1)
        );
        assert_eq!(tripped(&header("^", MAX_LINKS_PER_TRANSACTION)), None);
        let over = tripped(&header("^", MAX_LINKS_PER_TRANSACTION + 1)).unwrap();
        assert_eq!((over.what, over.max), ("links", MAX_LINKS_PER_TRANSACTION));

        // Directive metadata: a transaction's, counted as read, and an
        // `open`'s, checked on the finished map.
        let keys = |count: usize, indent: &str| -> String {
            (0..count)
                .map(|i| format!("{indent}k{i}: \"v\"\n"))
                .collect()
        };
        let txn = |count: usize| {
            format!(
                "2024-01-01 * \"n\"\n{}  Assets:Cash  1 USD\n  Equity:Open  -1 USD\n",
                keys(count, "  ")
            )
        };
        assert_eq!(tripped(&txn(MAX_METADATA_KEYS_PER_DIRECTIVE)), None);
        let over = tripped(&txn(MAX_METADATA_KEYS_PER_DIRECTIVE + 1)).unwrap();
        assert_eq!(
            (over.what, over.max),
            ("metadata keys", MAX_METADATA_KEYS_PER_DIRECTIVE)
        );
        let open = |count: usize| format!("2024-01-01 open Assets:Cash USD\n{}", keys(count, "  "));
        assert_eq!(tripped(&open(MAX_METADATA_KEYS_PER_DIRECTIVE)), None);
        let over = tripped(&open(MAX_METADATA_KEYS_PER_DIRECTIVE + 1)).unwrap();
        assert_eq!(
            (over.what, over.max),
            ("metadata keys", MAX_METADATA_KEYS_PER_DIRECTIVE)
        );

        // Posting metadata, summed over the postings: half on each of two.
        let split = |count: usize| {
            format!(
                "2024-01-01 * \"n\"\n  Assets:Cash  1 USD\n{}  Equity:Open  -1 USD\n{}",
                keys(count / 2, "    "),
                keys(count - count / 2, "    ").replace("    k", "    j")
            )
        };
        assert_eq!(
            tripped(&split(MAX_POSTING_METADATA_KEYS_PER_TRANSACTION)),
            None
        );
        let over = tripped(&split(MAX_POSTING_METADATA_KEYS_PER_TRANSACTION + 1)).unwrap();
        assert_eq!(
            (over.what, over.max),
            (
                "posting metadata keys in one transaction",
                MAX_POSTING_METADATA_KEYS_PER_TRANSACTION
            )
        );

        // Currencies in an `open` (L-78).
        let currencies = |count: usize| {
            let list: Vec<String> = (0..count).map(|i| format!("C{i:03}")).collect();
            format!("2024-01-01 open Assets:Cash {}\n", list.join(","))
        };
        assert_eq!(tripped(&currencies(MAX_CURRENCIES_PER_OPEN)), None);
        let over = tripped(&currencies(MAX_CURRENCIES_PER_OPEN + 1)).unwrap();
        assert_eq!(
            (over.what, over.max, over.line),
            ("currencies in one open", MAX_CURRENCIES_PER_OPEN, 1)
        );

        // Body lines: a repeated key is ONE map entry, so only the line count
        // can refuse this — and it does, while collecting.
        let lines = ParseLimits::RESOURCE.max_body_lines();
        let repeated = |count: usize| {
            format!(
                "2024-01-01 open Assets:Cash USD\n{}",
                "  k: \"v\"\n".repeat(count)
            )
        };
        assert_eq!(tripped(&repeated(lines)), None);
        let over = tripped(&repeated(lines + 1)).unwrap();
        assert_eq!(
            (over.what, over.max),
            ("body lines in one directive", lines)
        );
        assert_eq!(over.line, lines + 2);
    }

    /// A cap stops the parse: nothing after the refused block is read, and the
    /// errors before it are kept. The rendering carries no body text.
    #[test]
    fn a_tripped_cap_stops_the_parse_and_renders_small() {
        let input = format!(
            "x\n{}{}",
            transaction_with_postings(MAX_POSTINGS_PER_TRANSACTION + 1),
            "y\n".repeat(50)
        );
        let bounded = parse_file_bounded(&input, 3, ParseLimits::RESOURCE).unwrap_err();
        assert_eq!(
            bounded.total, 1,
            "the 50 blocks after the cap are never read"
        );
        assert_eq!(bounded.errors.len(), 1);
        let limit = bounded.limit.expect("stopped at the postings cap");
        assert!(limit.to_string().len() < 128, "{limit}");
        assert!(
            limit.to_string().starts_with("Too many postings"),
            "{limit}"
        );
    }

    /// `parse_file` — the file loader — applies no caps (boot applies no write
    /// caps), and `ParseLimits::UNLIMITED` is exactly `parse_file`.
    #[test]
    fn the_file_loader_applies_no_parse_limits() {
        let body = transaction_with_postings(MAX_POSTINGS_PER_TRANSACTION + 1);
        let parsed = parse_file(&body).expect("the file path is unchanged");
        let Directive::Transaction(transaction) = &parsed[0] else {
            panic!("a transaction");
        };
        assert_eq!(transaction.postings.len(), MAX_POSTINGS_PER_TRANSACTION + 1);
        assert_eq!(
            parse_file_bounded(&body, 3, ParseLimits::UNLIMITED).unwrap(),
            parsed
        );
    }

    /// The lazy scanner reads only what it walks, and still sees everything a
    /// look-ahead needs: trailing content far along a line is found, quoted
    /// and located exactly as the eager scanner did (M-25), and the column is
    /// the column of the first non-blank character after the last token.
    #[test]
    fn the_lazy_scanner_still_sees_the_rest_of_the_line() {
        let input = format!("2024-01-01 close Assets:Cash{}junk\n", " ".repeat(5000));
        let errors = parse_file(&input).unwrap_err();
        assert_eq!(errors[0].kind, ParseErrorKind::UnexpectedToken);
        assert_eq!(
            errors[0].column,
            "2024-01-01 close Assets:Cash".len() + 5000 + 1
        );
        assert!(
            errors[0].message.contains("'junk'"),
            "{}",
            errors[0].message
        );
        // A comment after the last token is end-of-line, found lazily too.
        assert!(parse_file("2024-01-01 close Assets:Cash   ; a comment\n").is_ok());
    }

    /// T75: an over-long currency is refused with an excerpt and its length,
    /// never echoed whole.
    #[test]
    fn an_over_long_currency_is_excerpted() {
        let error = validate_currency(&"U".repeat(100_000)).unwrap_err();
        assert!(error.len() < 160, "{}", error.len());
        assert!(error.contains("got 100000"), "{error}");
        assert!(validate_currency(&"U".repeat(24)).is_ok());
    }
}
