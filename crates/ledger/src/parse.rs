//! Hand-written recursive-descent parser for the Beancount directive subset (§2.3, §3.3.2).
//!
//! Entry point: [`parse_file`].

use chrono::NaiveDate;
use rust_decimal::Decimal;
use std::collections::BTreeMap;
use std::str::FromStr;

use crate::error::{ParseError, ParseErrorKind};
use crate::model::*;

// ─── Scanner ─────────────────────────────────────────────────────────────────

/// Character-level scanner for a single line of text.
struct Scanner {
    chars: Vec<char>,
    position: usize,
}

impl Scanner {
    fn new(line: &str) -> Self {
        Scanner {
            chars: line.chars().collect(),
            position: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.position).copied()
    }

    fn advance(&mut self) -> Option<char> {
        let character = self.chars.get(self.position).copied();
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
        for &character in &self.chars[self.position..] {
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
        Decimal::from_str(&number_string).map_err(|e| format!("Invalid number: {e}"))
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

    fn read_amount(&mut self) -> Result<Amount, String> {
        let number = self.read_number()?;
        self.skip_whitespace();
        let currency = self.read_currency()?;
        Ok(Amount { number, currency })
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
        Ok(link)
    }
}

// ─── Validation ──────────────────────────────────────────────────────────────

const VALID_ROOTS: [&str; 5] = ["Assets", "Liabilities", "Equity", "Income", "Expenses"];

/// Validate account name per §2.3: `Root:Segment:Segment` where each segment
/// matches `[A-Z][a-zA-Z0-9-]*`.
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
            if !character.is_alphanumeric() && character != '-' {
                return Err(format!(
                    "Invalid character '{character}' in account segment: {name}"
                ));
            }
        }
    }
    Ok(())
}

/// Validate currency per §2.3: `[A-Z][A-Z0-9'._-]{0,22}[A-Z0-9]` (min 2 chars).
pub fn validate_currency(currency: &str) -> Result<(), String> {
    let chars: Vec<char> = currency.chars().collect();
    if chars.len() < 2 {
        return Err(format!(
            "Currency must be at least 2 characters, got: {currency}"
        ));
    }
    if chars.len() > 24 {
        return Err(format!(
            "Currency must be at most 24 characters, got: {currency}"
        ));
    }
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
    if !tag
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_' || character == '-')
    {
        return Err(format!("Invalid character in tag: {tag}"));
    }
    Ok(())
}

/// Validate a link name per §2.3: `^[a-zA-Z0-9_-]+`.
pub fn validate_link(link: &str) -> Result<(), String> {
    if link.is_empty() {
        return Err("Link name cannot be empty".to_owned());
    }
    if !link
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_' || character == '-')
    {
        return Err(format!("Invalid character in link: {link}"));
    }
    Ok(())
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

// ─── Top-level ───────────────────────────────────────────────────────────────

/// Parse a complete `.bean` file into a list of directives.
///
/// Returns `Err` with all accumulated errors if any line fails to parse.
pub fn parse_file(input: &str) -> Result<Vec<Directive>, Vec<ParseError>> {
    let mut directives = Vec::new();
    let mut errors = Vec::new();

    let lines: Vec<&str> = input.lines().collect();
    let mut index = 0;

    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim();

        // Skip blank lines and comment-only lines.
        if trimmed.is_empty() || trimmed.starts_with(';') {
            index += 1;
            continue;
        }

        // A directive header starts at column 0 (not indented).
        if !line.starts_with(' ') && !line.starts_with('\t') {
            let header_line_number = index + 1; // 1-based
            let header = line;
            index += 1;

            // Collect indented body lines (postings + metadata).
            let mut body_lines: Vec<(usize, &str)> = Vec::new();
            while index < lines.len() {
                let body_line = lines[index];
                if body_line.is_empty() {
                    // Blank line ends the block.
                    break;
                }
                if body_line.starts_with(' ') || body_line.starts_with('\t') {
                    let body_trimmed = body_line.trim();
                    if !body_trimmed.is_empty() && !body_trimmed.starts_with(';') {
                        body_lines.push((index + 1, body_line));
                    }
                    index += 1;
                } else {
                    // Next non-indented line = next directive.
                    break;
                }
            }

            match parse_directive_block(header, &body_lines, header_line_number) {
                Ok(directive) => directives.push(directive),
                Err(error) => errors.push(error),
            }
        } else {
            errors.push(ParseError::new(
                index + 1,
                1,
                "Unexpected indented line without a preceding directive",
                ParseErrorKind::BadStructure,
            ));
            index += 1;
        }
    }

    if errors.is_empty() {
        Ok(directives)
    } else {
        Err(errors)
    }
}

// ─── Directive block parsing ─────────────────────────────────────────────────

fn parse_directive_block(
    header: &str,
    body_lines: &[(usize, &str)],
    line_number: usize,
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
            parse_transaction(&mut scanner, date, flag, body_lines, line_number)
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
                    format!("Unsupported directive: '{keyword}'"),
                    ParseErrorKind::UnsupportedDirective,
                ));
            }

            match keyword.as_str() {
                "txn" => {
                    parse_transaction(&mut scanner, date, Flag::Complete, body_lines, line_number)
                        .map(Directive::Transaction)
                }
                "open" => {
                    parse_open(&mut scanner, date, body_lines, line_number).map(Directive::Open)
                }
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
                    format!("Unsupported directive: '{keyword}'"),
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
            }
            _ => break,
        }
    }

    // Parse body lines into transaction metadata and postings.
    let (metadata, postings) = parse_transaction_body(body_lines)?;

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
            } else {
                break;
            }
        }
    }

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
    let metadata = parse_metadata_body(body_lines)?;
    Ok(Event {
        date,
        event_type,
        description,
        metadata,
    })
}

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
) -> Result<(Metadata, Vec<Posting>), ParseError> {
    let mut metadata = BTreeMap::new();
    let mut postings = Vec::new();
    let mut current_posting: Option<Posting> = None;

    for &(line_number, line) in body_lines {
        let trimmed = line.trim();
        if is_metadata_line(trimmed) {
            let (key, value) = parse_metadata_line(trimmed, line_number)?;
            if let Some(ref mut posting) = current_posting {
                posting.metadata.insert(key, value);
            } else {
                metadata.insert(key, value);
            }
        } else {
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

    // Read key.
    let key = scanner.read_word();
    if key.is_empty() {
        return Err(ParseError::new(
            line_number,
            1,
            "Expected metadata key",
            ParseErrorKind::UnexpectedToken,
        ));
    }

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
    let amount = scanner.read_amount().map_err(|message| {
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
    let amount = scanner.read_amount().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::InvalidNumber,
        )
    })?;

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

    let amount = scanner.read_amount().map_err(|message| {
        ParseError::new(
            line_number,
            scanner.column(),
            message,
            ParseErrorKind::InvalidNumber,
        )
    })?;

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

    #[test]
    fn test_invalid_metadata_non_string() {
        let input = "2024-01-01 open Assets:Cash\n  category: 42\n";
        let errors = parse_file(input).unwrap_err();
        assert_eq!(errors[0].kind, ParseErrorKind::InvalidMetadataValue);
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
}
