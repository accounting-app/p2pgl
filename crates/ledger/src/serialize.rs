//! Canonical serializer for Beancount directives (§3.3.2).
//!
//! Two modes:
//! - [`economic_canonical_serialize`]: single directive, no `openledger-*` metadata — for hashing.
//! - [`full_file_serialize`]: all directives, ordered, with envelope metadata — for `.bean` persistence.

use std::fmt::Write;

use crate::model::*;

// ─── Public API ──────────────────────────────────────────────────────────────

/// Serialize a single directive's economic canonical form (§3.3.2).
///
/// Omits every `openledger-*` metadata key. Includes a trailing `\n` after
/// the last line. Does **not** include the inter-directive blank line.
pub fn economic_canonical_serialize(directive: &Directive) -> String {
    let mut output = String::new();
    serialize_directive(&mut output, directive, false);
    output
}

/// Serialize the full ledger file in canonical order (§3.3.2).
///
/// Includes all metadata (envelope keys included), one blank line between
/// directives, and a final `\n`.
pub fn full_file_serialize(directives: &[Directive], leading_comments: &[String]) -> String {
    if directives.is_empty() && leading_comments.is_empty() {
        return String::new();
    }

    let mut output = String::new();

    // Leading comments (preserved at beginning of file).
    for comment in leading_comments {
        writeln!(output, "; {comment}").unwrap();
    }

    // Sort directives by (date, type_priority, stable_sort_key).
    let mut sorted_indices: Vec<usize> = (0..directives.len()).collect();
    sorted_indices.sort_by(|&a, &b| {
        let directive_a = &directives[a];
        let directive_b = &directives[b];
        directive_a
            .date()
            .cmp(&directive_b.date())
            .then_with(|| {
                directive_a
                    .type_priority()
                    .cmp(&directive_b.type_priority())
            })
            .then_with(|| stable_sort_key(directive_a).cmp(&stable_sort_key(directive_b)))
    });

    // Emit directives with blank lines between.
    for (index, &directive_index) in sorted_indices.iter().enumerate() {
        if index > 0 || !leading_comments.is_empty() {
            output.push('\n'); // blank line separator
        }
        serialize_directive(&mut output, &directives[directive_index], true);
    }

    output
}

// ─── Stable sort key (§3.3.2) ────────────────────────────────────────────────

fn stable_sort_key(directive: &Directive) -> String {
    match directive {
        Directive::Transaction(t) => {
            let narration = t.narration.as_deref().unwrap_or("");
            let payee = t.payee.as_deref().unwrap_or("");
            format!("{narration}|{payee}")
        }
        Directive::Open(o) => o.account.clone(),
        Directive::Close(c) => c.account.clone(),
        Directive::Balance(b) => {
            format!("{}|{} {}", b.account, b.amount.number, b.amount.currency)
        }
        Directive::Pad(p) => format!("{}|{}", p.account, p.source_account),
        Directive::Commodity(c) => c.currency.clone(),
        Directive::Price(p) => {
            format!("{}|{} {}", p.currency, p.amount.number, p.amount.currency)
        }
        Directive::Note(n) => format!("{}|{}", n.account, n.comment),
        Directive::Document(d) => format!("{}|{}", d.account, d.path),
        Directive::Event(e) => format!("{}|{}", e.event_type, e.description),
    }
}

// ─── Directive dispatch ──────────────────────────────────────────────────────

fn serialize_directive(output: &mut String, directive: &Directive, include_envelope: bool) {
    match directive {
        Directive::Transaction(t) => serialize_transaction(output, t, include_envelope),
        Directive::Open(o) => serialize_open(output, o, include_envelope),
        Directive::Close(c) => serialize_close(output, c, include_envelope),
        Directive::Commodity(c) => serialize_commodity(output, c, include_envelope),
        Directive::Pad(p) => serialize_pad(output, p, include_envelope),
        Directive::Balance(b) => serialize_balance(output, b, include_envelope),
        Directive::Note(n) => serialize_note(output, n, include_envelope),
        Directive::Document(d) => serialize_document(output, d, include_envelope),
        Directive::Event(e) => serialize_event(output, e, include_envelope),
        Directive::Price(p) => serialize_price(output, p, include_envelope),
    }
}

// ─── Transaction ─────────────────────────────────────────────────────────────

fn serialize_transaction(output: &mut String, txn: &Transaction, include_envelope: bool) {
    // Header: DATE FLAG ["payee"] ["narration"] [#tags] [^links]
    write!(
        output,
        "{} {}",
        txn.date.format("%Y-%m-%d"),
        txn.flag.as_char()
    )
    .unwrap();

    match (&txn.payee, &txn.narration) {
        (Some(payee), Some(narration)) => {
            write!(
                output,
                " {} {}",
                quote_string(payee),
                quote_string(narration)
            )
            .unwrap();
        }
        (None, Some(narration)) => {
            write!(output, " {}", quote_string(narration)).unwrap();
        }
        (Some(payee), None) => {
            // Payee without narration: emit as narration-only (Beancount convention).
            write!(output, " {}", quote_string(payee)).unwrap();
        }
        (None, None) => {}
    }

    // Tags sorted lexicographically (§3.3.2).
    let mut sorted_tags = txn.tags.clone();
    sorted_tags.sort();
    for tag in &sorted_tags {
        write!(output, " #{tag}").unwrap();
    }

    // Links sorted lexicographically (§3.3.2).
    let mut sorted_links = txn.links.clone();
    sorted_links.sort();
    for link in &sorted_links {
        write!(output, " ^{link}").unwrap();
    }

    output.push('\n');

    // Transaction-level metadata (2-space indent, sorted by key).
    serialize_metadata(output, &txn.metadata, include_envelope, "  ");

    // Postings.
    for posting in &txn.postings {
        serialize_posting(output, posting, include_envelope);
    }
}

// ─── Posting ─────────────────────────────────────────────────────────────────

fn serialize_posting(output: &mut String, posting: &Posting, include_envelope: bool) {
    let account_prefix = format!("  {}", posting.account);
    output.push_str(&account_prefix);

    if let Some(ref amount) = posting.amount {
        // Column 52 alignment: number starts at column 52 (1-based).
        // gap = spaces needed so that (prefix_len + gap) = 51,
        // putting the first digit/sign at position 52.
        let gap = if account_prefix.len() >= 51 {
            2 // minimum gap for very long account names
        } else {
            51 - account_prefix.len()
        };
        for _ in 0..gap {
            output.push(' ');
        }

        // Amount: NUMBER CURRENCY
        write!(output, "{} {}", amount.number, amount.currency).unwrap();

        // Optional cost: {NUMBER CURRENCY[, DATE]}
        if let Some(ref cost) = posting.cost {
            output.push_str(" {");
            if let Some(ref cost_amount) = cost.amount {
                write!(output, "{} {}", cost_amount.number, cost_amount.currency).unwrap();
                if let Some(ref date) = cost.date {
                    write!(output, ", {}", date.format("%Y-%m-%d")).unwrap();
                }
            }
            output.push('}');
        }

        // Optional price: @ or @@
        if let Some(ref price) = posting.price {
            match price {
                PriceSpec::Unit(a) => {
                    write!(output, " @ {} {}", a.number, a.currency).unwrap();
                }
                PriceSpec::Total(a) => {
                    write!(output, " @@ {} {}", a.number, a.currency).unwrap();
                }
            }
        }
    }
    // Elided posting: account name only, no amount.

    output.push('\n');

    // Posting-level metadata (4-space indent for subordination).
    serialize_metadata(output, &posting.metadata, include_envelope, "    ");
}

// ─── Non-transaction directives ──────────────────────────────────────────────

fn serialize_open(output: &mut String, open: &Open, include_envelope: bool) {
    write!(
        output,
        "{} open {}",
        open.date.format("%Y-%m-%d"),
        open.account
    )
    .unwrap();
    if !open.currencies.is_empty() {
        write!(output, " {}", open.currencies.join(", ")).unwrap();
    }
    output.push('\n');
    serialize_metadata(output, &open.metadata, include_envelope, "  ");
}

fn serialize_close(output: &mut String, close: &Close, include_envelope: bool) {
    writeln!(
        output,
        "{} close {}",
        close.date.format("%Y-%m-%d"),
        close.account
    )
    .unwrap();
    serialize_metadata(output, &close.metadata, include_envelope, "  ");
}

fn serialize_commodity(output: &mut String, commodity: &Commodity, include_envelope: bool) {
    writeln!(
        output,
        "{} commodity {}",
        commodity.date.format("%Y-%m-%d"),
        commodity.currency
    )
    .unwrap();
    serialize_metadata(output, &commodity.metadata, include_envelope, "  ");
}

fn serialize_pad(output: &mut String, pad: &Pad, include_envelope: bool) {
    writeln!(
        output,
        "{} pad {} {}",
        pad.date.format("%Y-%m-%d"),
        pad.account,
        pad.source_account
    )
    .unwrap();
    serialize_metadata(output, &pad.metadata, include_envelope, "  ");
}

fn serialize_balance(output: &mut String, balance: &Balance, include_envelope: bool) {
    writeln!(
        output,
        "{} balance {} {} {}",
        balance.date.format("%Y-%m-%d"),
        balance.account,
        balance.amount.number,
        balance.amount.currency
    )
    .unwrap();
    serialize_metadata(output, &balance.metadata, include_envelope, "  ");
}

fn serialize_note(output: &mut String, note: &Note, include_envelope: bool) {
    writeln!(
        output,
        "{} note {} {}",
        note.date.format("%Y-%m-%d"),
        note.account,
        quote_string(&note.comment)
    )
    .unwrap();
    serialize_metadata(output, &note.metadata, include_envelope, "  ");
}

fn serialize_document(output: &mut String, document: &Document, include_envelope: bool) {
    writeln!(
        output,
        "{} document {} {}",
        document.date.format("%Y-%m-%d"),
        document.account,
        quote_string(&document.path)
    )
    .unwrap();
    serialize_metadata(output, &document.metadata, include_envelope, "  ");
}

fn serialize_event(output: &mut String, event: &Event, include_envelope: bool) {
    writeln!(
        output,
        "{} event {} {}",
        event.date.format("%Y-%m-%d"),
        quote_string(&event.event_type),
        quote_string(&event.description)
    )
    .unwrap();
    serialize_metadata(output, &event.metadata, include_envelope, "  ");
}

fn serialize_price(output: &mut String, price: &Price, include_envelope: bool) {
    writeln!(
        output,
        "{} price {} {} {}",
        price.date.format("%Y-%m-%d"),
        price.currency,
        price.amount.number,
        price.amount.currency
    )
    .unwrap();
    serialize_metadata(output, &price.metadata, include_envelope, "  ");
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Serialize metadata lines. BTreeMap iteration order is alphabetical by key.
fn serialize_metadata(
    output: &mut String,
    metadata: &Metadata,
    include_envelope: bool,
    indent: &str,
) {
    for (key, value) in metadata {
        if !include_envelope && key.starts_with("openledger-") {
            continue;
        }
        writeln!(output, "{indent}{key}: {}", quote_string(value)).unwrap();
    }
}

/// Double-quote a string, escaping `"` and `\` per §3.3.2.
fn quote_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 2);
    result.push('"');
    for character in s.chars() {
        match character {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            _ => result.push(character),
        }
    }
    result.push('"');
    result
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::parse_file;
    use chrono::NaiveDate;
    use rust_decimal_macros::dec;
    use std::collections::BTreeMap;

    fn make_date(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).unwrap()
    }

    // ── Column 52 alignment ──────────────────────────────────────────────

    #[test]
    fn test_posting_column_52_alignment() {
        let posting = Posting {
            account: "Assets:Cash".to_owned(),
            amount: Some(Amount {
                number: dec!(1000.00),
                currency: "USD".to_owned(),
            }),
            cost: None,
            price: None,
            metadata: BTreeMap::new(),
        };
        let mut output = String::new();
        serialize_posting(&mut output, &posting, false);

        // "  Assets:Cash" = 13 chars, gap = 38, number at column 52.
        let line = output.trim_end_matches('\n');
        assert_eq!(
            &line[51..58],
            "1000.00",
            "number must start at column 52 (index 51)"
        );
    }

    #[test]
    fn test_posting_long_account_minimum_gap() {
        let long_account = "Assets:VeryLongAccountNameThatExceedsFiftyCharacters:Sub";
        let posting = Posting {
            account: long_account.to_owned(),
            amount: Some(Amount {
                number: dec!(100),
                currency: "USD".to_owned(),
            }),
            cost: None,
            price: None,
            metadata: BTreeMap::new(),
        };
        let mut output = String::new();
        serialize_posting(&mut output, &posting, false);

        let line = output.trim_end_matches('\n');
        // Should have at least 2-space gap.
        let expected_prefix = format!("  {long_account}  ");
        assert!(
            line.starts_with(&expected_prefix),
            "long account must have at least 2-space gap"
        );
    }

    // ── Worked fixture (CT-3) ────────────────────────────────────────────

    #[test]
    fn test_economic_serialize_worked_fixture() {
        let txn = Transaction {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: Some("Acme Corp".to_owned()),
            narration: Some("Initial funding".to_owned()),
            tags: Vec::new(),
            links: Vec::new(),
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(1000.00),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening-Balances".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-1000.00),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        };

        let canonical = economic_canonical_serialize(&Directive::Transaction(txn));
        let expected = "\
2024-01-15 * \"Acme Corp\" \"Initial funding\"
  Assets:Cash                                      1000.00 USD
  Equity:Opening-Balances                          -1000.00 USD\n";

        assert_eq!(canonical, expected);
    }

    // ── Envelope exclusion ───────────────────────────────────────────────

    #[test]
    fn test_economic_serialize_excludes_envelope() {
        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "peer-1".to_owned());
        metadata.insert("openledger-lamport".to_owned(), "1".to_owned());
        metadata.insert("openledger-parents".to_owned(), "".to_owned());
        metadata.insert("category".to_owned(), "test".to_owned());

        let txn = Transaction {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Test".to_owned()),
            tags: Vec::new(),
            links: Vec::new(),
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata,
        };

        let economic = economic_canonical_serialize(&Directive::Transaction(txn));
        // Should include "category" but NOT any "openledger-*" keys.
        assert!(economic.contains("category: \"test\""));
        assert!(!economic.contains("openledger-"));
    }

    #[test]
    fn test_full_serialize_includes_envelope() {
        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), "peer-1".to_owned());

        let txn = Transaction {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Test".to_owned()),
            tags: Vec::new(),
            links: Vec::new(),
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata,
        };

        let full = full_file_serialize(&[Directive::Transaction(txn)], &[]);
        assert!(full.contains("openledger-author: \"peer-1\""));
    }

    // ── Tags and links sorted ────────────────────────────────────────────

    #[test]
    fn test_tags_and_links_sorted() {
        let txn = Transaction {
            date: make_date(2024, 1, 1),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Test".to_owned()),
            tags: vec!["zebra".to_owned(), "apple".to_owned()],
            links: vec!["z-link".to_owned(), "a-link".to_owned()],
            postings: vec![
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: dec!(100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Equity:Opening".to_owned(),
                    amount: Some(Amount {
                        number: dec!(-100),
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        };

        let output = economic_canonical_serialize(&Directive::Transaction(txn));
        let header = output.lines().next().unwrap();
        assert!(header.contains("#apple #zebra ^a-link ^z-link"));
    }

    // ── Directive ordering in full-file ──────────────────────────────────

    #[test]
    fn test_full_file_ordering() {
        let directives = vec![
            Directive::Close(Close {
                date: make_date(2024, 1, 1),
                account: "Expenses:Food".to_owned(),
                metadata: BTreeMap::new(),
            }),
            Directive::Open(Open {
                date: make_date(2024, 1, 1),
                account: "Assets:Cash".to_owned(),
                currencies: vec!["USD".to_owned()],
                metadata: BTreeMap::new(),
            }),
            Directive::Transaction(Transaction {
                date: make_date(2024, 1, 1),
                flag: Flag::Complete,
                payee: None,
                narration: Some("Test".to_owned()),
                tags: Vec::new(),
                links: Vec::new(),
                postings: vec![
                    Posting {
                        account: "Assets:Cash".to_owned(),
                        amount: Some(Amount {
                            number: dec!(100),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                        metadata: BTreeMap::new(),
                    },
                    Posting {
                        account: "Equity:Opening".to_owned(),
                        amount: Some(Amount {
                            number: dec!(-100),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                        metadata: BTreeMap::new(),
                    },
                ],
                metadata: BTreeMap::new(),
            }),
        ];

        let output = full_file_serialize(&directives, &[]);
        let lines: Vec<&str> = output.lines().collect();

        // open (priority 0) before transaction (priority 4) before close (priority 9).
        assert!(lines[0].contains("open"), "first should be open");
        let txn_line = lines.iter().position(|l| l.contains("* \"Test\"")).unwrap();
        let close_line = lines.iter().position(|l| l.contains("close")).unwrap();
        assert!(txn_line < close_line, "txn before close");
    }

    // ── Non-transaction serialization ────────────────────────────────────

    #[test]
    fn test_serialize_open_with_currencies() {
        let open = Open {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            currencies: vec!["USD".to_owned(), "EUR".to_owned()],
            metadata: BTreeMap::new(),
        };
        let output = economic_canonical_serialize(&Directive::Open(open));
        assert_eq!(output, "2024-01-01 open Assets:Cash USD, EUR\n");
    }

    #[test]
    fn test_serialize_balance() {
        let balance = Balance {
            date: make_date(2024, 2, 1),
            account: "Assets:Cash".to_owned(),
            amount: Amount {
                number: dec!(1000.00),
                currency: "USD".to_owned(),
            },
            metadata: BTreeMap::new(),
        };
        let output = economic_canonical_serialize(&Directive::Balance(balance));
        assert_eq!(output, "2024-02-01 balance Assets:Cash 1000.00 USD\n");
    }

    #[test]
    fn test_serialize_event() {
        let event = Event {
            date: make_date(2024, 1, 1),
            event_type: "location".to_owned(),
            description: "New York".to_owned(),
            metadata: BTreeMap::new(),
        };
        let output = economic_canonical_serialize(&Directive::Event(event));
        assert_eq!(output, "2024-01-01 event \"location\" \"New York\"\n");
    }

    #[test]
    fn test_serialize_price_directive() {
        let price = Price {
            date: make_date(2024, 1, 1),
            currency: "EUR".to_owned(),
            amount: Amount {
                number: dec!(1.10),
                currency: "USD".to_owned(),
            },
            metadata: BTreeMap::new(),
        };
        let output = economic_canonical_serialize(&Directive::Price(price));
        assert_eq!(output, "2024-01-01 price EUR 1.10 USD\n");
    }

    // ── Cost and price serialization ─────────────────────────────────────

    #[test]
    fn test_serialize_posting_with_cost() {
        let posting = Posting {
            account: "Assets:Stock".to_owned(),
            amount: Some(Amount {
                number: dec!(10),
                currency: "AAPL".to_owned(),
            }),
            cost: Some(CostSpec {
                amount: Some(Amount {
                    number: dec!(150.00),
                    currency: "USD".to_owned(),
                }),
                date: None,
            }),
            price: None,
            metadata: BTreeMap::new(),
        };
        let mut output = String::new();
        serialize_posting(&mut output, &posting, false);
        assert!(output.contains("10 AAPL {150.00 USD}"));
    }

    #[test]
    fn test_serialize_posting_with_price() {
        let posting = Posting {
            account: "Assets:Foreign".to_owned(),
            amount: Some(Amount {
                number: dec!(100.00),
                currency: "EUR".to_owned(),
            }),
            cost: None,
            price: Some(PriceSpec::Unit(Amount {
                number: dec!(1.10),
                currency: "USD".to_owned(),
            })),
            metadata: BTreeMap::new(),
        };
        let mut output = String::new();
        serialize_posting(&mut output, &posting, false);
        assert!(output.contains("100.00 EUR @ 1.10 USD"));
    }

    #[test]
    fn test_serialize_elided_posting() {
        let posting = Posting {
            account: "Equity:Opening".to_owned(),
            amount: None,
            cost: None,
            price: None,
            metadata: BTreeMap::new(),
        };
        let mut output = String::new();
        serialize_posting(&mut output, &posting, false);
        assert_eq!(output, "  Equity:Opening\n");
    }

    // ── String escaping ──────────────────────────────────────────────────

    #[test]
    fn test_quote_string_escaping() {
        assert_eq!(quote_string("hello"), "\"hello\"");
        assert_eq!(quote_string("say \"hi\""), "\"say \\\"hi\\\"\"");
        assert_eq!(quote_string("path\\to"), "\"path\\\\to\"");
    }

    // ── Leading comments ─────────────────────────────────────────────────

    #[test]
    fn test_full_file_with_leading_comments() {
        let open = Open {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            currencies: Vec::new(),
            metadata: BTreeMap::new(),
        };
        let output = full_file_serialize(&[Directive::Open(open)], &["Header comment".to_owned()]);
        assert!(output.starts_with("; Header comment\n\n"));
        assert!(output.contains("open Assets:Cash"));
    }

    // ── Round-trip: serialize → parse → compare (CT-5) ───────────────────

    #[test]
    fn test_round_trip_serialize_parse() {
        let directives = vec![
            Directive::Open(Open {
                date: make_date(2024, 1, 1),
                account: "Assets:Cash".to_owned(),
                currencies: vec!["USD".to_owned()],
                metadata: BTreeMap::new(),
            }),
            Directive::Transaction(Transaction {
                date: make_date(2024, 1, 15),
                flag: Flag::Complete,
                payee: Some("Acme".to_owned()),
                narration: Some("Funding".to_owned()),
                tags: vec!["setup".to_owned()],
                links: vec!["ref-1".to_owned()],
                postings: vec![
                    Posting {
                        account: "Assets:Cash".to_owned(),
                        amount: Some(Amount {
                            number: dec!(1000.00),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                        metadata: BTreeMap::new(),
                    },
                    Posting {
                        account: "Equity:Opening".to_owned(),
                        amount: Some(Amount {
                            number: dec!(-1000.00),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                        metadata: BTreeMap::new(),
                    },
                ],
                metadata: BTreeMap::new(),
            }),
            Directive::Balance(Balance {
                date: make_date(2024, 2, 1),
                account: "Assets:Cash".to_owned(),
                amount: Amount {
                    number: dec!(1000.00),
                    currency: "USD".to_owned(),
                },
                metadata: BTreeMap::new(),
            }),
        ];

        let serialized = full_file_serialize(&directives, &[]);
        let reparsed = parse_file(&serialized).unwrap();

        assert_eq!(
            directives.len(),
            reparsed.len(),
            "directive count mismatch after round-trip"
        );

        for (original, parsed) in directives.iter().zip(reparsed.iter()) {
            assert_eq!(
                original, parsed,
                "directive mismatch after round-trip:\n  serialized text:\n{serialized}"
            );
        }
    }

    // ── Golden fixture round-trip (CT-6) ─────────────────────────────────

    #[test]
    fn test_golden_fixture_round_trip() {
        let fixture = include_str!("../../../testfixtures/fixture-simple.bean");
        let directives = parse_file(fixture).unwrap();
        let serialized = full_file_serialize(&directives, &[]);
        let reparsed = parse_file(&serialized).unwrap();

        assert_eq!(directives.len(), reparsed.len(), "directive count mismatch");
        for (index, (original, parsed)) in directives.iter().zip(reparsed.iter()).enumerate() {
            assert_eq!(
                original.date(),
                parsed.date(),
                "date mismatch at directive {index}"
            );
            assert_eq!(
                original.type_priority(),
                parsed.type_priority(),
                "type mismatch at directive {index}"
            );
        }
    }

    // ── Metadata sort order ──────────────────────────────────────────────

    #[test]
    fn test_metadata_sorted_alphabetically() {
        let mut metadata = BTreeMap::new();
        metadata.insert("zebra".to_owned(), "z".to_owned());
        metadata.insert("alpha".to_owned(), "a".to_owned());
        metadata.insert("middle".to_owned(), "m".to_owned());

        let open = Open {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            currencies: Vec::new(),
            metadata,
        };
        let output = economic_canonical_serialize(&Directive::Open(open));
        let lines: Vec<&str> = output.lines().collect();
        assert!(
            lines[1].contains("alpha:"),
            "alpha should be first metadata"
        );
        assert!(lines[2].contains("middle:"), "middle should be second");
        assert!(lines[3].contains("zebra:"), "zebra should be last");
    }

    // ── CT-13: Envelope idempotency ──────────────────────────────────────

    #[test]
    fn test_ct13_envelope_idempotency() {
        // Same economic body, different envelope → same economic canonical form.
        let make_txn = |author: &str, lamport: &str| -> Transaction {
            let mut metadata = BTreeMap::new();
            metadata.insert("openledger-author".to_owned(), author.to_owned());
            metadata.insert("openledger-lamport".to_owned(), lamport.to_owned());
            Transaction {
                date: make_date(2024, 1, 15),
                flag: Flag::Complete,
                payee: Some("Acme".to_owned()),
                narration: Some("Test".to_owned()),
                tags: Vec::new(),
                links: Vec::new(),
                postings: vec![
                    Posting {
                        account: "Assets:Cash".to_owned(),
                        amount: Some(Amount {
                            number: dec!(100),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                        metadata: BTreeMap::new(),
                    },
                    Posting {
                        account: "Equity:Opening".to_owned(),
                        amount: Some(Amount {
                            number: dec!(-100),
                            currency: "USD".to_owned(),
                        }),
                        cost: None,
                        price: None,
                        metadata: BTreeMap::new(),
                    },
                ],
                metadata,
            }
        };

        let txn_a = make_txn("peer-1", "1");
        let txn_b = make_txn("peer-2", "42");

        let canonical_a = economic_canonical_serialize(&Directive::Transaction(txn_a));
        let canonical_b = economic_canonical_serialize(&Directive::Transaction(txn_b));

        assert_eq!(
            canonical_a, canonical_b,
            "envelope differences must not affect economic form"
        );
    }
}
