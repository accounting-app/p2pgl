//! Canonical serializer for Beancount directives (§3.3.2).
//!
//! Two modes:
//! - [`economic_canonical_serialize`]: single directive, no `openledger-*` metadata — for hashing.
//! - [`full_file_serialize`]: all directives, ordered, with envelope metadata — for `.bean` persistence.

use std::fmt::Write;

use chrono::NaiveDate;

use crate::hash::compute_content_id;
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

    // Sort by (date, type priority, stable sort key, content id) — see
    // [`canonical_order`]. The last component is M-24's; the first three are
    // §3.3.2 unchanged.
    let sorted_indices = canonical_order(directives);

    // Emit directives with blank lines between.
    for (index, &directive_index) in sorted_indices.iter().enumerate() {
        if index > 0 || !leading_comments.is_empty() {
            output.push('\n'); // blank line separator
        }
        serialize_directive(&mut output, &directives[directive_index], true);
    }

    output
}

// ─── Canonical order (§3.3.2 + M-24) ─────────────────────────────────────────

/// One directive decorated with its §3.3.2 sort position.
///
/// Built once per directive rather than once per comparison (the pre-M-24
/// comparator formatted two [`stable_sort_key`] strings on every compare).
struct OrderKey {
    date: NaiveDate,
    priority: u8,
    stable_key: String,
    /// Index into the caller's slice — carried, never compared.
    index: usize,
}

impl OrderKey {
    /// The §3.3.2 part of the key. Two directives agreeing here are a TIE, and
    /// a tie is the only thing M-24's discriminator is allowed to touch.
    fn primary(&self) -> (NaiveDate, u8, &str) {
        (self.date, self.priority, self.stable_key.as_str())
    }
}

/// The canonical order of `directives`, as indices into the slice.
///
/// The key is §3.3.2's ordering with one component appended (M-24):
///
/// ```text
/// (date, type priority, stable sort key, content id)
/// ```
///
/// and it is TOTAL by construction — which is the whole point. This mirrors
/// [`crate::accounts::LifecycleKey`], whose final component is the content id
/// for exactly the same reason (M-09).
///
/// ## Why the fourth component exists
///
/// [`stable_sort_key`] is not injective: for a transaction it is
/// `narration|payee`, which omits the postings, the amounts and the
/// currencies; for an `open` it is the account, which omits the currency list.
/// Two coffees bought from the same shop on the same day tie, and so do two
/// same-date `open Assets:Cash` with different currency lists — ORDINARY data,
/// no attacker. `sort_by` is a STABLE sort, so a tie fell through to the input
/// order, and on the persist path the input is `LedgerDag::insertion_order`,
/// i.e. ARRIVAL order. Two replicas holding the same directive set but having
/// received it in different orders therefore wrote different `.bean` bytes,
/// violating I7/C4 — the invariant `ct9_two_nodes_converge_after_partition`
/// states as *"After convergence, .bean files must be byte-identical"* — and
/// they did so permanently, because a reboot re-derives insertion order from
/// the file's own order, so each node re-persists its own divergence forever.
///
/// ## Why the content id, and nothing else
///
/// It is a pure function of the directive's economic body, so every replica
/// computes the same one for the same directive, and it is already the DAG's
/// notion of identity. The alternatives are all replica-local and must never
/// enter the key: arrival order and file position are accidents of transport,
/// and the envelope Lamport (which [`crate::accounts::LifecycleKey`] can
/// afford, because it orders one account's events) may differ per replica for
/// one content id under M-10.
///
/// ## Why the primary ordering is untouched
///
/// §3.3.2's (date, type priority, stable key) ordering is read well beyond this
/// function — boot's canonical order, `reconcile_content`'s sort, T44's journal
/// — so this appends a final discriminator to EXACT ties; it does not re-sort
/// the ledger. `test_m24_tie_free_file_is_byte_identical_to_the_pre_fix_serializer`
/// pins that with a golden captured from the pre-fix serializer.
///
/// ## Cost
///
/// The content id is a SHA-256 over a second serialization of the directive, so
/// it is computed for the members of a tie run and for nobody else: a tie-free
/// file pays nothing new, and it pays less than before, since decorating costs
/// n key strings where the old comparator cost 2 per comparison.
fn canonical_order(directives: &[Directive]) -> Vec<usize> {
    let mut order: Vec<OrderKey> = directives
        .iter()
        .enumerate()
        .map(|(index, directive)| OrderKey {
            date: directive.date(),
            priority: directive.type_priority(),
            stable_key: stable_sort_key(directive),
            index,
        })
        .collect();
    order.sort_by(|a, b| a.primary().cmp(&b.primary()));

    // Break the exact ties, and only those. Equal primaries are adjacent after
    // the sort above, so each run is one tie.
    let mut start = 0;
    while start < order.len() {
        let mut end = start + 1;
        while end < order.len() && order[end].primary() == order[start].primary() {
            end += 1;
        }
        if end - start > 1 {
            order[start..end].sort_by_cached_key(|key| tie_break_key(&directives[key.index]));
        }
        start = end;
    }

    order.into_iter().map(|key| key.index).collect()
}

/// The discriminator that makes the canonical order total (M-24).
///
/// The content id comes first: it is the envelope-independent half, so replicas
/// that disagree about an envelope (M-10) still agree about the order. The
/// emitted bytes come second so the key is total over what this function
/// actually decides — OUTPUT BYTES — even for a caller holding two entries with
/// one content id and different envelopes. The production path cannot build
/// that slice (`compaction_directives`' quarantine arm drops any entry whose id
/// the DAG already holds), but [`full_file_serialize`] is public, and a
/// totality that rests on a caller's invariant is precisely what M-24 was.
fn tie_break_key(directive: &Directive) -> (String, String) {
    let mut emitted = String::new();
    serialize_directive(&mut emitted, directive, true);
    (compute_content_id(directive), emitted)
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
            // Payee without narration: emit an explicit empty narration slot so
            // this does not collide with a narration-only transaction carrying
            // the same string (L5). `"payee" ""` re-parses to payee + empty
            // narration, which serializes back to the same bytes (hash-stable);
            // the two are the same transaction, so that is correct.
            write!(output, " {} {}", quote_string(payee), quote_string("")).unwrap();
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
    use crate::hash::compute_content_id;
    use crate::parse::parse_file;
    use chrono::NaiveDate;
    use rust_decimal::Decimal;
    use rust_decimal_macros::dec;
    use std::collections::BTreeMap;

    fn make_date(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).unwrap()
    }

    // ── L-15: the two injectivity holes, demonstrated ────────────────────
    //
    // These are MECHANISM tests, not regressions: they pin that the serializer
    // still collapses both shapes, which is exactly why L-15 is closed by
    // REJECTING them at every ingress rather than by changing the emitted
    // bytes. The serialized form is the content-hash input, so a new spelling
    // for `{}`-with-a-date or for an elided-posting-with-a-cost would change
    // the id of nothing (both shapes are now unreachable) while risking the id
    // of everything. See `service::validate_posting_annotations`.

    fn elided(account: &str, cost: Option<CostSpec>, price: Option<PriceSpec>) -> Posting {
        Posting {
            account: account.to_owned(),
            amount: None,
            cost,
            price,
            metadata: BTreeMap::new(),
        }
    }

    #[test]
    fn test_l15_elided_posting_swallows_its_cost_and_price() {
        // (a) The whole `{...}`/`@` block sits inside `if let Some(amount)`, so
        // an elided posting emits its account name and nothing else — three
        // materially different postings, one line of output.
        let bare = elided("Assets:Stock", None, None);
        let with_cost = elided(
            "Assets:Stock",
            Some(CostSpec {
                amount: Some(Amount {
                    number: dec!(150),
                    currency: "USD".to_owned(),
                }),
                date: None,
            }),
            None,
        );
        let with_price = elided(
            "Assets:Stock",
            None,
            Some(PriceSpec::Unit(Amount {
                number: dec!(1.10),
                currency: "USD".to_owned(),
            })),
        );
        assert_ne!(bare, with_cost);
        assert_ne!(bare, with_price);

        let render = |posting: &Posting| {
            let mut output = String::new();
            serialize_posting(&mut output, posting, false);
            output
        };
        assert_eq!(render(&bare), "  Assets:Stock\n");
        assert_eq!(
            render(&bare),
            render(&with_cost),
            "distinct postings must not share a serialization"
        );
        assert_eq!(render(&bare), render(&with_price));
    }

    #[test]
    fn test_l15_empty_cost_swallows_its_date() {
        // (b) `cost.date` is written inside `if let Some(cost_amount)`, so an
        // amount-less `CostSpec` drops its date and emits a bare `{}`.
        let dated = Posting {
            account: "Assets:Stock".to_owned(),
            amount: Some(Amount {
                number: dec!(10),
                currency: "AAPL".to_owned(),
            }),
            cost: Some(CostSpec {
                amount: None,
                date: Some(make_date(2020, 3, 4)),
            }),
            price: None,
            metadata: BTreeMap::new(),
        };
        let undated = Posting {
            cost: Some(CostSpec {
                amount: None,
                date: None,
            }),
            ..dated.clone()
        };
        assert_ne!(dated, undated);

        let render = |posting: &Posting| {
            let mut output = String::new();
            serialize_posting(&mut output, posting, false);
            output
        };
        assert!(render(&dated).contains(" {}"));
        assert!(
            !render(&dated).contains("2020-03-04"),
            "the date is silently dropped"
        );
        assert_eq!(render(&dated), render(&undated));
    }

    #[test]
    fn test_l15_collapsed_shapes_share_a_content_id() {
        // Why the holes matter: `compute_content_id` hashes the serialized
        // economic form, so two distinct directives get ONE id. In a G-Set DAG
        // keyed by that id the second arrival is a no-op "duplicate", and a
        // signature made over one body authenticates the other.
        let base = Transaction {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: None,
            narration: Some("Collision".to_owned()),
            tags: vec![],
            links: vec![],
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
                elided("Equity:Opening", None, None),
            ],
            metadata: BTreeMap::new(),
        };
        let mut annotated = base.clone();
        annotated.postings[1].cost = Some(CostSpec {
            amount: Some(Amount {
                number: dec!(150),
                currency: "USD".to_owned(),
            }),
            date: None,
        });
        assert_ne!(base, annotated);
        assert_eq!(
            crate::hash::compute_content_id(&Directive::Transaction(base)),
            crate::hash::compute_content_id(&Directive::Transaction(annotated)),
            "two distinct transactions must not share a content id"
        );
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

    // ── Payee/narration injectivity (L5) ─────────────────────────────────

    fn balanced_txn(payee: Option<&str>, narration: Option<&str>) -> Directive {
        Directive::Transaction(Transaction {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: payee.map(str::to_owned),
            narration: narration.map(str::to_owned),
            tags: vec![],
            links: vec![],
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
        })
    }

    #[test]
    fn test_payee_only_distinct_from_narration_only() {
        // L5 regression: a payee-only transaction must not hash-collide with a
        // narration-only transaction carrying the same string.
        use crate::hash::compute_content_id;
        let payee_only = balanced_txn(Some("Acme"), None);
        let narration_only = balanced_txn(None, Some("Acme"));
        assert_ne!(
            compute_content_id(&payee_only),
            compute_content_id(&narration_only),
            "payee-only and narration-only with the same string must have distinct txids"
        );
    }

    #[test]
    fn test_payee_only_hash_stable_across_reparse() {
        // The `"payee" ""` form round-trips: re-parsing and re-serializing must
        // produce the same content id (payee + empty narration is the same
        // transaction as payee-only).
        use crate::hash::compute_content_id;
        let payee_only = balanced_txn(Some("Acme"), None);
        let id_before = compute_content_id(&payee_only);

        let body = economic_canonical_serialize(&payee_only);
        let reparsed = parse_file(&body).expect("payee-only body must re-parse");
        assert_eq!(reparsed.len(), 1);
        assert_eq!(
            compute_content_id(&reparsed[0]),
            id_before,
            "content id must be stable across a persist/reload round-trip"
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
    // ── M-24: the canonical order must be TOTAL ──────────────────────────
    //
    // `stable_sort_key` is `narration|payee` for a transaction and the account
    // for an `open`, so it omits the postings, the amounts and the currency
    // list — and `sort_by` is a STABLE sort, so before the fix a tie fell
    // through to the INPUT order. On the persist path the input is
    // `LedgerDag::insertion_order`, i.e. ARRIVAL order, so two replicas holding
    // the same directive set wrote different `.bean` bytes purely because the
    // directives reached them in different orders. That breaks I7/C4 — the
    // invariant `ct9_two_nodes_converge_after_partition` states as *"After
    // convergence, .bean files must be byte-identical"* — and it is permanent,
    // because a reboot re-derives insertion order from the file's own order, so
    // each node re-persists its own divergence forever.
    //
    // Both tie shapes below are ORDINARY data: no attacker, no collision
    // engineering. Each test builds the same set in both arrival orders and
    // demands one file, which is exactly what convergence asserts.

    /// Two coffees from the same shop on the same day — identical payee and
    /// narration, different amounts. The §3.3.2 key is `Coffee|Starbucks` for
    /// both.
    fn coffee(amount: Decimal) -> Directive {
        Directive::Transaction(Transaction {
            date: make_date(2024, 3, 7),
            flag: Flag::Complete,
            payee: Some("Starbucks".to_owned()),
            narration: Some("Coffee".to_owned()),
            tags: Vec::new(),
            links: Vec::new(),
            postings: vec![
                Posting {
                    account: "Expenses:Food".to_owned(),
                    amount: Some(Amount {
                        number: amount,
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
                Posting {
                    account: "Assets:Cash".to_owned(),
                    amount: Some(Amount {
                        number: -amount,
                        currency: "USD".to_owned(),
                    }),
                    cost: None,
                    price: None,
                    metadata: BTreeMap::new(),
                },
            ],
            metadata: BTreeMap::new(),
        })
    }

    /// A same-date `open` of one account with a given currency list.
    fn open_cash(currencies: &[&str]) -> Directive {
        Directive::Open(Open {
            date: make_date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            currencies: currencies.iter().map(|c| (*c).to_owned()).collect(),
            metadata: BTreeMap::new(),
        })
    }

    /// The two arrival orders of a two-directive set must produce ONE file.
    ///
    /// Asserted on the whole serialized string, not on a digest or a line
    /// count: byte-identity is the invariant, so bytes are what is compared,
    /// and a failure prints both files so the divergence is visible.
    fn assert_one_file_under_both_arrival_orders(
        first: &Directive,
        second: &Directive,
        what: &str,
    ) {
        let forward = full_file_serialize(&[first.clone(), second.clone()], &[]);
        let reverse = full_file_serialize(&[second.clone(), first.clone()], &[]);
        assert_eq!(
            forward, reverse,
            "M-24: {what} must serialize to the same bytes whatever order they \
             arrived in (I7/C4)\n── arrival order A,B ──\n{forward}\n── arrival \
             order B,A ──\n{reverse}"
        );
    }

    /// The tied pair must be emitted in CONTENT ID order, not in some other
    /// consistent order: the content id is the one discriminator every replica
    /// computes identically (arrival order, file position and the envelope
    /// Lamport are all replica-local — see M-10).
    fn assert_emitted_in_content_id_order(first: &Directive, second: &Directive) {
        let (low, high) = if compute_content_id(first) <= compute_content_id(second) {
            (first, second)
        } else {
            (second, first)
        };
        let file = full_file_serialize(&[first.clone(), second.clone()], &[]);
        // These fixtures carry no envelope metadata, so a directive's economic
        // form is byte-for-byte the block it occupies in the file.
        let position = |directive: &Directive| {
            file.find(&economic_canonical_serialize(directive))
                .expect("each directive appears in the file it was serialized from")
        };
        assert!(
            position(low) < position(high),
            "the smaller content id must be emitted first:\n{file}"
        );
    }

    #[test]
    fn test_m24_same_day_same_payee_transactions_are_order_insensitive() {
        let small = coffee(dec!(4.50));
        let large = coffee(dec!(6.25));
        assert_ne!(
            compute_content_id(&small),
            compute_content_id(&large),
            "the two coffees are distinct directives"
        );
        assert_eq!(
            stable_sort_key(&small),
            stable_sort_key(&large),
            "mechanism: the §3.3.2 key alone ties — amounts are not in it"
        );
        assert_one_file_under_both_arrival_orders(&small, &large, "two same-day coffees");
    }

    #[test]
    fn test_m24_same_date_opens_with_different_currencies_are_order_insensitive() {
        let usd = open_cash(&["USD"]);
        let eur = open_cash(&["EUR", "GBP"]);
        assert_ne!(compute_content_id(&usd), compute_content_id(&eur));
        assert_eq!(
            stable_sort_key(&usd),
            stable_sort_key(&eur),
            "mechanism: the §3.3.2 key for an `open` is the account alone"
        );
        assert_one_file_under_both_arrival_orders(&usd, &eur, "two same-date opens of one account");
    }

    #[test]
    fn test_m24_tie_break_is_the_content_id() {
        assert_emitted_in_content_id_order(&coffee(dec!(4.50)), &coffee(dec!(6.25)));
        assert_emitted_in_content_id_order(&open_cash(&["USD"]), &open_cash(&["EUR", "GBP"]));
    }

    #[test]
    fn test_m24_one_content_id_under_two_envelopes_still_has_one_order() {
        // The residual the emitted bytes close. Envelope metadata is outside
        // the content id — that is L-17's premise — so two entries can share an
        // id and still produce different bytes. `compaction_directives` cannot
        // build that slice (its quarantine arm drops any entry whose id the DAG
        // already holds), but `full_file_serialize` is public, and a totality
        // that rests on a caller's invariant is precisely what M-24 was.
        let stamped = |author: &str| -> Directive {
            let mut metadata = BTreeMap::new();
            metadata.insert("openledger-author".to_owned(), author.to_owned());
            Directive::Open(Open {
                date: make_date(2024, 1, 1),
                account: "Assets:Cash".to_owned(),
                currencies: vec!["USD".to_owned()],
                metadata,
            })
        };
        let peer_1 = stamped("peer-1");
        let peer_2 = stamped("peer-2");
        assert_eq!(
            compute_content_id(&peer_1),
            compute_content_id(&peer_2),
            "the envelope is outside the content id, so these tie on it too"
        );
        assert_one_file_under_both_arrival_orders(
            &peer_1,
            &peer_2,
            "one content id under two envelopes",
        );
    }

    #[test]
    fn test_m24_every_arrival_order_of_a_tied_set_yields_one_file() {
        // Ties of more than two members, and two independent tie runs in one
        // file: a discriminator that only fixed adjacent pairs would still
        // diverge here. Every permutation is an arrival order a replica can
        // legitimately see.
        let directives = vec![
            coffee(dec!(4.50)),
            coffee(dec!(6.25)),
            coffee(dec!(3.00)),
            open_cash(&["USD"]),
            open_cash(&["EUR", "GBP"]),
        ];
        let reference = full_file_serialize(&directives, &[]);
        let orders = permutations(&directives);
        assert_eq!(orders.len(), 120, "5 directives have 120 arrival orders");
        for order in orders {
            let file = full_file_serialize(&order, &[]);
            assert_eq!(
                file, reference,
                "M-24: an arrival order changed the file\n── reference ──\n{reference}\n── this order ──\n{file}"
            );
        }
    }

    /// Every ordering of `items`.
    fn permutations(items: &[Directive]) -> Vec<Vec<Directive>> {
        if items.len() <= 1 {
            return vec![items.to_vec()];
        }
        let mut orders = Vec::new();
        for index in 0..items.len() {
            let mut rest = items.to_vec();
            let chosen = rest.remove(index);
            for mut tail in permutations(&rest) {
                tail.insert(0, chosen.clone());
                orders.push(tail);
            }
        }
        orders
    }

    #[test]
    fn test_m24_tie_free_file_is_byte_identical_to_the_pre_fix_serializer() {
        // THE SAFETY PROPERTY. M-24 appends a discriminator to break exact
        // ties; it must change NOTHING else. §3.3.2's (date, type priority,
        // stable key) ordering is load-bearing well beyond this file — boot's
        // canonical order, `reconcile_content`'s sort and T44's journal all
        // read the same order — so re-sorting the ledger would be a far larger
        // change than the bug.
        //
        // `GOLDEN_TIE_FREE` is the output of the PRE-FIX serializer for the
        // golden fixture, captured verbatim before the change. The fixture is
        // tie-free (asserted below, so the golden keeps meaning what it says),
        // and a tie-free set must therefore serialize to exactly these bytes.
        let fixture = include_str!("../../../testfixtures/fixture-simple.bean");
        let directives = parse_file(fixture).unwrap();

        let mut keys: Vec<(NaiveDate, u8, String)> = directives
            .iter()
            .map(|d| (d.date(), d.type_priority(), stable_sort_key(d)))
            .collect();
        keys.sort();
        let distinct = {
            let mut deduped = keys.clone();
            deduped.dedup();
            deduped.len()
        };
        assert_eq!(
            keys.len(),
            distinct,
            "the golden fixture must be tie-free for this golden to prove anything"
        );

        assert_eq!(
            full_file_serialize(&directives, &[]),
            GOLDEN_TIE_FREE,
            "a tie-free set must serialize exactly as it did before M-24"
        );
    }

    /// The pre-M-24 serialization of `testfixtures/fixture-simple.bean`.
    const GOLDEN_TIE_FREE: &str = r#"2024-01-01 open Assets:Cash USD, EUR

2024-01-01 open Assets:Stock AAPL

2024-01-01 open Equity:Opening USD

2024-01-01 open Expenses:Food USD

2024-01-01 open Income:Salary USD

2024-01-01 commodity EUR

2024-01-01 pad Assets:Cash Equity:Opening

2024-01-15 * "Acme Corp" "Initial funding" #setup ^opening-001
  openledger-author: "local"
  openledger-lamport: "1"
  openledger-parents: ""
  Assets:Cash                                      1000.00 USD
  Equity:Opening                                   -1000.00 USD

2024-01-20 ! "Pending refund"
  openledger-author: "local"
  openledger-lamport: "2"
  openledger-parents: "dd4a9ec5ec298be6edaa02c4408c0b1cb1b25eb51426599b7eda600cfc5fa88f"
  Assets:Cash                                      25.00 USD
  Expenses:Food                                    -25.00 USD

2024-02-01 balance Assets:Cash 1025.00 USD

2024-03-01 note Assets:Cash "Reconciled with bank statement"

2024-03-01 document Assets:Cash "/statements/2024-Q1.pdf"

2024-06-01 event "location" "San Francisco"

2024-06-15 * "Buy stock"
  Assets:Stock                                     10 AAPL {150.00 USD}
  Assets:Cash                                      -1500.00 USD

2024-12-01 price EUR 1.10 USD

2024-12-31 close Expenses:Food
"#;
}
