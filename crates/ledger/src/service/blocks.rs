//! The ledger file block by block: splitting, the per-block salvage of what does
//! not parse, and the parent-cycle scan.

use super::*;

/// One source block of a `.bean` file: a header line at column 0 plus the
/// indented lines that belong to it (L-45).
///
/// The unit [`parse_file`] succeeds or fails at, kept as **exact source text**
/// so a block this node cannot parse can still be written back verbatim.
#[derive(Debug, Clone)]
pub(super) struct LedgerBlock {
    /// 1-based line number of the block's first line, for the operator.
    pub(super) line: usize,
    /// The block's source text, newline-terminated.
    pub(super) text: String,
    /// The block begins on the line right after the previous block's last
    /// line — no blank line, no comment line between them (H-20).
    ///
    /// A canonical file separates every directive with a blank line, so a
    /// block that starts *without* one is not a directive of its own: it is
    /// the rest of the block above, cut off by a line that lost its indent
    /// (a dedent, a BOM glued to a posting, a stray word). See
    /// [`salvage_unparsable_blocks`].
    pub(super) contiguous_with_previous: bool,
}

/// Split ledger text into the blocks [`parse_file`] reads it as (L-45).
///
/// A deliberate re-statement of `parse_file`'s outer loop — header at column 0,
/// then every indented non-blank line until a blank line or the next header —
/// and nothing else: it does not tokenize, does not validate, and cannot fail.
/// Splitting is what makes a *partial* parse possible, because `parse_file`
/// accumulates errors across the whole file and then throws away the directives
/// it did parse.
///
/// The blocks are independent by construction (the parser carries no state
/// across them), so `parse_file(block.text)` yields exactly the directive
/// `parse_file` over the whole file would have yielded for those lines, and the
/// blocks in order yield the whole file's directives in order. A leading
/// byte-order mark is stripped first, for the same reason `parse_file` strips
/// one (L-28).
///
/// Line endings are normalised to `\n` because `str::lines` is what both this
/// and the parser split on. A CRLF file therefore round-trips through the
/// quarantine as LF, which is what every other line this serializer writes uses
/// anyway.
pub(super) fn split_ledger_blocks(content: &str) -> Vec<LedgerBlock> {
    let content = crate::parse::strip_byte_order_mark(content);
    let lines: Vec<&str> = content.lines().collect();
    let mut blocks = Vec::new();
    let mut index = 0;
    // Index one past the previous block's last line, for `contiguous_with_previous`.
    let mut previous_end: Option<usize> = None;

    while index < lines.len() {
        let line = lines[index];
        let trimmed = line.trim();

        // Blank and comment-only lines belong to no block — exactly as
        // `parse_file` skips them. Leading comments are re-emitted by the
        // serializer from `LedgerService::leading_comments`; interior ones are
        // not preserved by a canonical rewrite and never were.
        if trimmed.is_empty() || trimmed.starts_with(';') {
            index += 1;
            continue;
        }

        let start = index;
        let contiguous_with_previous = previous_end == Some(start);
        index += 1;
        // An indented line with no header above it is its own one-line block:
        // `parse_file` reports "Unexpected indented line without a preceding
        // directive" for it and advances by one, so keeping the same shape here
        // keeps the two in step.
        if !line.starts_with(' ') && !line.starts_with('\t') {
            while index < lines.len() {
                let body_line = lines[index];
                if body_line.is_empty()
                    || !(body_line.starts_with(' ') || body_line.starts_with('\t'))
                {
                    break;
                }
                index += 1;
            }
        }

        let mut text = lines[start..index].join("\n");
        text.push('\n');
        blocks.push(LedgerBlock {
            line: start + 1,
            text,
            contiguous_with_previous,
        });
        previous_end = Some(index);
    }

    blocks
}

/// A block boot could not parse, with the reason (L-45).
#[derive(Debug, Clone)]
pub(super) struct UnparsableBlock {
    pub(super) line: usize,
    pub(super) text: String,
    pub(super) reason: String,
}

/// Parse a ledger file block by block, keeping what parses and the raw text of
/// what does not (L-45).
///
/// ## The finding
///
/// T37 tightened the account grammar to ASCII (L-25's confusable-account fix).
/// Before it, **both** the parser and `validate_account_name` used Unicode
/// `char::is_alphanumeric`, so `Assets:Cаsh` with a Cyrillic `а` was a name this
/// system would store, persist **and replicate**. At HEAD `parse_file` refuses
/// it, `boot` propagates the parse error, and `gl-node`'s `main` turns that into
/// `exit(1)`. Any deployment that ever booked — or merely *received* from a peer
/// — such a name cannot start after the upgrade, and the only diagnostic is a
/// parse error on a line the operator did not write.
///
/// That is the failure mode T35 removed from L-17 and T41 declined to
/// reintroduce for the fan-in cap: **boot must never brick on a file the node
/// can otherwise read.** A brick is not even the conservative choice here — the
/// node is down, the ledger is unserved, and the fix requires hand-editing a
/// file the node no longer protects.
///
/// ## Why not loosen the charset back
///
/// Because the charset is the fix. L-25 is a forgery finding: two account names
/// no reviewer can tell apart are two identities, and they key the read model,
/// every I3/I9 lifecycle check and the content id. Accepting them again to make
/// boot work would trade a availability bug for an integrity one.
///
/// ## Scope: any parse failure, not just the charset
///
/// The salvage is written against the *block*, not against a specific error, so
/// a truncated final transaction, a half-typed line left by a crashed editor, or
/// a directive written by a future format version get the same treatment. That
/// is deliberate: the property worth having is "boot loads everything it can
/// read and destroys nothing it cannot", and a rule that enumerated error kinds
/// would have to be extended every time the grammar tightens again — which is
/// precisely the mistake this finding is.
///
/// ## A split block is held whole, never loaded truncated (H-20 door (b))
///
/// [`split_ledger_blocks`] starts a new block at any non-indented line, so a
/// stray dedent, a BOM glued to a posting or a stray word *inside* a
/// node-written transaction cuts it in two: a head (header, envelope, some
/// postings) that parses as a complete transaction, and a tail that does not.
/// Loading the head is loading a **different record** — one posting, its
/// counter-posting gone — under the original envelope and a new content id;
/// the audit showed `+100` kept and `−100` dropped while the banner said
/// nothing was lost. An unparsable block with no blank line before it belongs
/// to the block above (a canonical file separates directives with blank
/// lines), so the parsed head is **demoted** into the same raw
/// [`UnparsableBlock`] as its tail: one text, the head's line number, the
/// tail's reason. A run of contiguous unparsable blocks joins the same one.
///
/// Costs nothing on a well-formed file: `boot` only calls this after
/// `parse_file` over the whole text has already failed.
pub(super) fn salvage_unparsable_blocks(content: &str) -> (Vec<Directive>, Vec<UnparsableBlock>) {
    let mut directives: Vec<Directive> = Vec::new();
    let mut refused: Vec<UnparsableBlock> = Vec::new();
    // The previous block, if it parsed: the number of directives it
    // contributed (so a demotion can take them back) and its source.
    let mut previous_parsed: Option<(usize, LedgerBlock)> = None;
    // Whether the previous block was refused, i.e. `refused.last()` is it.
    let mut previous_refused = false;

    for block in split_ledger_blocks(content) {
        match parse_block(&block.text) {
            Ok(parsed) => {
                let count = parsed.len();
                directives.extend(parsed);
                previous_parsed = Some((count, block));
                previous_refused = false;
            }
            Err(errors) => {
                let reason = errors
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; ");
                if block.contiguous_with_previous && previous_refused {
                    // A second cut in the same directive: same raw block.
                    let held = refused.last_mut().expect("previous block was refused");
                    held.text.push_str(&block.text);
                    held.reason.push_str("; ");
                    held.reason.push_str(&reason);
                } else if let Some((count, head)) = previous_parsed
                    .take()
                    .filter(|_| block.contiguous_with_previous)
                {
                    // H-20 door (b): the head parsed only because the cut
                    // made it look complete. Take its directives back and
                    // hold head + tail as one raw block.
                    directives.truncate(directives.len() - count);
                    let mut text = head.text;
                    text.push_str(&block.text);
                    refused.push(UnparsableBlock {
                        line: head.line,
                        text,
                        reason: format!(
                            "block continues without a blank line into text that does not \
                             parse ({reason}); held whole rather than loaded truncated (H-20)"
                        ),
                    });
                } else {
                    refused.push(UnparsableBlock {
                        line: block.line,
                        text: block.text,
                        reason,
                    });
                }
                previous_parsed = None;
                previous_refused = true;
            }
        }
    }

    (directives, refused)
}

/// Parse ONE block of a `.bean` file exactly as the whole-file parser would
/// have read it in place (L-62).
///
/// [`parse_file`] strips a byte-order mark at offset 0 of whatever it is
/// given — right for a file, wrong for a block cut out of the middle of one:
/// the whole-file pass strips only the file's first character, so a `U+FEFF`
/// glued to a mid-file header (a `cat` of two BOM'd files, a paste from an
/// editor that writes one) makes the whole-file parse fail on that line
/// while a per-block parse quietly succeeds. That disagreement was reachable
/// two ways, both bad: as the file's only defect it made every block parse
/// after the whole file had failed, which is the fail-closed `Err` arm in
/// [`LedgerService::boot`] — `exit(1)` — and with any other broken block
/// present the BOM'd directive was **loaded** although the whole-file parser
/// had refused it.
///
/// So a block that begins with a BOM is refused here, with a reason naming
/// it, and never handed to `parse_file`. [`split_ledger_blocks`] has already
/// stripped the file-level BOM (offset 0), so the only way a block can start
/// with one is the mid-file shape above — or a doubled BOM at the very start,
/// which the whole-file parser refuses too. Both callers of a per-block parse
/// ([`salvage_unparsable_blocks`] and
/// [`LedgerService::parse_around_quarantined_text`]) go through this one
/// function so they cannot disagree with each other either.
/// The content ids of a block boot refused as text, when the ONLY thing
/// wrong with it is an amount past the cap (T81 / M-52).
///
/// The capped parse refused it; a parse with every cap lifted
/// ([`crate::parse::ParseLimits::IDENTIFY`]) accepting it is the proof that
/// the amount cap was the reason. `None` for any other unparsable block
/// (a Unicode account name, a split record). Nothing it returns is admitted:
/// the ids only let boot find the records that name the block as a parent.
pub(super) fn amount_cap_refused_block_ids(text: &str) -> Option<Vec<String>> {
    if text.starts_with(crate::parse::BYTE_ORDER_MARK) {
        return None;
    }
    let directives =
        crate::parse::parse_file_bounded(text, 0, crate::parse::ParseLimits::IDENTIFY).ok()?;
    if directives.is_empty() {
        return None;
    }
    Some(directives.iter().map(compute_content_id).collect())
}

pub(super) fn parse_block(text: &str) -> Result<Vec<Directive>, Vec<ParseError>> {
    if text.starts_with(crate::parse::BYTE_ORDER_MARK) {
        return Err(vec![ParseError {
            line: 1,
            column: 1,
            message: "block begins with a byte-order mark (U+FEFF) after the start of the file; \
                      the whole-file parser does not accept one there (L-62)"
                .to_owned(),
            kind: crate::error::ParseErrorKind::UnexpectedToken,
        }]);
    }
    parse_file(text)
}

/// Content ids of the file's transactions that sit on — or descend from — a
/// parent cycle (L-17).
///
/// `openledger-parents` lives in the envelope, and the content hash covers only
/// the economic body, so the parent pointers are hand-editable **without any id
/// changing**: a text editor can make `A` claim `hash(B)` as its parent while
/// `B` claims `hash(A)`. That file is not a DAG, and the DAG's own `I8` check
/// only catches it on the *second* insert — after the first cycle member is
/// already in, and (at boot) by aborting the whole load.
///
/// The scan is Kahn's algorithm over the subgraph induced by parents **present
/// in this file**. A parent the file does not contain is a legitimately missing
/// ancestor that anti-entropy supplies later, so it never blocks its child.
/// Whatever cannot be ordered is on a cycle or descends from one; both are
/// reported, because a directive whose ancestry runs through a fabricated cycle
/// can never have that ancestry validated either. Only transactions carry
/// parents, so only transactions can be on a cycle — every other directive is a
/// sink in this graph and orders immediately, which is why they are not hashed
/// here.
///
/// Returns an empty set for every well-formed file, which is the only case that
/// costs anything on a normal boot.
pub(super) fn directives_blocked_by_parent_cycles(directives: &[&Directive]) -> BTreeSet<String> {
    let mut parents_by_id: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for directive in directives {
        if let Directive::Transaction(transaction) = directive {
            // First occurrence wins, exactly like the DAG's G-Set dedup: a
            // second line with the same economic body is the same directive and
            // never reaches `insert`.
            parents_by_id
                .entry(compute_content_id(directive))
                .or_insert_with(|| {
                    transaction
                        .parent_ids()
                        .iter()
                        .map(|parent| (*parent).to_owned())
                        .collect()
                });
        }
    }

    let mut unordered_parents: BTreeMap<&str, usize> = BTreeMap::new();
    let mut children_of: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    let mut ready: Vec<&str> = Vec::new();

    for (content_id, parents) in &parents_by_id {
        let mut in_file_parents = 0usize;
        for parent in parents {
            if parents_by_id.contains_key(parent.as_str()) {
                in_file_parents += 1;
                children_of
                    .entry(parent.as_str())
                    .or_default()
                    .push(content_id.as_str());
            }
        }
        if in_file_parents == 0 {
            ready.push(content_id.as_str());
        }
        unordered_parents.insert(content_id.as_str(), in_file_parents);
    }

    while let Some(content_id) = ready.pop() {
        let Some(children) = children_of.get(content_id) else {
            continue;
        };
        for child in children {
            if let Some(remaining) = unordered_parents.get_mut(*child) {
                *remaining = remaining.saturating_sub(1);
                if *remaining == 0 {
                    ready.push(child);
                }
            }
        }
    }

    unordered_parents
        .into_iter()
        .filter(|(_, remaining)| *remaining > 0)
        .map(|(content_id, _)| content_id.to_owned())
        .collect()
}
