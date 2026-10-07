//! Boot (§3.5): `boot_with`, the operator input it adopts, and
//! `finalize_operator_input`.

use super::*;

impl LedgerService {
    // ── Boot ──────────────────────────────────────────────────────────────

    /// Boot the ledger service from a `.bean` file **and its commit journal**.
    ///
    /// If the file doesn't exist, creates an empty file and starts with an empty ledger.
    /// Parses directives, builds account state, populates the DAG, and initializes
    /// the Lamport clock.
    ///
    /// # Canonical ∪ journal (T44)
    ///
    /// Since T44 a mutation on a ledger past
    /// [`COMPACTION_MIN_CANONICAL_BYTES`] becomes an append to
    /// `<ledger>.bean.journal` rather than a rewrite of the `.bean`, so the
    /// durable state is the **union** of the two files. Boot reads both,
    /// concatenates the journal's records after the canonical text, and runs
    /// the identical pipeline over the result: one canonical `(date,
    /// type_priority)` sort, one cycle pre-scan, one insert loop. Nothing else
    /// changes, and it is that reuse — rather than a second merge routine —
    /// that makes "boot(canonical + journal) == boot(compacted canonical)" hold
    /// by construction:
    ///
    /// * the union is a set, and directive identity is the content hash, so a
    ///   directive present in *both* files (the post-crash, pre-compaction
    ///   shape) is deduped for free by the DAG's G-Set;
    /// * record order in the journal is arrival order, and the sort discards it
    ///   before anything is inserted, so the state cannot depend on it;
    /// * the leading comments and the L-30 file hash are taken from the
    ///   canonical text **only** — the journal is node-private and holds no
    ///   comments, and the hash's only job is to answer "did a human edit the
    ///   `.bean`?".
    ///
    /// Boot never writes. That is deliberate: [`Self::persist_or_reload`]
    /// recovers a failed commit by re-booting this very path, and a recovery
    /// that tried to write would fail for exactly the reason the commit just
    /// failed. A journal present at boot is simply carried; the first commit —
    /// or an explicit [`Self::compact`] from the node's startup path — folds it
    /// in.
    ///
    /// # Operator input (H-13)
    ///
    /// A directive with neither `openledger-author` nor `openledger-lamport`
    /// was never written by a node. It is adopted here through the same path
    /// a live hand edit takes — validated, stamped with this node's author,
    /// lamport and parents, inserted — and its signature is added by
    /// [`Self::finalize_operator_input`] once the node key is installed. A
    /// refusal is quarantined. See [`Self::unsigned_operator_input`].
    pub fn boot(file_path: impl Into<PathBuf>, author_id: String) -> Result<Self, ServiceError> {
        Self::boot_with(file_path, author_id, BootMode::Fresh, RecordFormat::V1)
    }

    /// [`Self::boot`], writing records in `format` (Format v2, Facets A + B).
    ///
    /// Under [`RecordFormat::V2`] every record this node writes through its
    /// API carries `openledger-format: "2"`: its id covers its author (the one
    /// in force at the write), and it is signed in signature v4. A line typed
    /// into the `.bean` keeps v1 identity — see `stamp_file_directive` — so the
    /// file's repairs keep their ids. Records are accepted in both formats
    /// whatever `format` says.
    pub fn boot_emitting(
        file_path: impl Into<PathBuf>,
        author_id: String,
        format: RecordFormat,
    ) -> Result<Self, ServiceError> {
        Self::boot_with(file_path, author_id, BootMode::Fresh, format)
    }

    /// The format of the records this node writes.
    pub fn emit_format(&self) -> RecordFormat {
        self.emit_format
    }

    /// [`Self::boot`] with the caller saying whether this is a process start
    /// or an L-13 reload — the one thing that decides what an absent `.bean`
    /// means (H-15). See [`BootMode`].
    pub(super) fn boot_with(
        file_path: impl Into<PathBuf>,
        author_id: String,
        mode: BootMode,
        emit_format: RecordFormat,
    ) -> Result<Self, ServiceError> {
        let configured: PathBuf = file_path.into();
        let file_path = Self::resolve_boot_path(&configured, mode)?;
        let journal_path = crate::journal::journal_path_for(&file_path);
        let content =
            Self::read_or_create_ledger_file(&configured, &file_path, &journal_path, mode)?;
        let canonical_bytes = content.len() as u64;
        let canonical_marker = FileMarker::of(&file_path);
        let scan = Self::read_boot_journal(&journal_path)?;

        // Extract leading comments (lines starting with `;` before any
        // directive) from the CANONICAL text: the journal carries none, and a
        // record header is a `;` line that would otherwise be mistaken for one.
        let leading_comments = extract_leading_comments(&content);

        // Canonical ∪ journal, as one `.bean`-shaped string. Each payload and
        // the canonical text already end in `\n`, so one extra `\n` reproduces
        // the blank-line separator `full_file_serialize` writes.
        let mut combined = content.clone();
        for payload in &scan.payloads {
            if !combined.trim().is_empty() {
                combined.push('\n');
            }
            combined.push_str(payload);
        }

        let ParsedBootText {
            directives,
            unparsable,
            amount_cap_refused,
            amount_cap_blocks,
            salvaged,
        } = Self::parse_boot_text(&combined, &file_path)?;
        let mut directives = directives;
        Self::drop_stray_envelope_keys(&mut directives, &file_path);

        // Sort by canonical order for correct AccountState building.
        let mut sorted: Vec<&Directive> = directives.iter().collect();
        sorted.sort_by(|a, b| {
            a.date()
                .cmp(&b.date())
                .then_with(|| a.type_priority().cmp(&b.type_priority()))
        });
        let cycle_blocked = Self::cycle_blocked_ids(&sorted, &file_path);
        let BootLoad {
            accounts,
            dag,
            mut lamport_high,
            quarantined,
            operator_input,
            unverified_history,
            content_rule_refused,
            duplicate_copies,
        } = Self::load_history(&sorted, &cycle_blocked, salvaged, &author_id, &file_path);
        let lamport_clock =
            Self::resume_boot_clock(&mut lamport_high, &unparsable, &author_id, &file_path);
        // T72 / H-19, judged on the content since T83 (L-94): the lamport gap
        // is no longer judged here, on the history as loaded, but by
        // `verify_own_history`, over the history the node will serve — after
        // the signature pass and the quarantines (T89 / L-100: it used to fire
        // for a record the same boot then quarantined).
        Self::warn_boot_quarantine(&quarantined, &unparsable, &file_path);

        // Build the read model from all directives.
        let all_directives: Vec<Directive> = dag.directives().into_iter().cloned().collect();
        let read_model = ReadModel::build(&all_directives);

        let mut service = LedgerService {
            dag,
            accounts,
            read_model,
            lamport_clock,
            author_id,
            file_path,
            leading_comments,
            // H-08: empty for every well-formed file; non-empty means the file
            // holds records this boot would otherwise have let the next
            // compaction delete.
            quarantined,
            // L-45: likewise, for the blocks that never became directives at
            // all. Both halves are re-derived from the file on every boot, so
            // neither is ever carried across a reload (see
            // [`Self::adopt_reloaded`]).
            quarantined_text: unparsable.into_iter().map(|block| block.text).collect(),
            // L-30: the bytes we just read (or the empty file we just created)
            // are the baseline every later persist compares against. Hashed
            // over the CANONICAL text alone — the journal is not part of the
            // artefact a human edits.
            last_file_hash: file_content_hash(&content),
            external_reconcile_count: 0,
            // L-11: installed by the node after the key is loaded. H-13: which
            // is why the operator input adopted below is signed later, by
            // `finalize_operator_input`, and tracked here until then.
            signer: None,
            // H-20: likewise installed after the key is loaded; the history
            // is verified the moment either the signer or the verifier is.
            verifier: None,
            unverified_history,
            signature_quarantined_total: 0,
            write_despite_signature_verdict: false,
            signature_verified_total: 0,
            signed_by_finalize: HashSet::new(),
            signature_failed_total: 0,
            release_on_hold: BTreeSet::new(),
            refused_history_closure: BTreeSet::new(),
            alternative_copies: BTreeMap::new(),
            typed_copies: BTreeMap::new(),
            quarantined_typed: BTreeMap::new(),
            reconcile_batch_ids: HashSet::new(),
            unsigned_operator_input: Vec::new(),
            operator_input_with_file_author: BTreeSet::new(),
            operator_input_as_written: BTreeMap::new(),
            boot_outside_dag_lamports: std::mem::take(&mut lamport_high.outside_dag),
            boot_clock_base: lamport_clock,
            journal_path,
            canonical_bytes,
            canonical_marker,
            // Boot read this file; it did not write it, so it may not be in
            // canonical form. The first commit rewrites it, exactly as every
            // pre-T44 persist did.
            canonical_is_current: false,
            canonical_over_cap: false,
            canonical_journal_bytes: scan.file_bytes,
            // Everything just loaded came off disk, so nothing is uncommitted.
            pending_ids: Vec::new(),
            // M-46: filled by the operator-input adoption below, not staged.
            adopted_from_file: HashSet::new(),
            // A torn tail must not be appended after: the scanner would read
            // the truncated payload's bytes as the next record's header. The
            // next commit rewrites the canonical file and deletes the journal,
            // which is the only safe way to make the file appendable again.
            // L-58: likewise a journal others can read — `append_record`
            // refuses it, so only a compaction can make appending possible.
            force_compaction: scan.torn_tail_bytes > 0 || scan.readable_by_others,
            // M-43: the compaction that folds a torn journal renames it.
            journal_torn_at_boot: scan.torn_tail_bytes > 0,
            commit_generation: 0,
            commit_in_flight: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
                IDLE_COMMIT_GENERATION,
            )),
            commit_gate: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            commit_observer: None,
            directive_id_snapshot: std::sync::Mutex::new(None),
            served_id_snapshot: std::sync::Mutex::new(None),
            withheld_snapshot: std::sync::Mutex::new(None),
            staged_frontier: std::sync::Mutex::new(None),
            join_trust: false,
            emit_format,
        };

        service.settle_boot_history(
            content_rule_refused,
            amount_cap_refused,
            duplicate_copies,
            operator_input,
            &amount_cap_blocks,
            mode,
        );

        Ok(service)
    }

    /// The path boot works at (T82 / L-84, T93 / L-117): a symlinked `.bean` is
    /// resolved on a process start; a reload uses the path it is handed.
    fn resolve_boot_path(configured: &Path, mode: BootMode) -> Result<PathBuf, ServiceError> {
        // T82 / L-84: a symlinked `.bean` this node's user created is worked
        // at its target — journal, temp files and compactions included.
        //
        // T93 / L-117: resolved once, by the process start. A reload is handed
        // the path the running service works at — the one gl-node locked and
        // its watcher polls — and uses it as it is: resolving it again followed
        // a link the operator had put there since, and the rebuilt service
        // then read, journalled and compacted a file the lock did not cover.
        // A path that has become a link is refused instead: the reload fails,
        // and `finish_recovery`'s reload-failed arm keeps memory, less the
        // writes the failed commit staged (T100 / L-147). Its next commit is a
        // full rewrite that renames a regular file onto the path, replacing
        // the link (L-44).
        let file_path = if matches!(mode, BootMode::Reload) {
            let is_link = std::fs::symlink_metadata(configured)
                .map(|metadata| metadata.file_type().is_symlink())
                .unwrap_or(false);
            if is_link {
                return Err(ServiceError::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!(
                        "ledger path {} became a symbolic link while the node was running; a \
                         reload does not follow it, since this node's lock and watcher are on the \
                         path it started with — stop the node, then start it on the new layout \
                         (L-117, L-44)",
                        configured.display()
                    ),
                )));
            }
            configured.to_path_buf()
        } else {
            crate::journal::resolve_ledger_path(configured)?
        };
        if file_path != configured {
            info!(
                link = %configured.display(),
                target = %file_path.display(),
                "ledger path is a symbolic link; this node reads, journals and compacts at its \
                 target, so the link is kept (L-84)"
            );
        }
        Ok(file_path)
    }

    /// The canonical text, read — or, on a process start with nothing beside
    /// it, created empty (H-15, T67).
    fn read_or_create_ledger_file(
        configured: &Path,
        file_path: &Path,
        journal_path: &Path,
        mode: BootMode,
    ) -> Result<String, ServiceError> {
        // Read the file, or — on a process start with nothing beside it —
        // create it.
        //
        // H-15: an absent file is created in exactly one case, a fresh start
        // with no journal. A reload never creates it (the service being
        // recovered had one; recreating it empty and installing that over
        // memory was the finding), and a fresh start next to a journal refuses
        // too: a journal exists only beside a `.bean` past the compaction
        // threshold, so this is a ledger whose `.bean` was removed or renamed,
        // and an empty file here would silently fold the journal's records
        // into a ledger holding nothing else.
        //
        // T67: `read_ledger_file` refuses anything at the path that is not a
        // regular file (or a symlink to one) without blocking, so a FIFO
        // `.bean` fails the boot instead of parking it after the lock is
        // taken, and a dangling symlink is refused rather than read as
        // "absent" and replaced by an empty ledger.
        if matches!(mode, BootMode::Fresh) {
            // L-57: once per process start, clear what crashed rewrites left.
            sweep_stale_temporaries(file_path, None);
            // T87: and what a build that still wrote beside the LINK left
            // there (`<link>.tmp.*`); since T82 temp files sit beside the
            // target, so nothing else ever cleans those up.
            if file_path != configured {
                sweep_stale_temporaries(configured, Some(file_path));
            }
        }
        let content = match read_ledger_file(file_path) {
            Ok(content) => content,
            Err(ServiceError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                // T78: `lstat`, not `Path::exists()` — `exists()` follows a
                // symlink, so a DANGLING journal link read as "absent", the
                // Fresh arm created an empty `.bean`, and only then did the
                // journal open refuse the link. Any entry at the journal path
                // (a dangling link included), and any probe error other than
                // NotFound, counts as present: the refusal below creates
                // nothing.
                let journal_exists = !matches!(
                    std::fs::symlink_metadata(journal_path),
                    Err(ref error) if error.kind() == std::io::ErrorKind::NotFound
                );
                match mode {
                    BootMode::Reload => {
                        return Err(ServiceError::Io(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            format!(
                                "ledger file {} is missing (journal {}: {}); refusing to rebuild \
                                 an empty ledger over the one in memory during a failed-commit \
                                 recovery — restore the .bean, the next commit recreates it from \
                                 memory otherwise (H-15)",
                                file_path.display(),
                                journal_path.display(),
                                if journal_exists { "present" } else { "absent" },
                            ),
                        )));
                    }
                    BootMode::Fresh if journal_exists => {
                        return Err(ServiceError::Io(std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            format!(
                                "ledger file {} is missing but its commit journal {} exists; \
                                 refusing to start an empty ledger beside a journal that belonged \
                                 to one — restore the .bean, or move the journal away to start a \
                                 new ledger deliberately (H-15)",
                                file_path.display(),
                                journal_path.display(),
                            ),
                        )));
                    }
                    BootMode::Fresh => {
                        // Create parent dirs + empty file (§3.3).
                        if let Some(parent) = file_path.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        persist_atomically(file_path, "")?;
                        String::new()
                    }
                }
            }
            Err(error) => return Err(error),
        };
        Ok(content)
    }

    /// The commit journal beside the ledger, with its torn-tail and
    /// permission warnings (T44, M-35, M-43, L-58).
    fn read_boot_journal(journal_path: &Path) -> Result<crate::journal::JournalScan, ServiceError> {
        // M-35: the journal is read under the full `MAX_LEDGER_FILE_BYTES`, not
        // under what the canonical file leaves of it. T44 invariant 5 —
        // canonical ∪ journal fits the cap — is enforced where the bytes are
        // produced: the append path projects `canonical + journal + record`
        // before every append, and `persist_atomically` refuses to write a
        // compacted file over the cap. Budgeting the journal at `MAX −
        // canonical` here as well turned a crash between the compaction's
        // rename and its `remove_journal` into a boot brick: the new `.bean`
        // is ≈ canonical + journal, so the post-crash state is
        // `canonical + 2·journal`, over the old budget on a journal the new
        // `.bean` already contains in full. Reading it costs one dedup pass
        // through the G-Set; the compaction that follows rewrites nothing
        // larger than it would have anyway.
        let journal_budget = MAX_LEDGER_FILE_BYTES;
        let scan = crate::journal::read_journal(journal_path, journal_budget)?;
        if scan.torn_tail_bytes > 0 {
            // M-43: say only what the bytes show. "The node crashed mid-append"
            // and "its commit never reported success" are true of a genuine
            // torn tail and false of a truncated or edited journal, which
            // looks the same from here — so the warning names both, and the
            // dropped bytes are kept rather than deleted.
            warn!(
                dropped_bytes = scan.torn_tail_bytes,
                intact_records = scan.payloads.len(),
                journal = %journal_path.display(),
                "ledger commit journal ends in a torn record; its {} trailing bytes are NOT \
                 loaded, the {} intact records before it are. This is what a crash mid-append \
                 leaves (that commit never reported success), and also what a truncated or \
                 edited journal looks like, or a final record damaged on disk AFTER its commit \
                 succeeded — then an acknowledged record is among the dropped bytes, and on a \
                 node with no peer to re-supply it the sidecar is where it is. Nothing is \
                 deleted: the next commit compacts and renames the journal to \
                 {}{}<unix-seconds> for inspection (M-43, T82).",
                scan.torn_tail_bytes,
                scan.payloads.len(),
                journal_path.display(),
                crate::journal::TORN_JOURNAL_SUFFIX,
            );
        }
        if scan.readable_by_others {
            // L-58: loaded (only this uid could have written it), but never
            // appended to; the forced compaction below folds and deletes it.
            warn!(
                journal = %journal_path.display(),
                "ledger commit journal is readable by other accounts; its records are loaded, \
                 and the next commit compacts it away instead of appending to it (L-58)"
            );
        }
        Ok(scan)
    }

    /// Parse canonical ∪ journal, salvaging block by block when the whole
    /// text does not parse (L-45, T81 / M-52).
    fn parse_boot_text(combined: &str, file_path: &Path) -> Result<ParsedBootText, ServiceError> {
        // Parse directives.
        //
        // L-45: a block that does not parse costs the node that block, NOT the
        // boot. Until T51 this line was `?`, and `gl-node`'s `main` turns a boot
        // error into `exit(1)` — so T37's ASCII account grammar (L-25's
        // confusable-account fix) made every pre-T37 ledger holding
        // `Assets:Cаsh` with a Cyrillic `а` unbootable at the moment of the
        // upgrade, on a node nobody had touched, with no targeted error. That
        // name was storable AND replicable before T37, so a node could acquire
        // one from a peer without its operator ever typing it.
        //
        // The tolerant path costs a well-formed file nothing: it runs only
        // after `parse_file` over the whole text has already failed, which on a
        // healthy ledger never happens. See [`salvage_unparsable_blocks`] for
        // why the salvage is per-block and why loosening the charset back is
        // not the fix.
        //
        // H-08 is the reason this is not simply a skip: the startup compaction
        // rewrites the whole `.bean` from memory, so a boot that merely skipped
        // these blocks would delete them from disk seconds after coming up.
        // Their raw text goes into `quarantined_text` and is spliced back by
        // every rewrite ([`Self::compaction_text`]).
        let mut unparsable: Vec<UnparsableBlock> = Vec::new();
        // T81 / M-52: content ids of text-held blocks refused only for an
        // amount past the cap — see `amount_cap_refused_block_ids`.
        let mut amount_cap_refused: BTreeSet<String> = BTreeSet::new();
        // T103 / M-73: each such block's line and ids, named once boot knows
        // whether anything it holds still descends from it.
        let mut amount_cap_blocks: Vec<(usize, Vec<String>)> = Vec::new();
        // H-20 door (b): set when the per-block salvage produced the
        // directives, which is the one path that can yield a fragment of a
        // record — the I1 arm below runs only then.
        let mut salvaged = false;
        let directives = if combined.trim().is_empty() {
            Vec::new()
        } else {
            match parse_file(combined) {
                Ok(directives) => directives,
                Err(errors) => {
                    salvaged = true;
                    let (directives, refused) = salvage_unparsable_blocks(combined);
                    // Fail closed if the splitter and the parser disagree about
                    // where the failure is: whole-file parse said no, per-block
                    // parse said every block is fine. That cannot happen while
                    // `split_ledger_blocks` mirrors `parse_file`'s outer loop,
                    // and if it ever does, the old hard failure is the safe
                    // answer — adopting a set of directives neither function
                    // agrees on is not.
                    if refused.is_empty() {
                        return Err(ServiceError::Parse(errors));
                    }
                    for block in &refused {
                        // T81 / M-52: a block refused only for an amount past
                        // the cap parses once the cap is lifted. Held as text
                        // all the same (nothing is admitted); what the lifted
                        // parse buys is its content id, so the records that
                        // name it as a parent can be found below. Its WARN
                        // waits for them (T103 / M-73,
                        // `warn_amount_cap_block`).
                        if let Some(ids) = amount_cap_refused_block_ids(&block.text) {
                            amount_cap_refused.extend(ids.iter().cloned());
                            amount_cap_blocks.push((block.line, ids));
                            continue;
                        }
                        warn!(
                            line = block.line,
                            reason = %block.reason,
                            file = %file_path.display(),
                            "quarantining a ledger-file block this node cannot parse — kept in \
                             the file byte-for-byte, kept out of the DAG; the rest of the file \
                             still loads. A pre-T37 ledger holding a Unicode account name looks \
                             exactly like this; stop the node and repair the line (L-45)"
                        );
                    }
                    unparsable = refused;
                    directives
                }
            }
        };
        Ok(ParsedBootText {
            directives,
            unparsable,
            amount_cap_refused,
            amount_cap_blocks,
            salvaged,
        })
    }

    /// Drop the `openledger-*` keys outside the envelope from node-written
    /// records (T83 / L-89, T89 / L-112).
    fn drop_stray_envelope_keys(directives: &mut [Directive], file_path: &Path) {
        // T83 / L-89: H-06's closed envelope-key set. A directive-level
        // `openledger-*` key that is not one of the envelope keys, on a
        // node-written record, used to load as verified history, be served
        // locally and be written back by every compaction. It is outside the
        // content hash and the signature, and no peer ever sees it
        // (`extract_envelope` keeps the closed set), so it is DROPPED here, with
        // a warning: the record keeps its id, its signature and its place in
        // every balance, and the next compaction writes it without the key.
        // (Operator input keeps its refusal on the file path.)
        // T89 / L-112: posting-level keys too.
        for directive in directives.iter_mut() {
            if Self::is_operator_input(directive) {
                continue;
            }
            let stray = strip_stray_envelope_keys(directive);
            if stray.is_empty() {
                continue;
            }
            warn!(
                id = %compute_content_id(directive),
                keys = %stray.join(", "),
                file = %file_path.display(),
                "dropped openledger-* metadata keys that are not part of the envelope from a \
                 node-written record; they are not hashed, not signed and never sent to a peer, \
                 and the next compaction writes the record without them (L-89, H-06)"
            );
        }
    }

    /// The transactions on, or descending from, an `openledger-parents` cycle,
    /// named in a warning (L-17).
    fn cycle_blocked_ids(sorted: &[&Directive], file_path: &Path) -> BTreeSet<String> {
        // L-17: refuse a hand-planted parent cycle *before* the load rather than
        // aborting in the middle of it. The DAG's I8 check catches such a pair
        // on the second insert and boot used to propagate that error, so a file
        // whose envelope someone edited — envelope parents are outside the
        // content hash, so no id has to change — bricked every subsequent boot
        // of an otherwise perfectly good ledger. Name the offenders and load the
        // rest.
        let cycle_blocked = directives_blocked_by_parent_cycles(sorted);
        if !cycle_blocked.is_empty() {
            warn!(
                blocked = cycle_blocked.len(),
                ids = %cycle_blocked.iter().cloned().collect::<Vec<_>>().join(", "),
                file = %file_path.display(),
                "ledger file contains transactions on (or descending from) an openledger-parents \
                 cycle; those directives are QUARANTINED — kept in the file, kept out of the DAG \
                 — and the rest of the file boots normally. Stop the node, then repair or remove \
                 their openledger-parents metadata (H-08)"
            );
        }
        cycle_blocked
    }

    /// Load the sorted history: insert what every peer would take, quarantine
    /// the rest, park operator input, and fold the clock (H-08, H-13, M-18).
    ///
    /// Each directive is judged first ([`Self::judge_history_directive`]) and
    /// the verdict applied after: every refusal is one [`BootLoad::hold`], so
    /// a refusal cannot forget the clock, the closure seed or the quarantine.
    fn load_history(
        sorted: &[&Directive],
        cycle_blocked: &BTreeSet<String>,
        salvaged: bool,
        author_id: &str,
        file_path: &Path,
    ) -> BootLoad {
        let mut load = BootLoad::new();
        for directive in sorted {
            // M-18 / T63: the clock is folded at each FATE below, not here.
            // Every directive that reaches the DAG counts; a directive that
            // does not (quarantined, or a duplicate body) counts only when it is
            // this node's own — see `BootLamportHigh`.
            match Self::judge_history_directive(directive, cycle_blocked, salvaged, file_path) {
                HistoryVerdict::OperatorInput => load.operator_input.push((*directive).clone()),
                HistoryVerdict::Hold {
                    content_id,
                    seeds_closure,
                } => load.hold(directive, content_id, seeds_closure, author_id),
                HistoryVerdict::Load => load.insert(directive, author_id, file_path),
            }
        }
        load
    }

    /// What boot does with one directive of the sorted history, and the
    /// warning it logs when it holds one back. The checks run in this order,
    /// and the first that refuses decides the warning and whether what
    /// descends from the record is held with it.
    fn judge_history_directive(
        directive: &Directive,
        cycle_blocked: &BTreeSet<String>,
        salvaged: bool,
        file_path: &Path,
    ) -> HistoryVerdict {
        // Insert into DAG (lenient mode: parents may not be present yet),
        // then record any lifecycle event it carries under the content id
        // the DAG just assigned (M-09).
        //
        // Boot deliberately applies NO lifecycle policy: no already-open
        // rejection (and, since T98, no ingest path refuses a `close`
        // either). The account state has to be a
        // pure function of the persisted directive set, so that a node which
        // boots from the file and a node which ingested the same directives
        // one at a time agree exactly. A guard here would also reintroduce
        // the order dependence M-09 is about — boot's `sorted` order is the
        // canonical one, not the order the directives were accepted in —
        // and could brick boot on a file the node itself wrote.
        // Skip the cycle members (and their descendants) identified above.
        // `cycle_blocked` is empty for every well-formed file, so this costs
        // no hashing on a normal boot.
        //
        // H-08: skipped, NOT dropped. The id is already in hand, so the
        // quarantine costs one clone of a directive this boot has decided
        // not to load — and it is what keeps the record on disk when the
        // startup compaction rewrites the file from the DAG.
        if !cycle_blocked.is_empty() && matches!(directive, Directive::Transaction(_)) {
            let content_id = compute_content_id(directive);
            if cycle_blocked.contains(&content_id) {
                return HistoryVerdict::hold(content_id);
            }
        }

        // H-13: no author AND no lamport means no node wrote this — it is
        // operator input, not history, and history's tolerant load below
        // is the wrong path for it: that path applies no lifecycle rule,
        // no body cap, no stamp and no signature, which is exactly how a
        // hand-typed record became an envelope-less, peer-refused parent
        // of everything this node authored afterwards. Parked here, in
        // canonical order, and adopted after the history loop so its
        // parents are the heads of the whole ledger, as a live append's
        // would be. After the cycle scan on purpose: a hand-written
        // `openledger-parents` that closes a cycle is quarantined with its
        // partner (M-38's union), never adopted.
        if Self::is_operator_input(directive) {
            return HistoryVerdict::OperatorInput;
        }

        // T41: `MAX_PARENTS` applied at the FILE ingress, tolerantly.
        //
        // The cap was enforced on the wire only, so a crafted or
        // hand-edited `.bean` could name unboundedly many parents on one
        // transaction — exactly what L-14's decoy does — and boot loaded it
        // without complaint. Loading it is what makes the fan-in real: the
        // directive becomes part of the served set, and every peer refuses
        // it forever.
        //
        // Skipped with a warning rather than refused, per T35's rule: boot
        // must never brick on a file the node can otherwise read. The
        // consequence of skipping is understood — a transaction absent from
        // the DAG is absent from the read model and from what this node
        // serves — and is strictly better than carrying a directive the
        // mesh will not accept.
        //
        // H-08: this is the skip site that needs no attacker at all. It
        // fires on any file written BEFORE T41 existed, at the moment of
        // the upgrade, on a node nobody has touched — and, before the
        // quarantine, the startup compaction that followed erased whatever
        // it skipped. Quarantine it.
        //
        // M-20: and the rest of the wire path's check set with it, by the
        // identical argument. Boot was the other half of the sibling-path
        // gap — an over-cap economic body (L-02), a malformed parent txid
        // (L-29) or an unreadable `openledger-lamport` all loaded here
        // without complaint, joined the served set, and were then refused
        // by every peer forever. Same tolerant treatment, same quarantine,
        // one call site so the two file paths cannot drift apart:
        // `reconcile_content` runs the very same
        // [`validate_file_ingest_parity`].
        //
        // Two things are deliberately NOT checked here, both recorded so
        // the omission reads as a decision rather than an oversight:
        //
        // * `enforce_economic_bean_limit`. Boot loads history; reconcile
        //   admits new records and signs them. See
        //   [`validate_file_ingest_parity`] for the full argument and for
        //   the residual it leaves.
        // * [`LAMPORT_CEILING`]. T46 owns that bound and deliberately chose
        //   warn-and-load at boot, so a poisoned clock stops *authoring*
        //   loudly while reads, reports and the file stay intact. Since
        //   T63 a directive quarantined here no longer feeds the clock
        //   unless it is this node's own (`BootLamportHigh`), so a
        //   quarantined FOREIGN value cannot poison authoring either.
        // T81 / M-51: the content rules peers hold history to — the §3.12
        // limits with the legacy ceilings, and the amount cap below. A
        // record refused by one of THESE is refused by every peer, so what
        // descends from it cannot replicate either: it seeds the closure
        // quarantine after the loop. (Fan-in and envelope form refuse the
        // record's envelope, not its content, and keep H-08's
        // record-only quarantine.)
        if let Err(error) = enforce_resource_limits_for(directive, ResourceRule::History) {
            let content_id = compute_content_id(directive);
            warn!(
                %error,
                id = %content_id,
                file = %file_path.display(),
                "quarantining a ledger-file directive over a limit every peer holds history \
                 to — kept in the file, kept out of the DAG, and with it every record that \
                 descends from it (named below) (M-51, H-08)"
            );
            return HistoryVerdict::hold_with_descendants(content_id);
        }
        // T85 / L-101, decision (19): the wire's body cap is a content rule
        // every peer holds history to as well — `validate_supply_entry`
        // refuses an over-cap `economic_bean` for good — so it seeds the
        // closure like the two above. T51 kept it off boot (see
        // `enforce_economic_bean_limit`); the record it left served was
        // M-51's shape: counted here, refused everywhere, and everything
        // written on top of it stranded on every fresh replica.
        if let Err(error) = enforce_economic_bean_limit(directive) {
            let content_id = compute_content_id(directive);
            warn!(
                %error,
                id = %content_id,
                file = %file_path.display(),
                "quarantining a ledger-file directive whose body is over the wire's size cap, \
                 which every peer refuses — kept in the file, kept out of the DAG, and with it \
                 every record that descends from it (named below) (L-101, H-08)"
            );
            return HistoryVerdict::hold_with_descendants(content_id);
        }
        if let Err(error) = validate_parent_fan_in(directive)
            .and_then(|()| validate_file_envelope_form(directive))
            // H-17 (T65, T76): the amount cap as a directive-level
            // quarantine arm too, so a transaction amount past
            // `MAX_AMOUNT_MAGNITUDE` stays out of the DAG even if the
            // parser's own check is ever loosened. `balance` and `price`
            // amounts are not capped (never summed).
            .and_then(|()| {
                crate::validate::check_directive_amounts(directive).map_err(|error| {
                    ServiceError::ResourceLimitExceeded {
                        message: error.to_string(),
                    }
                })
            })
        {
            let content_id = compute_content_id(directive);
            warn!(
                %error,
                id = %content_id,
                file = %file_path.display(),
                "quarantining a ledger-file directive that the wire path would refuse — \
                 kept in the file, kept out of the DAG; the rest of the file still loads \
                 (H-08, M-20)"
            );
            return HistoryVerdict::hold(content_id);
        }

        // H-20 door (b): a transaction that reached this loop through the
        // per-block salvage may be a fragment — a blank line typed inside
        // a node-written block leaves a head that parses on its own with
        // some of its postings — so it is held to I1 (balance, no
        // unresolved elision) before insertion, exactly as every other
        // ingress holds a new transaction. The whole-file path never
        // yields one (a fragment that parses is what this arm is for),
        // and a node-written record always balances, so a healthy boot
        // pays nothing here.
        if salvaged {
            if let Directive::Transaction(txn) = directive {
                if let Some(reason) = Self::transaction_fails_i1(txn) {
                    let content_id = compute_content_id(directive);
                    warn!(
                        reason = %reason,
                        id = %content_id,
                        file = %file_path.display(),
                        "quarantining a salvaged ledger-file transaction that does not \
                         balance — a fragment of a split block, not a record; kept in \
                         the file, kept out of the DAG (H-20, H-08)"
                    );
                    return HistoryVerdict::hold(content_id);
                }
            }
        }

        HistoryVerdict::Load
    }

    /// The clock boot resumes at, with the ceiling warnings (M-18, H-07,
    /// H-12, T72 (d)).
    fn resume_boot_clock(
        lamport_high: &mut BootLamportHigh,
        unparsable: &[UnparsableBlock],
        author_id: &str,
        file_path: &Path,
    ) -> u64 {
        // T78: an envelope naming this node inside a block boot could not
        // parse is a pair this node signed; see `BootLamportHigh`.
        for block in unparsable {
            lamport_high.note_text_if_own(&block.text, author_id);
        }
        let max_lamport = lamport_high.value;
        let lamport_clock = if max_lamport > 0 {
            max_lamport.saturating_add(1)
        } else {
            0
        };

        // H-07 / H-12: warn exactly when the stamp site is going to refuse —
        // the SAME predicate, applied to the value this node would stamp next
        // (`lamport_clock + 1`). Before T63 this tested `lamport_clock >=
        // LAMPORT_CEILING` while the stamp refused one step earlier, so the
        // state a peer can actually reach (a legal directive at `CEILING - 2`,
        // clock `CEILING - 1`) booted with zero WARN lines and the operator
        // learnt of it from the first refused mutation (H-12 fact 1). Boot
        // still neither clamps (walking the clock backwards would re-issue
        // `(author, lamport)` pairs the file already holds — M-18) nor refuses
        // to boot: reads, reports and replication carry on; only authoring
        // stops, loudly, at the stamp sites.
        //
        // T72 (d): the author named is the one that carried the clock highest
        // among OTHER nodes when there is one — after this node has authored
        // on top of a peer's jump, its own record is the highest and naming it
        // would name the victim.
        let suspect = lamport_high.suspect_author().unwrap_or("(unknown)");
        if !lamport_value_is_legal(lamport_clock.saturating_add(1)) {
            warn!(
                lamport_clock,
                ceiling = LAMPORT_CEILING,
                author = suspect,
                file = %file_path.display(),
                "ledger file carries an openledger-lamport at the Lamport ceiling; this node \
                 will refuse to author new directives. The directive was carried in by the \
                 author named here. Remedy, mesh-wide: remove that author from the allowlist \
                 on every node, then stop every node and remove the directive from each \
                 node's .bean — removing it here alone is undone by the next anti-entropy \
                 round (H-07, H-12). Removing an author whose directives are already in the \
                 history has a second consequence: {BOOTSTRAP_JOIN_REMEDY}"
            );
        } else if LAMPORT_CEILING - lamport_clock <= MAX_LAMPORT_ADVANCE {
            // T63: the ratchet bounds one step at 2^32, so a clock this close
            // to the ceiling is one ordinary-looking peer directive away from
            // the state above. Honest clocks are nowhere near here; say so
            // while the node can still author.
            warn!(
                lamport_clock,
                ceiling = LAMPORT_CEILING,
                max_advance = MAX_LAMPORT_ADVANCE,
                author = suspect,
                file = %file_path.display(),
                "ledger clock is within one adoption step (2^32) of the Lamport ceiling; no \
                 honest mesh gets here, and one more peer directive can stop authoring on \
                 this node. Investigate the author named here (H-12). If that author is \
                 removed from the allowlist: {BOOTSTRAP_JOIN_REMEDY}"
            );
        }
        lamport_clock
    }

    /// The one boot line an operator can act on when anything was held (H-08).
    fn warn_boot_quarantine(
        quarantined: &BTreeMap<String, Directive>,
        unparsable: &[UnparsableBlock],
        file_path: &Path,
    ) {
        // H-08: one line the operator can act on, after every per-directive
        // warning above. It states the contract the quarantine exists to make
        // true — the records are still in the file — because the pre-H-08
        // warnings said "skipped", which an operator reasonably read as "still
        // there", and it was the one thing that was not.
        if !quarantined.is_empty() || !unparsable.is_empty() {
            warn!(
                quarantined = quarantined.len(),
                unparsable_blocks = unparsable.len(),
                ids = %quarantined.keys().cloned().collect::<Vec<_>>().join(", "),
                unparsable_lines = %unparsable
                    .iter()
                    .map(|block| block.line.to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
                file = %file_path.display(),
                "ledger booted with directives QUARANTINED out of the DAG; they are NOT served, \
                 NOT in the read model and NOT in any balance, but they remain in the .bean and \
                 every compaction writes them back verbatim, so no record is deleted. A block \
                 this node could not parse is held whole — a parsable head cut off from an \
                 unparsable tail is held with it, never loaded as a shorter record — so a \
                 balance may be missing what that block holds until it is repaired. Stop the \
                 node and repair them (H-08, L-45, H-20)"
            );
        }
    }

    /// What follows the load, on the built service: the closure of refused
    /// history, the operator input, re-admission, the served-set rule, and
    /// the amount-cap WARNs (T81, H-13, T99, T84, T103).
    fn settle_boot_history(
        &mut self,
        mut content_rule_refused: BTreeSet<String>,
        amount_cap_refused: BTreeSet<String>,
        duplicate_copies: Vec<(String, Directive)>,
        operator_input: Vec<Directive>,
        amount_cap_blocks: &[(usize, Vec<String>)],
        mode: BootMode,
    ) {
        // T81 / M-51, M-52: what descends from a record refused under a
        // content rule goes with it — before the operator input, so its
        // parents are chosen from what stays.
        content_rule_refused.extend(amount_cap_refused);
        // T99 / M-72, decision (58): every other copy of a record the file
        // spells twice is kept, and each step about to hold a record — the
        // closure below, the served-set rule, the signature pass — first
        // tries them (`choose_servable_copies`). T90 chose here, once, before
        // any of those steps had spoken, and judged "its parents resolve"
        // against a DAG that still held what the closure was about to take.
        for (content_id, copy) in duplicate_copies {
            if self.dag.get(&content_id) != Some(&copy) {
                self.alternative_copies
                    .entry(content_id)
                    .or_default()
                    .push(copy);
            }
        }
        let closure_held = self.quarantine_descendants_of_refused_history(&content_rule_refused);

        // H-13: adopt the operator input, now that the whole history is in
        // place. Same path as a live hand edit, same order boot itself used.
        self.adopt_operator_input_at_boot(operator_input);

        // T99 / L-144: a record the closure held because its parent was a
        // closure member is servable again once the operator input put a copy
        // of that parent back (a block retyped beside it, T92 / L-131). The
        // closure was walked before that copy existed; before T99 the record
        // came back only at the next boot, after the compaction had rewritten
        // the parent.
        self.readmit_closure_members_now_servable(&closure_held);

        // T84 / H-23: and what no fresh replica could hold for any other
        // reason — a parent served nowhere, an account that does not admit it.
        // After the operator input, whose envelope-less `open`s (a very old
        // build's, or the operator's) are part of the accounts a peer judges
        // against; the rebuild re-chooses the parents of any operator input
        // that named what it takes out, so no hand line is signed over it.
        self.quarantine_unservable_history();

        // T103 / M-73, decision (68a): each block refused for its amount is
        // named with what this node still holds because of it — and, once
        // nothing is, as a copy to delete when its restatement is served.
        for (line, ids) in amount_cap_blocks {
            self.warn_amount_cap_block(*line, ids);
        }

        // L-64 (T78): a process start says so when the canonical form will not
        // fit. With operator input pending the check waits for
        // `finalize_operator_input`, whose author and signature are part of
        // what the compaction writes; a reload is a recovery rebuild and
        // stays quiet.
        if self.unsigned_operator_input.is_empty() {
            // T82 / L-80: a reload measures too — the fact decides whether
            // writes are refused before staging — but only a process start
            // says so.
            self.measure_canonical_over_cap(matches!(mode, BootMode::Fresh));
        }
    }

    /// Warn when the canonical form of this ledger — what every compaction
    /// writes — is larger than [`MAX_LEDGER_FILE_BYTES`] (L-64, T78).
    ///
    /// The file on disk can be under the cap while its canonical spelling is
    /// not: operator input gains an envelope (author, lamport, parents,
    /// signature — several hundred bytes on a one-line `open`), a leading
    /// `;comment` gains a space, one-space indentation becomes two. Such a
    /// ledger boots and serves, but `persist_atomically` refuses every
    /// compaction, so a write that needs one fails (and the startup compaction
    /// in `gl-node` logs it). Measured with [`Self::compaction_text_len`], one
    /// per-directive serialization pass per process start (or per
    /// finalisation of boot's operator input): no sort, no clone of the
    /// ledger, no 64 MiB string. Returns the canonical length when it is over
    /// the cap.
    pub(super) fn warn_if_canonical_exceeds_cap(&mut self) -> Option<u64> {
        self.measure_canonical_over_cap(true)
    }

    /// Measure the canonical form against the cap and record the fact in
    /// [`Self::canonical_over_cap`] (T82 / L-80), warning when `warn` and it
    /// is over. Returns the canonical length when it is over.
    pub(super) fn measure_canonical_over_cap(&mut self, warn: bool) -> Option<u64> {
        let canonical = self.compaction_text_len();
        self.canonical_over_cap = canonical > MAX_LEDGER_FILE_BYTES;
        if !self.canonical_over_cap || !warn {
            return self.canonical_over_cap.then_some(canonical);
        }
        warn!(
            canonical_bytes = canonical,
            file_bytes = self.canonical_bytes,
            journal_bytes = self.canonical_journal_bytes,
            max = MAX_LEDGER_FILE_BYTES,
            over_by = canonical - MAX_LEDGER_FILE_BYTES,
            file = %self.file_path.display(),
            "the canonical form of this ledger is larger than the ledger file cap, although the \
             file on disk is not: every compaction would refuse to write it, and every write \
             needs one, so EVERY WRITE FAILS until the file is made smaller — this node refuses \
             local writes and defers peer batches before staging them (L-80). The difference is \
             spelling — operator input gains its openledger \
             envelope, a leading ';comment' gains a space, indentation is normalised. Stop the \
             node and shrink the file until its canonical form fits: remove leading comments \
             and hand-typed directives you do not need, or start a new ledger for new history \
             (L-64)"
        );
        Some(canonical)
    }

    /// Is this file directive operator input rather than node-written history?
    /// (H-13, M-47)
    ///
    /// A node never writes a directive without `openledger-author` **and**
    /// `openledger-lamport`, so the exact negation is "lacks either". Until
    /// M-47 this tested "lacks both", and a half envelope — an author with no
    /// lamport (a block copied from another ledger with the line dropped) or
    /// a lamport with no author — took the history path: loaded raw, never
    /// stamped, never signed, served, refused by every peer with
    /// `EnvelopeMissing`, and a head the node's next write descended from.
    /// The live reconcile already stamped the missing half; boot now agrees.
    pub(super) fn is_operator_input(directive: &Directive) -> bool {
        let metadata = directive.metadata();
        !metadata.contains_key(ENVELOPE_KEY_AUTHOR) || !metadata.contains_key(ENVELOPE_KEY_LAMPORT)
    }

    /// Why operator input naming another node as its author is refused
    /// (M-54, T79) — one spelling for both file paths.
    pub(super) fn foreign_operator_input_reason(other_author: &str) -> String {
        // 0925 §5: "local" is not another node — it is the placeholder a
        // pre-T80 build wrote; say so, with the same remedy.
        if other_author == PLACEHOLDER_AUTHOR {
            return "openledger-author names the placeholder \"local\" — what a build before \
                    T80 wrote instead of this node's id — on an entry that is missing its \
                    openledger-lamport or openledger-signature, so it cannot be told apart from \
                    another node's. Remove the openledger-author line to adopt it as this node's \
                    own (M-54)"
                .to_owned();
        }
        format!(
            "openledger-author names another node ({other_author}) on an entry that is missing \
             its openledger-lamport or openledger-signature: this node cannot sign for that \
             author, every signing peer refuses it unsigned, and this node's next write would \
             name it as a parent — so everything written after it would be refused too. \
             Remove the openledger-author line to adopt it as this node's own, or restore the \
             author's complete signed record from a peer's copy of the ledger (M-54)"
        )
    }

    /// Hold `directive` in `quarantine` under `content_id`, keeping an
    /// enveloped spelling over an envelope-less one (L-76).
    ///
    /// The content hash excludes the envelope, so one id can be spelled twice
    /// in a file — once as the node wrote it and once as a raw copy. The
    /// enveloped copy is the record every peer holds; writing the raw one
    /// back instead would re-author the record under a fresh envelope at the
    /// next boot while the mesh keeps the original.
    pub(super) fn quarantine_keeping_envelope(
        quarantine: &mut BTreeMap<String, Directive>,
        content_id: String,
        directive: Directive,
    ) {
        match quarantine.entry(content_id) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                slot.insert(directive);
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => {
                if Self::is_operator_input(slot.get()) && !Self::is_operator_input(&directive) {
                    slot.insert(directive);
                }
            }
        }
    }

    /// The content id `directive` will be stored under once I2 has resolved
    /// an elided posting — which is what a hand line naming it as a parent
    /// spells (T92 / L-128). The file's own id when the body does not resolve
    /// (the adoption refuses it anyway) or is not a transaction.
    pub(super) fn stored_content_id(directive: &Directive) -> String {
        let Directive::Transaction(txn) = directive else {
            return compute_content_id(directive);
        };
        let mut permissive = AccountState::new();
        for posting in &txn.postings {
            let open = Open {
                date: txn.date,
                account: posting.account.clone(),
                currencies: Vec::new(),
                metadata: BTreeMap::new(),
            };
            permissive.record_open(&open, &posting.account);
        }
        match validate_transaction(txn, &permissive) {
            Ok(validated) => compute_content_id(&Directive::Transaction(Transaction {
                postings: validated.postings,
                ..txn.clone()
            })),
            Err(_) => compute_content_id(directive),
        }
    }

    /// Why `txn` fails I1/I2 — unbalanced, or an elision that cannot be
    /// resolved — or `None` when it balances (H-20 door (b)).
    ///
    /// The one definition every ingress uses, [`validate_transaction`],
    /// evaluated against a state in which each posting's account is open
    /// with no currency constraint: that turns I3 and I9 into tautologies and
    /// leaves exactly the two content invariants, weights and all, so the
    /// answer here is the answer `append_transaction` and the wire would give
    /// for the same postings. Boot applies no lifecycle policy (M-09), so this
    /// is deliberately not the service's real account state.
    pub(super) fn transaction_fails_i1(txn: &Transaction) -> Option<String> {
        let mut permissive = AccountState::new();
        for posting in &txn.postings {
            let open = Open {
                date: txn.date,
                account: posting.account.clone(),
                currencies: Vec::new(),
                metadata: BTreeMap::new(),
            };
            permissive.record_open(&open, &posting.account);
        }
        validate_transaction(txn, &permissive)
            .err()
            .map(|error| error.to_string())
    }

    /// The second half of [`Self::boot`] (H-13): adopt the envelope-less
    /// directives the load loop parked, through [`Self::adopt_file_directive`].
    ///
    /// Runs on the constructed service so that the adoption sees the complete
    /// history — the parents it stamps are `heads_admissible_as_parents_of`
    /// over the whole ledger, and a hand-typed transaction is validated
    /// against every open the file holds, hand-typed opens earlier in
    /// canonical order included (the input arrives in boot's sorted order).
    ///
    /// A refusal is quarantined, not dropped. The live reconcile drops what it
    /// refuses because the operator is at the keyboard and the L-12 warning
    /// tells them what went; boot's contract is that it destroys nothing it
    /// read (H-08), so the raw block stays in the file, out of the DAG, named
    /// in the banner, until the operator repairs it and restarts. A refused
    /// entry is quarantined as the FILE spelled it — never a half-stamped
    /// copy, which the next boot would mistake for history.
    ///
    /// Everything adopted is recorded in [`Self::unsigned_operator_input`]
    /// under its *stored* id (which differs from the file's content id when I2
    /// resolved an elided posting) and forces the next commit to be a
    /// compaction: the file spells these records raw, and only a rewrite gives
    /// them their envelope.
    pub(super) fn adopt_operator_input_at_boot(&mut self, operator_input: Vec<Directive>) {
        if operator_input.is_empty() {
            return;
        }
        let operator_input = hand_parented_last(operator_input);
        let mut tally = AdoptionTally::default();
        for directive in operator_input {
            let content_id = compute_content_id(&directive);
            // T99 / L-143, decision (59): a line typed beside a record the
            // DAG holds as history is parked, not dropped — the history copy
            // may yet be held (the served-set rule, the signature pass), and
            // then this copy is adopted in its place, as the in-place strip
            // remedy would be.
            let stored_id = Self::stored_content_id(&directive);
            let held_as = [&content_id, &stored_id]
                .into_iter()
                .find(|id| self.dag.get(id.as_str()).is_some())
                .cloned();
            if let Some(existing) = held_as {
                if self
                    .dag
                    .get(&existing)
                    .is_some_and(|held| !Self::is_operator_input(held))
                {
                    self.typed_copies.entry(existing).or_insert(directive);
                }
                tally.duplicates += 1;
                continue;
            }
            self.adopt_one_operator_input(directive, content_id, &mut tally);
        }
        if !self.unsigned_operator_input.is_empty() {
            // The file holds these raw; the rewrite is what canonicalises them.
            self.force_compaction = true;
            info!(
                adopted = self.unsigned_operator_input.len(),
                duplicates = tally.duplicates,
                author = %self.author_id,
                file = %self.file_path.display(),
                "ledger file holds directives with no openledger envelope; adopted as OPERATOR \
                 INPUT — this node's author, lamport and parents stamped — and signed once the \
                 node key is installed, before the first compaction canonicalises them (H-13)"
            );
        }
        if !tally.rejections.is_empty() {
            warn!(
                refused = tally.rejections.len(),
                entries = %tally
                    .rejections
                    .iter()
                    .map(|(id, reason)| format!("{id}: {reason}"))
                    .collect::<Vec<_>>()
                    .join(" | "),
                file = %self.file_path.display(),
                "ledger file holds operator input this node refuses to adopt; the entries are \
                 QUARANTINED — kept in the file as written, kept out of the DAG, NOT served — \
                 stop the node, repair them, and restart (H-13, H-08)"
            );
        }
    }

    /// One entry of [`Self::adopt_operator_input_at_boot`]: adopted as pending
    /// operator input, or held as the file spelled it.
    pub(super) fn adopt_one_operator_input(
        &mut self,
        directive: Directive,
        content_id: String,
        tally: &mut AdoptionTally,
    ) -> bool {
        // Kept as the file spelled it, for the quarantine on refusal.
        let as_written = directive.clone();
        // M-47: an author the FILE spelled is the operator's word, and
        // `finalize_operator_input` must not write this node's id over
        // it — see `operator_input_with_file_author`.
        let file_author = directive_author(&directive).map(str::to_owned);
        match self.adopt_file_directive(directive, content_id.clone(), tally, AdoptionPath::Boot) {
            FileAdoption::Inserted(stored_id) => {
                if file_author.is_some() {
                    self.operator_input_with_file_author
                        .insert(stored_id.clone());
                }
                // T79 / H-22: a later step may still refuse this entry.
                self.operator_input_as_written
                    .insert(stored_id.clone(), (content_id, as_written));
                self.unsigned_operator_input.push(stored_id);
                true
            }
            FileAdoption::Duplicate => false,
            FileAdoption::Refused => {
                self.hold_operator_input_as_written(content_id, as_written);
                false
            }
        }
    }

    /// Adopt the parked typed copy of each record in `held` the DAG no longer
    /// holds (T99 / L-143, decision (59)): the operator retyped the record
    /// beside its history copy, and a step has just held that copy — the
    /// served-set rule (its parent is gone) or the signature pass (its
    /// envelope was edited). Before T99 the typed copy had been counted a
    /// duplicate at adoption and the startup compaction dropped it, silently;
    /// T92's L-131 fix reached only a record the closure held, which leaves
    /// the DAG before the operator input is adopted. Returns how many were
    /// adopted.
    pub(super) fn adopt_typed_copies_of_held_records(&mut self, held: &BTreeSet<String>) -> usize {
        let mut tally = AdoptionTally::default();
        let mut adopted: Vec<String> = Vec::new();
        for content_id in held {
            if self.dag.get(content_id).is_some() {
                continue;
            }
            let Some(typed) = self.typed_copies.remove(content_id) else {
                continue;
            };
            let file_id = compute_content_id(&typed);
            if self.adopt_one_operator_input(typed, file_id, &mut tally) {
                adopted.push(content_id.clone());
            }
        }
        if !adopted.is_empty() {
            self.force_compaction = true;
            info!(
                ids = %adopted.join(", "),
                file = %self.file_path.display(),
                "the ledger file spells these held records twice — as history and as a line                  typed by hand without an envelope; the typed line is adopted as this node's                  own and signed, and replaces the held copy at the next compaction (L-131,                  L-143)"
            );
        }
        if !tally.rejections.is_empty() {
            warn!(
                refused = tally.rejections.len(),
                entries = %tally
                    .rejections
                    .iter()
                    .map(|(id, reason)| format!("{id}: {reason}"))
                    .collect::<Vec<_>>()
                    .join(" | "),
                file = %self.file_path.display(),
                "ledger file holds a line typed beside a held record that this node refuses to                  adopt; QUARANTINED — kept in the file as written (L-143, H-08)"
            );
        }
        adopted.len()
    }

    /// Hold operator input as the file spelled it (T79; T99 / L-145): beside
    /// an enveloped copy of the same record already held, the typed spelling
    /// is kept too, so the compaction writes both and "kept in the file as
    /// written" is true. Before T99 [`Self::quarantine_keeping_envelope`] kept
    /// only the enveloped copy (L-76) and the operator's block was dropped.
    pub(super) fn hold_operator_input_as_written(&mut self, file_id: String, written: Directive) {
        match self.quarantined.get(&file_id) {
            Some(held) if !Self::is_operator_input(held) => {
                self.quarantined_typed.insert(file_id, written);
            }
            _ => Self::quarantine_keeping_envelope(&mut self.quarantined, file_id, written),
        }
    }

    /// Drop the blocks typed beside records this node still serves (T99 /
    /// L-143) — the same records, so nothing adopts them and the compaction
    /// writes each record once — saying so for each (C8 of
    /// `docs/audits/RESIDUALS.md`), so a retyped block that leaves the file is
    /// not a silent change.
    pub(super) fn drop_typed_copies_as_duplicates(&mut self) {
        for content_id in std::mem::take(&mut self.typed_copies).into_keys() {
            info!(
                id = %content_id,
                file = %self.file_path.display(),
                "a block typed into the ledger file repeats a record this node already holds \
                 and serves; it is the same record, so the next compaction writes the record \
                 once (L-143)"
            );
        }
    }

    /// Give every directive [`Self::boot`] adopted as operator input its
    /// final envelope: this node's author id and, when a signer is installed,
    /// its signature (H-13).
    ///
    /// Call it after [`Self::set_author_id`] and [`Self::set_signer`] and
    /// before the first compaction — `gl-node` does exactly that, and
    /// [`Self::prepare`] does it for any compaction a library caller reaches
    /// first. Idempotent and cheap: the set is drained, so a second call does
    /// nothing, and an empty set costs one `is_empty`.
    ///
    /// # What it may and may not change
    ///
    /// * `openledger-author` — overwritten with the current author id. Boot
    ///   stamped whatever author it was booted with (`gl-node` boots with a
    ///   placeholder and learns its `EndpointId` from the P2P layer
    ///   afterwards), and only ids this node itself stamped are tracked here,
    ///   so no foreign author is ever rewritten.
    /// * `openledger-signature` — added, never replaced, and only when a
    ///   signer is installed. Without one the entry stays unsigned, which is
    ///   precisely what [`Self::reconcile_content`] does without a signer.
    /// * `openledger-lamport` — stamped here, in adoption order, from the
    ///   clock the signature pass has settled (T84 / M-57, decision (16));
    ///   boot's stamp is a placeholder that never moved the clock.
    /// * Nothing else. Parents are the DAG's edges, chosen at boot and re-chosen
    ///   by the H-22 rebase; the signed message is built from them exactly as
    ///   `sign_adopted_entry` builds it.
    ///
    /// An in-place edit of a directive that is on disk in raw form cannot be
    /// expressed by an append (the G-Set drops a journal record whose id it
    /// already holds — the same argument as [`Self::stamp_signature`]), so
    /// the next commit is forced to be a compaction. Returns how many entries
    /// were finalised.
    pub fn finalize_operator_input(&mut self) -> usize {
        if self.unsigned_operator_input.is_empty() {
            self.drop_typed_copies_as_duplicates();
            return 0;
        }
        // M-54 (T79): an author the FILE spelled that is not this node. Boot
        // could not judge it — the author may have been a placeholder then —
        // so it is judged here, where the identity is complete, and refused:
        // this node cannot sign for it, every signing peer refuses it
        // unsigned, and adopted it is a head this node's next write names.
        // `quarantine_out_of_dag` holds each as the file spelled it and
        // re-chooses the parents of the operator input that named it.
        let foreign: BTreeSet<String> = self
            .operator_input_with_file_author
            .iter()
            .filter(|content_id| {
                self.dag
                    .get(content_id.as_str())
                    .and_then(directive_author)
                    .is_some_and(|author| author != self.author_id)
            })
            .cloned()
            .collect();
        if !foreign.is_empty() {
            for content_id in &foreign {
                let author = self
                    .dag
                    .get(content_id)
                    .and_then(directive_author)
                    .unwrap_or_default()
                    .to_owned();
                warn!(
                    id = %content_id,
                    this_node = %self.author_id,
                    file = %self.file_path.display(),
                    "quarantining a ledger-file entry, kept in the file as written: {}",
                    Self::foreign_operator_input_reason(&author)
                );
            }
            self.quarantine_out_of_dag(&foreign);
            // T84 / H-23: history on an account only a refused entry opened.
            self.quarantine_unservable_history();
        }
        // T92 / L-121 (decision (42), revised 2026-09-26): L-77 for a hand
        // `open` adopted at boot, judged here, after the signature pass has
        // settled which `open`s are served. At boot the node's own edited
        // `open` — the one the H-23 WARN tells the operator to replace with
        // "the missing open" — was still in the DAG, so boot's L-77 refused
        // the remedy as "already open" while the account was open nowhere
        // anyone could see. Refused now only when a served `open` other than
        // pending operator input still opens the account, in adoption order
        // (of two hand `open`s of one new account the second is refused).
        let mut pending_opens: HashSet<String> = self
            .unsigned_operator_input
            .iter()
            .filter(|id| matches!(self.dag.get(id.as_str()), Some(Directive::Open(_))))
            .cloned()
            .collect();
        let mut already_open: BTreeSet<String> = BTreeSet::new();
        for content_id in self.unsigned_operator_input.clone() {
            let Some(Directive::Open(open)) = self.dag.get(&content_id) else {
                continue;
            };
            if self
                .accounts
                .is_open_excluding(&open.account, &pending_opens)
            {
                warn!(
                    id = %content_id,
                    file = %self.file_path.display(),
                    "quarantining a ledger-file entry, kept in the file as written: {} (L-77)",
                    ServiceError::AccountAlreadyOpen {
                        account: open.account.clone(),
                    }
                );
                already_open.insert(content_id);
            } else {
                pending_opens.remove(&content_id);
            }
        }
        if !already_open.is_empty() {
            self.quarantine_out_of_dag(&already_open);
            self.quarantine_unservable_history();
        }
        // T99 / L-143: a line typed beside a record still served is a
        // duplicate of it; nothing adopts it from here on, and the compaction
        // keeps the node-written copy.
        self.drop_typed_copies_as_duplicates();
        // T84 / M-57, decision (16): the lamport, stamped here for the first
        // time — boot's was a placeholder that never moved the clock — from
        // the clock the signature pass and the L-87 release have settled, in
        // adoption order. Before T84 boot stamped it above whatever the file's
        // edited lamports had carried the clock to, and the release, seeing
        // it, released nothing: a hand line appended beside an edited lamport
        // was signed above the edit and every peer refused it.
        let pending: Vec<String> = self.unsigned_operator_input.clone();
        let mut unstampable: BTreeSet<String> = BTreeSet::new();
        let mut restamped: Vec<Directive> = Vec::new();
        for content_id in &pending {
            let lamport = match self.next_stamp() {
                Ok(lamport) => lamport,
                Err(error @ ServiceError::SignatureVerdict { .. }) => {
                    warn!(
                        id = %content_id,
                        %error,
                        file = %self.file_path.display(),
                        "quarantining operator input, kept in the file as written: every \
                         signature this node checked failed, so it is not signed under a domain \
                         that is likely wrong — it is adopted at the first boot under the right \
                         p2p.meshId and key (L-114, H-08)"
                    );
                    unstampable.insert(content_id.clone());
                    continue;
                }
                Err(error) => {
                    warn!(
                        id = %content_id,
                        %error,
                        file = %self.file_path.display(),
                        "quarantining operator input, kept in the file as written: this node's \
                         clock cannot stamp it without passing the Lamport ceiling (H-12, H-08)"
                    );
                    unstampable.insert(content_id.clone());
                    continue;
                }
            };
            if let Some(directive) = self.dag.get_mut(content_id) {
                directive_metadata_mut(directive)
                    .insert(ENVELOPE_KEY_LAMPORT.to_owned(), lamport.to_string());
                self.lamport_clock = lamport;
                restamped.push(directive.clone());
            }
        }
        for directive in &restamped {
            self.read_model.reindex_directive(directive);
        }
        if !unstampable.is_empty() {
            self.quarantine_out_of_dag(&unstampable);
            // T92 / M-64: as the M-54 arm above does — history that relied on
            // the input just held (an account only its hand `open` opened, a
            // hand parent) is no longer servable.
            self.quarantine_unservable_history();
        }
        let ids = std::mem::take(&mut self.unsigned_operator_input);
        // T99 / L-145: a typed copy of a closure member leaves the closure
        // once it is finalised — not at adoption, when a refusal above could
        // still hold it and leave the id out of the closure until a restart.
        for content_id in &ids {
            self.refused_history_closure.remove(content_id);
        }
        // Every file-spelled author left names this node (the rest were
        // refused above), so the stamp below writes the id it already has.
        self.operator_input_with_file_author.clear();
        // Nothing can refuse these entries any more: from here on they are
        // this node's signed records, and a later quarantine treats them as
        // history.
        self.operator_input_as_written.clear();
        let author_id = self.author_id.clone();
        let signer = self.signer.clone();
        let mut finalized = 0usize;
        let mut signed = 0usize;
        // L-74: the read model holds boot's clone of each of these, author
        // placeholder and all; re-indexed below so `journal` serves what
        // `transaction` serves.
        let mut reindex: Vec<Directive> = Vec::new();
        for content_id in &ids {
            let Some(directive) = self.dag.get_mut(content_id) else {
                continue;
            };
            let is_transaction = matches!(directive, Directive::Transaction(_));
            let format = RecordFormat::of(directive);
            let metadata = directive_metadata_mut(directive);
            metadata.insert(ENVELOPE_KEY_AUTHOR.to_owned(), author_id.clone());
            finalized += 1;
            if !metadata.contains_key(ENVELOPE_KEY_SIGNATURE) {
                if let Some(signer) = signer.as_ref() {
                    let (parents, lamport) = Self::envelope_parents_and_lamport(metadata);
                    let (parents, lamport) = (parents.to_owned(), lamport.to_owned());
                    if let Some(signature_hex) =
                        signer(content_id, is_transaction, &parents, &lamport, format)
                    {
                        metadata.insert(ENVELOPE_KEY_SIGNATURE.to_owned(), signature_hex);
                        signed += 1;
                    }
                }
            }
            reindex.push(directive.clone());
            // H-20: what this node just signed is checked like everything
            // else — a signer and a verifier bound to different mesh ids
            // would otherwise sign records every peer refuses.
            self.unverified_history.insert(content_id.clone());
            // T92 / L-114: but it is not evidence that the history verifies.
            self.signed_by_finalize.insert(content_id.clone());
        }
        for directive in &reindex {
            self.read_model.reindex_directive(directive);
        }
        // The raw spellings on disk have to be replaced whether or not a
        // signature was produced: the author and the stamp boot added are in
        // memory only until a rewrite.
        self.force_compaction = true;
        info!(
            finalized,
            signed,
            signer_installed = signer.is_some(),
            author = %author_id,
            "operator input adopted at boot now carries this node's identity (H-13)"
        );
        self.verify_history_pass();
        // L-64 (T78): boot deferred its size check to here, where the
        // envelope the compaction will write is complete.
        self.warn_if_canonical_exceeds_cap();
        finalized
    }
}

/// What [`LedgerService::parse_boot_text`] returns.
struct ParsedBootText {
    directives: Vec<Directive>,
    unparsable: Vec<UnparsableBlock>,
    amount_cap_refused: BTreeSet<String>,
    amount_cap_blocks: Vec<(usize, Vec<String>)>,
    salvaged: bool,
}

/// What [`LedgerService::judge_history_directive`] decides for one directive.
enum HistoryVerdict {
    /// No envelope: parked, and adopted after the history (H-13).
    OperatorInput,
    /// Held back: kept in the file, out of the DAG (H-08). `seeds_closure`
    /// when the refusal is a content rule every peer holds history to, so
    /// what descends from the record is held with it (T81 / M-51).
    Hold {
        content_id: String,
        seeds_closure: bool,
    },
    /// Every check passed: insert it into the DAG.
    Load,
}

impl HistoryVerdict {
    /// A refusal of the record alone.
    fn hold(content_id: String) -> Self {
        Self::Hold {
            content_id,
            seeds_closure: false,
        }
    }

    /// A refusal under a content rule: the record and what descends from it.
    fn hold_with_descendants(content_id: String) -> Self {
        Self::Hold {
            content_id,
            seeds_closure: true,
        }
    }
}

/// What [`LedgerService::load_history`] returns.
struct BootLoad {
    accounts: AccountState,
    dag: LedgerDag,
    /// M-18 / T63: the highest Lamport value this node's clock must resume
    /// above, and the author of the directive that carries it (named in the
    /// H-12 boot warning). See `BootLamportHigh` for which directives count.
    lamport_high: BootLamportHigh,
    /// H-08: every directive the load refuses, so the next compaction can
    /// write it back instead of deleting it. See `LedgerService::quarantined`
    /// for why a skip that reaches a rewrite destroys the record.
    quarantined: BTreeMap<String, Directive>,
    /// H-13: directives with no envelope at all — operator input, adopted
    /// through the reconcile path once the history is in place, in this same
    /// canonical order. See `LedgerService::unsigned_operator_input`.
    operator_input: Vec<Directive>,
    /// H-20: every enveloped directive the load inserts, for the signature
    /// pass that runs once a signer or verifier is installed. See
    /// `LedgerService::unverified_history`.
    unverified_history: BTreeSet<String>,
    /// T81 / M-51: records the history arm refused under a content rule,
    /// seeding the closure quarantine after construction.
    content_rule_refused: BTreeSet<String>,
    /// T90 / H-24: the second copy of a transaction body already in the DAG
    /// — the same id under another envelope — for the copy choice after the
    /// load.
    duplicate_copies: Vec<(String, Directive)>,
}

impl BootLoad {
    fn new() -> Self {
        Self {
            accounts: AccountState::new(),
            dag: LedgerDag::new(),
            lamport_high: BootLamportHigh::default(),
            quarantined: BTreeMap::new(),
            operator_input: Vec::new(),
            unverified_history: BTreeSet::new(),
            content_rule_refused: BTreeSet::new(),
            duplicate_copies: Vec::new(),
        }
    }

    /// Hold `directive` back: its lamport counts only if it is this node's
    /// own (T63), a content-rule refusal seeds the closure (T81), and it is
    /// kept for the compaction to write back (H-08).
    fn hold(
        &mut self,
        directive: &Directive,
        content_id: String,
        seeds_closure: bool,
        author_id: &str,
    ) {
        self.lamport_high.note_if_own(directive, author_id);
        if seeds_closure {
            self.content_rule_refused.insert(content_id.clone());
        }
        // L-76: `entry().or_insert`, preferring the enveloped spelling. A
        // plain `insert` let a later envelope-less copy of the same id replace
        // the signed one; the compaction then wrote the raw copy, and the next
        // boot re-authored the record under a fresh envelope while every peer
        // kept the original.
        LedgerService::quarantine_keeping_envelope(
            &mut self.quarantined,
            content_id,
            directive.clone(),
        );
    }

    /// Insert `directive`, which every check admitted, into the DAG.
    fn insert(&mut self, directive: &Directive, author_id: &str, file_path: &Path) {
        // L-17: a DAG refusal must never abort the load. The cycle pre-scan
        // and `require_parents: false` between them rule out `CycleDetected`
        // and `MissingParent`, but L-14 added a third refusal this arm really
        // does see: [`DagError::CycleCheckExhausted`], the I8 check giving up
        // on a parent graph crafted to make both of its search frontiers
        // large at once.
        //
        // H-08: so this arm is reachable, and a refusal here must cost the
        // directive its place in the DAG — never its place in the file.
        // Quarantine it, for the same reason as the judge's refusals.
        let insert_result = match self.dag.insert(directive.clone(), false) {
            Ok(result) => result,
            Err(error) => {
                let content_id = compute_content_id(directive);
                warn!(
                    %error,
                    id = %content_id,
                    file = %file_path.display(),
                    "quarantining a directive the DAG refused at boot — kept in the file, \
                     kept out of the DAG; the rest of the file still loads (H-08)"
                );
                self.hold(directive, content_id, false, author_id);
                return;
            }
        };
        match insert_result {
            InsertResult::Inserted { content_id } => {
                self.lamport_high.note(directive, author_id);
                self.accounts.record_lifecycle(directive, &content_id);
                // H-20: loaded on the strength of its form; its signature is
                // checked by `verify_own_history` once the node has the means.
                // Everything on this path carries an author (H-13 parks the
                // rest as operator input).
                self.unverified_history.insert(content_id);
            }
            // A duplicate body is the same directive: its event is already
            // recorded, under the same content id. Its ENVELOPE is not in the
            // DAG, so its lamport counts only if it is this node's own pair
            // (T63; see `BootLamportHigh`).
            InsertResult::Duplicate { content_id } => {
                self.lamport_high.note_if_own(directive, author_id);
                self.duplicate_copies.push((content_id, directive.clone()));
            }
        }
    }
}
