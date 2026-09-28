//! The live reconcile of hand edits (T35): `reconcile_file`, adopting one file
//! directive, and signing what it adopts.

use super::*;

/// The running counts of one pass over file directives — the reconcile loop's
/// and boot's operator-input adoption's (H-13) — plus every refusal with its
/// reason, for the L-12 per-entry log line.
#[derive(Debug, Default)]
pub(super) struct AdoptionTally {
    pub(super) new_directives: usize,
    pub(super) duplicates: usize,
    pub(super) rejected: usize,
    /// `(content id as the file spells it, reason)` for every refusal.
    pub(super) rejections: Vec<(String, String)>,
}

impl AdoptionTally {
    pub(super) fn refuse(&mut self, content_id: String, reason: String) {
        self.rejected += 1;
        self.rejections.push((content_id, reason));
    }
}

/// What [`LedgerService::adopt_file_directive`] did with one directive.
#[derive(Debug)]
pub(super) enum FileAdoption {
    /// Inserted into the DAG under this **stored** id (the resolved body's id,
    /// which differs from the file's content id when I2 filled an elision).
    Inserted(String),
    /// The resolved body was already in the DAG.
    Duplicate,
    /// Refused; the reason is in the tally.
    Refused,
}

/// Which file path is adopting (T79 / M-54).
///
/// The two paths share every rule except those that need the node's final
/// identity. At boot the author may still be a placeholder (gl-node sets the
/// real one after boot) and no signer or verifier is installed, so a rule
/// that compares against this node's author runs later, in
/// `finalize_operator_input`; on the live reconcile the identity is final
/// and the rule runs before anything is stamped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AdoptionPath {
    /// `boot`'s adoption of operator input.
    Boot,
    /// The live reconcile of a running node.
    Live,
}

/// `directives` with every hand-typed transaction that spells its own
/// `openledger-parents` (operator input — no full envelope — with a parents
/// line) moved after the rest, each group keeping its order (T89 / L-108).
///
/// Operator input is adopted in canonical (date, type) order, and a hand
/// parent must already be served when the line naming it is adopted (L-75).
/// Two hand lines of one edit, the child placed before its hand parent on the
/// same date, used to refuse the child ("exists nowhere") at one boot and
/// adopt it at the next — served set, balances and file bytes changing across
/// a restart with nothing edited in between.
pub(super) fn hand_parented_last(directives: Vec<Directive>) -> Vec<Directive> {
    let (rest, hand_parented): (Vec<Directive>, Vec<Directive>) =
        directives.into_iter().partition(|directive| {
            !(matches!(directive, Directive::Transaction(_))
                && LedgerService::is_operator_input(directive)
                && directive.metadata().contains_key(ENVELOPE_KEY_PARENTS))
        });
    // Within the group, a line whose hand parent is another line of the group
    // comes after it (stable; a cycle keeps file order, and the L-75 check
    // refuses it as before).
    //
    // T92 / L-128: lines are matched by the id each will be STORED under — a
    // child names its hand parent by that id, which differs from the file's
    // when I2 resolves an elided posting — and L-129: Kahn's algorithm, ready
    // lines taken in file order, instead of a rescan of the group per line
    // (quadratic: 20,000 lines in a reversed chain took 58 s to boot).
    let ids: Vec<String> = hand_parented
        .iter()
        .map(LedgerService::stored_content_id)
        .collect();
    let mut position: HashMap<&str, usize> = HashMap::new();
    for (index, id) in ids.iter().enumerate() {
        position.entry(id.as_str()).or_insert(index);
    }
    let mut waiting_on = vec![0usize; hand_parented.len()];
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); hand_parented.len()];
    for (index, directive) in hand_parented.iter().enumerate() {
        let Directive::Transaction(txn) = directive else {
            continue;
        };
        let parents: HashSet<&str> = txn.parent_ids().into_iter().collect();
        for parent in parents {
            if let Some(&parent_index) = position.get(parent) {
                if parent_index != index {
                    waiting_on[index] += 1;
                    children[parent_index].push(index);
                }
            }
        }
    }
    let mut ready: std::collections::BinaryHeap<std::cmp::Reverse<usize>> = waiting_on
        .iter()
        .enumerate()
        .filter(|(_, count)| **count == 0)
        .map(|(index, _)| std::cmp::Reverse(index))
        .collect();
    let mut order: Vec<usize> = Vec::with_capacity(hand_parented.len());
    while let Some(std::cmp::Reverse(index)) = ready.pop() {
        order.push(index);
        for &child in &children[index] {
            waiting_on[child] -= 1;
            if waiting_on[child] == 0 {
                ready.push(std::cmp::Reverse(child));
            }
        }
    }
    // What a cycle kept waiting follows, in file order.
    let placed: HashSet<usize> = order.iter().copied().collect();
    order.extend((0..hand_parented.len()).filter(|index| !placed.contains(index)));
    let mut slots: Vec<Option<Directive>> = hand_parented.into_iter().map(Some).collect();
    let ordered: Vec<Directive> = order
        .into_iter()
        .filter_map(|index| slots[index].take())
        .collect();
    rest.into_iter().chain(ordered).collect()
}

/// The `openledger-parents` value a transaction stored under `content_id`
/// names in `dag`: its admissible heads, at most [`MAX_PARENTS`], chosen by
/// [`select_parents`] (§3.3.1, L-40, T64, L-68).
///
/// A free function over any DAG so the H-22 rebuild in
/// `quarantine_out_of_dag` chooses parents by exactly the rule every stamping
/// site uses, against the DAG it is rebuilding.
pub(super) fn choose_parents_in(dag: &LedgerDag, content_id: &str) -> String {
    let mut candidates: Vec<(&str, Option<&str>)> = dag
        .heads_admissible_as_parents_of(content_id)
        .into_iter()
        .map(|head| (head, dag.get(head).and_then(directive_author)))
        .collect();
    select_parents(&mut candidates).join(",")
}

/// Mutable access to whichever directive kind's metadata map this is.
///
/// One place, rather than the same ten-arm match written out at each site.
pub(super) fn directive_metadata_mut(directive: &mut Directive) -> &mut Metadata {
    match directive {
        Directive::Transaction(d) => &mut d.metadata,
        Directive::Open(d) => &mut d.metadata,
        Directive::Close(d) => &mut d.metadata,
        Directive::Commodity(d) => &mut d.metadata,
        Directive::Pad(d) => &mut d.metadata,
        Directive::Balance(d) => &mut d.metadata,
        Directive::Note(d) => &mut d.metadata,
        Directive::Document(d) => &mut d.metadata,
        Directive::Event(d) => &mut d.metadata,
        Directive::Price(d) => &mut d.metadata,
    }
}

impl LedgerService {
    /// Reconcile external edits to the `.bean` file (§3.3, CT-12).
    ///
    /// Re-reads the file, parses it, computes content IDs, and union-merges
    /// any new directives into the DAG. External transactions that lack
    /// envelope keys are adopted with the local author ID and current
    /// Lamport clock. After merge, re-persists to ensure canonical form.
    ///
    /// Returns the number of new directives adopted.
    pub fn reconcile_file(&mut self) -> Result<crate::file_watcher::ReconcileResult, ServiceError> {
        let result = self.reconcile_file_staged()?;

        // Re-persist in canonical form (L-13: reload from disk if it fails).
        //
        // T44: a COMPACTION, not an append. Reconcile's output is a canonical
        // rewrite — it drops the entries it refused and re-spells everything
        // else — and neither of those is something a journal record can say.
        //
        // M-37(b): on `rejected > 0` as well as `new_directives > 0`. The L-12
        // warning says the canonical re-persist drops what was refused, and
        // until this ran only on adoptions that was false for a rejected-ONLY
        // edit: the entry stayed on disk and the next boot loaded it raw,
        // without the I3 check that had just refused it. Quarantined entries
        // are counted in `rejected` too and are NOT dropped by this rewrite
        // (H-08's split) — the extra compaction on their account is harmless.
        // And whenever the service already knows the file must be rewritten
        // (`force_compaction` — e.g. the file vanished, H-15), do it now.
        if result.new_directives > 0 || result.rejected > 0 || self.force_compaction {
            self.compact()?;
        }

        Ok(result)
    }

    /// [`Self::reconcile_file`] without the write (T44).
    ///
    /// Union-merges the file into memory and, when anything was adopted, marks
    /// the next commit as a forced compaction. The caller drives that commit —
    /// `reconcile_file` does it inline, the node's file watcher does it off the
    /// ledger write lock.
    ///
    /// # The identical-bytes short-circuit (M-29)
    ///
    /// [`Self::adopt_external_edits`] has always compared the file's hash
    /// against [`Self::last_file_hash`] and returned on a match; this path did
    /// not, and it is the one the file watcher drives — under the **write**
    /// lock, four times a second, on every change including the node's own
    /// writes. So a self-write cost a full `parse_file` plus a content id per
    /// directive with readers blocked, to discover that every directive was a
    /// duplicate.
    ///
    /// The two entry points now carry the same guard in the same shape. The
    /// probe is re-baselined from this read either way, so an editor that
    /// merely touched the mtime does not escalate the next append.
    ///
    /// # H-14, H-15, M-37(b)
    ///
    /// The marker and byte count are re-baselined only on identical bytes;
    /// on a real edit `reconcile_content` records them after the parse (H-14).
    /// A file that is *gone* is nothing to reconcile: the next commit is
    /// forced to be a compaction, which recreates it from memory (H-15). And
    /// the forced compaction is armed on `rejected > 0` as well, so the
    /// canonical re-persist the L-12 warning promises actually happens
    /// (M-37(b); see [`Self::reconcile_file`]).
    pub fn reconcile_file_staged(
        &mut self,
    ) -> Result<crate::file_watcher::ReconcileResult, ServiceError> {
        let nothing = crate::file_watcher::ReconcileResult {
            new_directives: 0,
            duplicates: 0,
            rejected: 0,
        };
        let content = match read_ledger_file(&self.file_path) {
            Ok(content) => content,
            Err(ServiceError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                warn!(
                    file = %self.file_path.display(),
                    directives = self.dag.len(),
                    "ledger file is MISSING on disk — removed or renamed while this node was \
                     running. Nothing to reconcile; the next commit is a full rewrite that \
                     recreates it from memory with every directive in it (H-15)"
                );
                self.canonical_marker = None;
                self.canonical_bytes = 0;
                self.canonical_is_current = false;
                self.force_compaction = true;
                return Ok(nothing);
            }
            Err(error) => return Err(error),
        };
        if file_content_hash(&content) == self.last_file_hash {
            self.canonical_marker = FileMarker::of(&self.file_path);
            self.canonical_bytes = content.len() as u64;
            return Ok(nothing);
        }
        let result = self.reconcile_content(&content)?;
        if result.new_directives > 0 || result.rejected > 0 {
            self.force_compaction = true;
        }
        Ok(result)
    }

    /// Does the service already know its next commit must be a full rewrite?
    /// (T44's `force_compaction`, read-only.)
    ///
    /// For the node's file watcher, which drives the commit after
    /// [`Self::reconcile_file_staged`] itself: a reconcile that adopted or
    /// refused something arms this, and so does a reconcile that found the
    /// file missing (H-15) — a case the watcher cannot see in the
    /// `ReconcileResult`, which has nothing to count.
    pub fn compaction_pending(&self) -> bool {
        self.force_compaction
    }

    /// Is `hash` — lowercase-hex SHA-256 of the canonical file's bytes — the
    /// text this service last wrote to, or last read from, the `.bean`? (M-29)
    ///
    /// The file watcher's self-write suppression. The watcher has already
    /// hashed the bytes it polled; this lets it answer "that change was us"
    /// against a **read** lock and skip the write permit, the write lock and
    /// the reconcile entirely, rather than taking all three to be told that
    /// every directive it just re-parsed was a duplicate.
    ///
    /// Conservative in the cheap direction: a `false` answer costs one wasted
    /// reconcile, which the short-circuit in [`Self::reconcile_file_staged`]
    /// then catches with this service's own hash of its own read.
    pub fn file_hash_is_current(&self, hash: &str) -> bool {
        hash == self.last_file_hash
    }

    /// Union-merge already-read file text into memory — the body of
    /// [`Self::reconcile_file`], without the read and without the re-persist.
    ///
    /// Split out so the pre-persist hand-edit adoption
    /// ([`Self::adopt_external_edits`]) can reuse it on bytes it has already read
    /// and hashed, and so that adoption cannot recurse back into a persist.
    ///
    /// Two L-12 properties live here:
    ///
    /// 1. **Canonical order.** The input is sorted by `(date, type_priority)`
    ///    exactly as [`Self::boot`] sorts it, with the file order preserved for
    ///    ties (the sort is stable). Processing raw file order made adoption
    ///    depend on where in the file a human happened to paste something: an
    ///    `open` typed below the transaction that uses it left that transaction
    ///    rejected for referencing an unopened account, and the very same file
    ///    loaded cleanly on the next boot — which sorts.
    /// 2. **Rejections are surfaced.** Anything refused here is dropped from the
    ///    file by the canonical re-persist that follows, so every rejection is
    ///    logged with its content id and the reason before that happens, rather
    ///    than collapsing into an opaque count.
    pub(super) fn reconcile_content(
        &mut self,
        content: &str,
    ) -> Result<crate::file_watcher::ReconcileResult, ServiceError> {
        // T99 / L-143: typed copies boot parked belong to the boot pipeline;
        // the live path adopts what the file holds now, by its own rules.
        self.typed_copies.clear();
        let content_hash = file_content_hash(content);
        // M-29: is this text the one this service itself last wrote (or read)?
        let is_own_bytes = content_hash == self.last_file_hash;

        // H-14: PARSE FIRST. Nothing about this text — not its hash, not its
        // size, not its `stat` marker, not the canonical flag — is recorded
        // until it is known to parse. These four used to be written above
        // this point, so a file that then failed to parse became "what this
        // service last read": the next commit of any kind saw an unchanged
        // baseline, adopted nothing, and rewrote the file from memory over the
        // operator's edit — valid lines included — after two log lines had
        // said it was safe. Now a file that does not parse leaves every fact
        // this service holds about the `.bean` untouched, so the very next
        // `prepare` re-detects it as foreign, re-reads it, and refuses again:
        // a broken hand edit blocks writes until it is repaired, which is what
        // the documentation has always claimed.
        //
        // L-45: the file this reconcile is reading contains, at its tail,
        // whatever boot could not parse — `compaction_text` puts it back on
        // every rewrite precisely so it is not lost. So `parse_file` over the
        // whole text fails on a ledger that is behaving exactly as designed,
        // and the pre-T51 hard failure here would have wedged every subsequent
        // write on such a node: reconcile refuses, `adopt_external_edits`
        // propagates the refusal, and `prepare`'s compaction branch can never
        // complete again.
        //
        // The exemption is deliberately the narrowest one that works: a block
        // is skipped ONLY if its text is byte-identical to one this service is
        // already holding in `quarantined_text`. Anything else that fails to
        // parse — a human mid-edit, a truncated paste — still refuses the whole
        // reconcile, which is the property the original hard failure exists for
        // and which is worth keeping: canonicalising over a half-written file
        // is not recoverable, blocking writes until it is repaired is.
        //
        // Re-deriving the set from the text just read is also how a block
        // LEAVES the quarantine. It is the raw-text analogue of
        // `release_quarantined_now_in_dag`: an operator who repairs the account
        // name makes that block parse, so it is adopted as an ordinary
        // directive and is no longer retained; one who deletes the block
        // outright is simply obeyed. Without this the next compaction would
        // splice the stale broken text back in underneath the repaired copy.
        let (file_directives, retained_text) = match parse_file(content) {
            // Everything parses: nothing is being held back any more.
            Ok(directives) => (directives, BTreeSet::new()),
            Err(errors) => match self.parse_around_quarantined_text(content) {
                Some((directives, retained)) => (directives, retained),
                None => {
                    warn!(
                        file = %self.file_path.display(),
                        errors = %errors.iter().map(|e| e.to_string()).collect::<Vec<_>>().join("; "),
                        "ledger file does not parse; NOT reconciling and NOT persisting over it — \
                         repair the file (the in-memory ledger is unaffected)"
                    );
                    return Err(ServiceError::Parse(errors));
                }
            },
        };

        // The text parsed: it is now the baseline for the next persist's
        // hand-edit check (L-30). T44: and the cheap `stat` probe's baseline
        // too, so the facts this service holds about the canonical file are
        // refreshed together and cannot drift.
        self.last_file_hash = content_hash;
        self.canonical_bytes = content.len() as u64;
        self.canonical_marker = FileMarker::of(&self.file_path);
        self.quarantined_text = retained_text;
        // Whatever is on disk right now came from a text editor, not from this
        // service's serializer: it needs canonicalising, not appending to.
        //
        // M-29: unless it did come from this service's serializer. The clear
        // was unconditional, and `prepare` turns `canonical_is_current = false`
        // into a forced rewrite — so ONE watcher tick over the node's own
        // compaction output permanently demoted every subsequent commit from
        // T44's `Append` to a full `Compact`, and each of those compactions
        // rewrote the file, which the watcher saw, which cleared the flag
        // again. A self-sustaining loop that turned the append-only path off
        // for the life of the process, entered by the node writing its own
        // file.
        //
        // Setting it, never clearing it, is the correct asymmetry: this
        // function learns "the file is not canonical" but never learns "it is"
        // — only a compaction this service performed knows that, and
        // `finish_commit` is where it is recorded. So identical bytes leave the
        // flag exactly as it was: still `false` after boot (which read a file
        // it did not write), still `true` after a compaction.
        if !is_own_bytes {
            self.canonical_is_current = false;
        }

        // T85: every id this reconcile may adopt — a complete envelope's parent
        // can come later in canonical order (see `reconcile_batch_ids`).
        self.reconcile_batch_ids = file_directives.iter().map(compute_content_id).collect();

        // L-12: canonical order, like boot. Stable, so equal keys keep file order.
        let mut file_directives = file_directives;
        file_directives.sort_by(|a, b| {
            a.date()
                .cmp(&b.date())
                .then_with(|| a.type_priority().cmp(&b.type_priority()))
        });
        // T89 / L-108: and hand lines that spell their own parents after the
        // rest, as boot adopts them.
        let file_directives = hand_parented_last(file_directives);

        // M-38: the same Kahn pre-scan boot runs, over the file ∪ the live
        // quarantine. The DAG's own I8 check catches a planted cycle only on
        // the SECOND insert — the first member's partner is absent, so it goes
        // in — and `release_quarantined_now_in_dag` then freed that member
        // from the quarantine, it became a head, this node's own next
        // transaction descended from it, and the next boot's scan quarantined
        // the cycle AND that transaction: signed, served, then gone from every
        // balance on every restart until the file was hand-repaired. A member
        // found here stays quarantined (a newly planted one joins the
        // quarantine, so the rewrite that follows keeps it in the file rather
        // than dropping it — the next boot would quarantine it anyway) and is
        // never inserted. The union matters: the file may hold one member and
        // the quarantine the other. O(transactions) hashes on a path that
        // already hashes every directive once; empty on every honest file.
        let cycle_blocked = {
            let candidates: Vec<&Directive> = file_directives
                .iter()
                .chain(self.live_quarantine().map(|(_, directive)| directive))
                .collect();
            directives_blocked_by_parent_cycles(&candidates)
        };

        let mut tally = AdoptionTally::default();

        for directive in file_directives {
            let content_id = compute_content_id(&directive);

            // Check if already in DAG (G-Set dedup).
            if self.dag.get(&content_id).is_some() {
                tally.duplicates += 1;
                continue;
            }

            if !cycle_blocked.is_empty()
                && matches!(directive, Directive::Transaction(_))
                && cycle_blocked.contains(&content_id)
            {
                tally.refuse(
                    content_id.clone(),
                    "transaction sits on (or descends from) an openledger-parents cycle; \
                     quarantined, not adopted (M-38)"
                        .to_owned(),
                );
                self.quarantined.entry(content_id).or_insert(directive);
                continue;
            }

            self.adopt_file_directive(directive, content_id, &mut tally, AdoptionPath::Live);
        }
        self.reconcile_batch_ids.clear();
        // T85 / H-23: a parent the loop admitted on the strength of being in
        // this file can itself have been refused a moment later; what named
        // it is then a record no peer could adopt, and goes too.
        self.quarantine_unservable_history();

        // H-08: a repaired directive keeps its content id (the envelope is
        // outside the hash), so the operator's fix arrives above as an ordinary
        // insert under the id the quarantine is keyed by. Release those now, so
        // the compaction that follows writes the DAG's repaired copy once
        // rather than the DAG's copy *and* the quarantine's broken one.
        self.release_quarantined_now_in_dag();

        // L-12: whatever this reconcile refused is about to be deleted from the
        // file by the canonical re-persist. Say so, per entry, with the id and
        // the reason — a bare `rejected: 3` in a counter leaves an operator no
        // way to find out what they lost.
        //
        // H-08: except the quarantined ones. A reconcile re-reads the whole
        // file, so it sees boot's quarantined records too and refuses them for
        // the same reason boot did — but those are precisely the entries the
        // compaction keeps. Splitting the log line is not cosmetic: telling an
        // operator their records are about to be dropped when they are not is
        // how an operator is talked into "fixing" it by hand under a running
        // node, which L-30 says is unsupported.
        let (preserved, dropped): (Vec<_>, Vec<_>) = tally
            .rejections
            .iter()
            .partition(|(id, _)| self.quarantined.contains_key(id));
        if !dropped.is_empty() {
            warn!(
                rejected = dropped.len(),
                entries = %dropped
                    .iter()
                    .map(|(id, reason)| format!("{id}: {reason}"))
                    .collect::<Vec<_>>()
                    .join(" | "),
                file = %self.file_path.display(),
                "reconcile refused ledger-file entries; they are NOT adopted and the canonical \
                 re-persist will drop them from the file"
            );
        }
        if !preserved.is_empty() {
            warn!(
                quarantined = preserved.len(),
                entries = %preserved
                    .iter()
                    .map(|(id, reason)| format!("{id}: {reason}"))
                    .collect::<Vec<_>>()
                    .join(" | "),
                file = %self.file_path.display(),
                "reconcile refused ledger-file entries that are already quarantined; they stay \
                 in the file and the canonical re-persist writes them back unchanged (H-08)"
            );
        }

        // T82 / L-80: a hand edit can grow the canonical form past the cap
        // (or shrink it back under); re-measure only when the file was not
        // this service's own output.
        if !is_own_bytes {
            self.measure_canonical_over_cap(true);
        }

        Ok(crate::file_watcher::ReconcileResult {
            new_directives: tally.new_directives,
            duplicates: tally.duplicates,
            rejected: tally.rejected,
        })
    }

    /// Adopt ONE directive read from this node's own `.bean` file — the body
    /// of the reconcile loop, shared with boot's operator-input adoption
    /// (H-13) so the two file paths cannot drift apart.
    ///
    /// `content_id` is the id of the directive as the file spells it; the
    /// caller has already checked it is not in the DAG. Every refusal is
    /// recorded in `tally` with its reason, and the return value tells the
    /// caller which of the three things happened, with the **stored** id on
    /// an insert (it differs from `content_id` when I2 resolved an elided
    /// posting). The lamport clock moves only in the `Inserted` arms (L-55):
    /// every check below `continue`s past the insert on failure, and the
    /// ordering T46 fixed on the peer path — adopt after validation, never
    /// before — applies to the file path identically.
    pub(super) fn adopt_file_directive(
        &mut self,
        mut directive: Directive,
        content_id: String,
        tally: &mut AdoptionTally,
        path: AdoptionPath,
    ) -> FileAdoption {
        // H-04: never adopt a directive whose date the file grammar cannot
        // read back — the next persist would brick every later boot. Checked
        // before the envelope stamp so a rejection cannot move the Lamport
        // clock either. `read_date` cannot currently yield such a year, so
        // this is a guard against future parser or format changes.
        if let Err(error) = validate_directive_dates(&directive) {
            tally.refuse(content_id, error.to_string());
            return FileAdoption::Refused;
        }

        // H-06: a file may legitimately carry the four envelope keys at
        // directive level (that is how a peer's directive round-trips), but
        // any other `openledger-*` key — and any at posting level — is
        // unvalidated metadata that the content hash ignores and that
        // `extract_envelope` would promote into the envelope on the next
        // serve, bricking the receiving peer's closed-set check.
        // L-26: control characters in body strings would be written
        // verbatim into every replica's file from here on.
        // T41: and the same `MAX_PARENTS` fan-in cap the wire path applies.
        // The cap was wire-only, so a hand edit — or a pre-hardening file —
        // could carry an `openledger-parents` list of any length, which the
        // next persist would then serve to every peer, where it is refused.
        // M-20: and the rest of the wire path's check set, which this path
        // simply did not have. Since L-11 reconcile SIGNS what it adopts,
        // so an entry the file accepts and the wire refuses is adopted,
        // signed with this node's key, persisted and served — and then
        // refused by every peer forever while this node keeps advertising
        // it. Permanent divergence plus perpetual re-Want churn, reached
        // through a text editor rather than a peer. The three missing
        // checks were:
        //
        // * **L-02** — `enforce_economic_bean_limit`. Called on all three
        //   local API paths and on `stage_remote_directive`, never here,
        //   and nothing else bounds body length: the parser caps charsets,
        //   not lengths.
        // * **L-29** — parent txid FORM. `parent_txid_is_well_formed` had
        //   exactly one production call site. Parents are envelope metadata
        //   and are stripped before hashing, so an uppercase-hex spelling
        //   of a real txid changes no content id, passes `validate_parent_
        //   fan_in` (a count check), passes `LedgerDag::insert` (no form
        //   check), and then never resolves.
        // * The **format** of `openledger-lamport`. The adoption arm below
        //   read it with `.parse().ok()` and treated failure as "leave the
        //   clock alone", so `openledger-lamport: "seven"` was adopted
        //   silently. Its RANGE is T46's `checked_lamport`, applied a few
        //   lines down — one rule, one constant, not a second copy here.
        //
        // Placed in this chain, i.e. BEFORE the envelope stamp, so a
        // refusal costs the entry its line in `rejections` and moves
        // neither the Lamport clock nor a half-stamped envelope — the same
        // ordering rule H-04 states above and T27 states for the local
        // paths.
        // T89 / L-109, decision (34): a complete envelope — a node's record,
        // pasted or re-read — is stripped as boot strips it, not refused and
        // then deleted from the file by the re-persist (the same bytes had two
        // fates). Operator input keeps H-06's refusal below.
        if !Self::is_operator_input(&directive) {
            let stray = strip_stray_envelope_keys(&mut directive);
            if !stray.is_empty() {
                warn!(
                    id = %content_id,
                    keys = %stray.join(", "),
                    file = %self.file_path.display(),
                    "dropped openledger-* metadata keys that are not part of the envelope from a \
                     node-written record the reconcile read; they are not hashed, not signed and \
                     never sent to a peer (L-109, L-89, H-06)"
                );
            }
        }
        if let Err(error) = validate_body_envelope_keys(&directive, ENVELOPE_KEYS)
            .and_then(|()| validate_body_strings(&directive))
        {
            tally.refuse(content_id, error.to_string());
            return FileAdoption::Refused;
        }
        // T90 / L-126: boot quarantines a record over the fan-in cap, the body
        // cap or with a malformed envelope, and keeps it in the file; so does
        // the live path now, for history.
        if let Err(error) = validate_parent_fan_in(&directive)
            .and_then(|()| validate_file_ingest_parity(&directive))
        {
            self.hold_refused_file_entry(&content_id, &directive);
            tally.refuse(content_id, error.to_string());
            return FileAdoption::Refused;
        }

        // Adopt: stamp envelope metadata only if missing.
        // If the directive already has envelope keys (e.g. from another node),
        // preserve them as-is to maintain content hash stability.
        //
        // M-47: "missing" is the same test boot applies — either key absent.
        // A half envelope is operator input, and the whole envelope is this
        // node's to stamp: a hand-typed lamport is not a clock value this
        // node issued (honouring it could re-issue an `(author, lamport)`
        // pair, M-18), and a signature under a freshly stamped lamport is
        // stale by construction.
        let needs_stamp = Self::is_operator_input(&directive);
        // T84 / M-57, decision (16): boot's operator input is stamped for real
        // in `finalize_operator_input`, after every pass has settled the clock;
        // the lamport written here is a placeholder that does not move it.
        let provisional_stamp = needs_stamp && matches!(path, AdoptionPath::Boot);

        // M-54 (T79): operator input is this node's own authorship. An entry
        // whose file-spelled `openledger-author` names another node cannot be
        // signed here, so every signing peer refuses it — and adopted, it is
        // a head this node's next write names as a parent, so everything
        // written after it is orphaned mesh-wide (M-47's consequence). On the
        // live path the identity is final, so the rule runs here, before
        // anything is stamped; at boot the author may still be a placeholder
        // and the rule runs in `finalize_operator_input`.
        if needs_stamp && path == AdoptionPath::Live {
            if let Some(other) = directive_author(&directive) {
                if other != self.author_id {
                    tally.refuse(content_id, Self::foreign_operator_input_reason(other));
                    return FileAdoption::Refused;
                }
            }
        }

        // T81 / M-51, M-52: a complete-envelope transaction descending from
        // history boot refused under a content rule stays quarantined with
        // it — the live reconcile re-reads the whole file, and would
        // otherwise re-adopt the descendants boot held back.
        //
        // T90 / H-24, decision (36): judged on THIS copy's parents, as the
        // wire judges it. The file's held copy of a closure member is already
        // in the quarantine (boot put it there) and is written back as it is;
        // a copy spelled with parents this node serves — the operator
        // restating the chain in place — is adopted under the same id.
        if !needs_stamp {
            if let Directive::Transaction(txn) = &directive {
                if let Some(parent) = txn
                    .parent_ids()
                    .into_iter()
                    .find(|parent| self.names_a_held_back_parent(parent))
                    .map(str::to_owned)
                {
                    self.hold_refused_file_entry(&content_id, &directive);
                    tally.refuse(
                        content_id,
                        format!(
                            "descends from {parent}, a record no peer accepts (over a limit peers \
                             hold history to, or an amount past the cap); quarantined with it \
                             (M-51, M-52)"
                        ),
                    );
                    return FileAdoption::Refused;
                }
            }
        }

        // L-75: parents the operator spelled must resolve. They are honoured
        // verbatim below, and a parent that exists nowhere became a signed
        // head every later write descended from — orphaned on every peer, no
        // warning. In the DAG alone (T79 / H-22): a quarantined record is
        // never served, so no peer can resolve a parent that is only in this
        // node's quarantine. At boot the DAG still holds history the
        // signature pass has not judged yet; `quarantine_out_of_dag` checks
        // again once it has. Checked before the stamp, so a refusal moves
        // nothing.
        if needs_stamp {
            if let Directive::Transaction(txn) = &directive {
                if let Some(parent) = txn
                    .parent_ids()
                    .into_iter()
                    .find(|parent| self.dag.get(parent).is_none())
                {
                    let held = if self.quarantined.contains_key(parent) {
                        "is held in this node's quarantine, which is never served"
                    } else {
                        "exists nowhere in this ledger"
                    };
                    tally.refuse(
                        content_id,
                        format!(
                            "openledger-parents names {parent}, which {held}; a hand-spelled \
                             parent must be a record this node serves, and since H-22 one in \
                             the quarantine does not count — remove the openledger-parents \
                             line to let this node choose the parents (L-75)"
                        ),
                    );
                    return FileAdoption::Refused;
                }
            }
        }

        let metadata = directive_metadata_mut(&mut directive);

        // H-07: the clock value this adoption would move to, bounds-checked
        // BEFORE anything is written. The ceiling is not a wire rule — a
        // file is an ingest path too, and a hand-edited (or pre-T46) `.bean`
        // carrying a value at the cap would otherwise walk this node's clock
        // past it exactly as a hostile peer once could. Computing it first
        // means a refusal costs the directive its line in `rejections` and
        // leaves both the clock and a half-stamped envelope untouched.
        let next_lamport = if needs_stamp {
            self.next_stamp()
        } else {
            // Update local Lamport clock to at least match the incoming
            // value.
            //
            // T41 — the `+1` asymmetry with peer ingest, documented rather
            // than unified. `stage_remote_directive` does
            // `max(local, remote).saturating_add(1)`; this does `max(local,
            // incoming)` with no `+1`, and **both preserve the (author,
            // lamport) uniqueness M-18 needs**, because the increment that
            // matters happens at STAMPING time, not at adoption time:
            // `stamp_transaction_envelope`/`stamp_directive_envelope`
            // pre-increment, so the next value this node signs is
            // `max(local, incoming) + 1` — strictly greater than anything
            // adopted here — either way. The peer-ingest form simply
            // reserves that slot one step earlier, leaving the clock one
            // ahead; it is more conservative, not more correct.
            //
            // NOT unified, deliberately. The clock is serialized into the
            // envelope of every directive this node subsequently stamps, so
            // changing the arithmetic on either path changes the `.bean`
            // bytes for an identical input sequence — which is exactly what
            // T27's `batch_path_is_byte_identical_to_per_entry_path` and
            // T29's byte-identical convergence assertions pin. A cosmetic
            // unification is not worth perturbing determinism tests whose
            // whole value is that they are sensitive.
            //
            // T63 / H-12: the one Lamport rule on `max(local, incoming)` —
            // the value this path moves the clock to — and the adoption
            // ratchet, exactly as on the peer path. A file is operator input
            // here, and pasting a peer's directive into it must not be a way
            // around either bound. `author` names whom to remove from the
            // allowlist when either refuses.
            match metadata
                .get("openledger-lamport")
                .and_then(|v| v.parse::<u64>().ok())
            {
                Some(incoming_lamport) => {
                    let author = metadata.get(ENVELOPE_KEY_AUTHOR).map(String::as_str);
                    checked_lamport(self.lamport_clock.max(incoming_lamport), author).and_then(
                        |next| {
                            check_lamport_advance(self.lamport_clock, incoming_lamport, author)
                                .map(|()| next)
                        },
                    )
                }
                // Unparsable: the clock stays exactly where it is, as it did
                // before this guard existed.
                None => Ok(self.lamport_clock),
            }
        };
        let next_lamport = match next_lamport {
            Ok(value) => value,
            // T103 / L-140, decision (69a): the ratchet on a complete
            // envelope is the running node's alone. Boot loads the same bytes
            // as history, above any ratchet (a bootstrap join relies on it),
            // so the refusal says how to keep the record rather than holding
            // it — held live, it would be served only after a restart.
            Err(error @ ServiceError::LamportAdvance { .. })
                if !needs_stamp && matches!(path, AdoptionPath::Live) =>
            {
                tally.refuse(
                    content_id,
                    format!(
                        "{error} Refused by the running node only (L-140): boot adopts the \
                         same bytes as history, and this rewrite drops them — to keep the \
                         record, stop the node, put it back in the file and start it"
                    ),
                );
                return FileAdoption::Refused;
            }
            Err(error) => {
                tally.refuse(content_id, error.to_string());
                return FileAdoption::Refused;
            }
        };

        if needs_stamp {
            // M-47: a signature the file carried was made over a different
            // lamport (or by nobody); under the stamp below it verifies
            // nowhere, which is worse than none — `sign_adopted_entry` makes
            // a fresh one when this node can.
            metadata.remove(ENVELOPE_KEY_SIGNATURE);
            if !metadata.contains_key("openledger-author") {
                metadata.insert("openledger-author".to_owned(), self.author_id.clone());
            }
            metadata.insert("openledger-lamport".to_owned(), next_lamport.to_string());
        }
        // L-55: `self.lamport_clock = next_lamport` used to sit here, ahead
        // of `enforce_resource_limits`, `validate_transaction`, the
        // resolved-body cap and `dag.insert` — each of which refuses with the
        // clock already moved, so a rejected hand-appended entry carrying
        // `openledger-lamport: "5000"` walked the clock from 3 to 5000 and
        // the next authored envelope was 5001. The assignment now lives in
        // the two `Inserted` arms below, mirroring the peer path.

        // For transactions: set parents to current heads if not already set.
        //
        // Provisionally against the file's content id; re-chosen (L-40) once
        // the id the DAG will store the entry under is known — see
        // `stamped_parents`. Both through `choose_parents`, so both are capped
        // at `MAX_PARENTS` (T64 / H-16): this path signs what it adopts, and an
        // over-cap parent list signed here is refused by every peer exactly as
        // an over-cap local append was.
        let mut stamped_parents = false;
        if let Directive::Transaction(txn) = &mut directive {
            if !txn.metadata.contains_key("openledger-parents") {
                stamped_parents = true;
                txn.metadata.insert(
                    "openledger-parents".to_owned(),
                    self.choose_committed_parents(&content_id),
                );
            }
        }

        // Validate transactions (I1–I3, I9).
        //
        // T81: operator input is this node's authorship and is counted as it
        // will be stored, signature included (M-55); a complete envelope is
        // history — a peer's record, or this node's own round-tripped — and
        // is held to the rule every peer and boot hold history to (M-51).
        let limits = if needs_stamp {
            enforce_resource_limits_as_stored(&directive)
        } else {
            enforce_resource_limits_for(&directive, ResourceRule::History)
        };
        if let Err(error) = limits {
            // T90 / L-126: a limit every peer holds history to — boot holds the
            // record (and seeds the closure with it); so does the live path.
            if !needs_stamp {
                self.hold_refused_file_entry(&content_id, &directive);
            }
            tally.refuse(content_id, error.to_string());
            return FileAdoption::Refused;
        }
        if let Directive::Transaction(txn) = &directive {
            // T98 / M-09, decision (54): the file is data, judged by the rule
            // every peer applies — a `close` never refuses it.
            match validate_transaction_as_data(txn, &self.accounts) {
                Ok(validated) => {
                    // Build the final transaction with the resolved postings.
                    let final_txn = Transaction {
                        postings: validated.postings,
                        ..txn.clone()
                    };
                    let mut final_directive = Directive::Transaction(final_txn);
                    // L-11: sign over the id the DAG will actually store it
                    // under. That is NOT `content_id` when I2 resolved an
                    // elided posting — the resolved body hashes differently,
                    // and a signature over the pre-resolution id would fail
                    // on every peer.
                    let stored_id = compute_content_id(&final_directive);
                    // L-40: parents this node chose must not include a head
                    // that already names `stored_id` through a dangling
                    // `openledger-parents` — that is a cycle this node would
                    // build itself, refused below and, had it landed,
                    // quarantined with the operator's entry at next boot.
                    // Chosen against `stored_id`, not `content_id`: the DAG
                    // keys (and a planted pointer targets) the resolved
                    // body. Identical to the provisional set on every
                    // honest ledger. Parents the FILE spelled are the
                    // operator's own and are left alone.
                    if stamped_parents {
                        let parents = self.choose_committed_parents(&stored_id);
                        directive_metadata_mut(&mut final_directive)
                            .insert("openledger-parents".to_owned(), parents);
                    }
                    // M-20 / L-02, the second application. The guard chain
                    // above measured the body as the FILE spells it; I2
                    // then resolved the elided posting, which is what the
                    // signature, the DAG and every peer actually see. A
                    // body within the cap before resolution can be over it
                    // after, and the wire cap is enforced on the resolved
                    // form — so the entry must be re-measured on this side
                    // of `validate_transaction` and before
                    // `sign_adopted_entry`. Costs one serialization on the
                    // reconcile path only, which already rewrites the whole
                    // file.
                    if let Err(error) = enforce_economic_bean_limit(&final_directive) {
                        if !needs_stamp {
                            self.hold_refused_file_entry(&content_id, &directive);
                        }
                        tally.refuse(content_id, error.to_string());
                        return FileAdoption::Refused;
                    }
                    // T85 / M-56, H-23: a full envelope is history, and history
                    // this node serves must be what a peer can adopt — every
                    // parent it names already here. Boot holds such a record
                    // (`quarantine_unservable_history`); so does the live
                    // path, in the quarantine, so the canonical re-persist
                    // keeps it in the file and a peer that re-supplies its
                    // parent (and then it) heals it. Before T85 the live path
                    // inserted it leniently with a dangling parent (0924 §5).
                    if !needs_stamp {
                        let missing_parent = match &final_directive {
                            Directive::Transaction(txn) => txn
                                .parent_ids()
                                .into_iter()
                                .find(|parent| {
                                    self.dag.get(parent).is_none()
                                        && (!self.reconcile_batch_ids.contains(*parent)
                                            || self.quarantined.contains_key(*parent))
                                })
                                .map(str::to_owned),
                            _ => None,
                        };
                        if let Some(parent) = missing_parent {
                            // T103 / L-141: counted, as boot counts it.
                            self.fold_held_own_lamport(&final_directive);
                            self.quarantined
                                .entry(stored_id.clone())
                                .or_insert_with(|| final_directive.clone());
                            tally.refuse(
                                content_id,
                                format!(
                                    "its parent {parent} is not served by this node, so no peer \
                                     lacking it could adopt it; held in the quarantine until a \
                                     peer re-supplies the parent (H-23)"
                                ),
                            );
                            return FileAdoption::Refused;
                        }
                    }
                    // H-20: a full envelope is adopted as history, and the
                    // live path holds it to the same signature check boot
                    // does — against the id it is stored under.
                    // T80 / M-53: the same re-attribution boot applies.
                    if !needs_stamp {
                        if let Some(owned) =
                            self.reattributed_placeholder_record(&stored_id, &final_directive)
                        {
                            final_directive = owned;
                        } else if let HistoryVerdict::Refused(reason) =
                            self.verify_history_directive(&stored_id, &final_directive)
                        {
                            tally.refuse(content_id, reason);
                            return FileAdoption::Refused;
                        }
                    }
                    self.sign_adopted_entry(&mut final_directive, &stored_id);
                    match self.dag.insert(final_directive.clone(), false) {
                        Ok(InsertResult::Inserted { .. }) => {
                            // L-55: adopted, so the clock moves — and only now.
                            // T84 / M-57, decision (16): except for operator
                            // input adopted at boot, whose stamp here is
                            // provisional — `finalize_operator_input` stamps
                            // it from the clock the signature pass settles.
                            let clock_before = self.lamport_clock;
                            if !provisional_stamp {
                                self.lamport_clock = next_lamport;
                            }
                            self.warn_if_adoption_opens_a_lamport_gap(
                                clock_before,
                                final_directive.lamport_clock(),
                                directive_author(&final_directive),
                            );
                            self.read_model.index_directive(&final_directive);
                            // M-46: adopted FROM the file, so on disk
                            // already — not staged. Tracked apart from
                            // `pending_ids` so the L-13 floor never counts
                            // it as "never on disk"; its non-emptiness is
                            // what makes the next commit the rewrite that
                            // spells it canonically (see `prepare`).
                            self.adopted_from_file.insert(stored_id.clone());
                            // T90 / H-24: a copy of a closure member with
                            // parents this node serves; no longer held back —
                            // at boot once finalised (T99 / L-145).
                            if path == AdoptionPath::Live {
                                self.refused_history_closure.remove(&stored_id);
                            }
                            tally.new_directives += 1;
                            FileAdoption::Inserted(stored_id)
                        }
                        Ok(InsertResult::Duplicate { .. }) => {
                            tally.duplicates += 1;
                            FileAdoption::Duplicate
                        }
                        Err(error) => {
                            tally.refuse(content_id, error.to_string());
                            FileAdoption::Refused
                        }
                    }
                }
                Err(error) => {
                    // T90 / L-126: a complete envelope the accounts do not
                    // admit is held by boot's served-set rule (H-23) and kept
                    // in the file; the live path holds it too, so the
                    // re-persist does not delete what a restart would keep.
                    if !needs_stamp {
                        self.hold_refused_file_entry(&content_id, &directive);
                    }
                    tally.refuse(content_id, error.to_string());
                    FileAdoption::Refused
                }
            }
        } else {
            // T98 / M-09 remainder, decision (54): a `close` in the file is
            // data, like a peer's — never refused for the transactions dated
            // after it (it is inert over any interval that holds one; see
            // `AccountState::check_account_opened_by`). Refusing it made the
            // verdict depend on what this node held when it read the line: a
            // hand `close` judged at boot before a later hand re-`open` was
            // held at one boot and served at the next (L-153), and one judged
            // while a record was held only here was accepted where every peer
            // refused it (M-75).
            // L-77: a hand-typed `open` of an account that is already open is
            // refused exactly as `open_account` refuses it. Operator input
            // only: a full-envelope `open` is a peer's data (M-09) and joins
            // the lifecycle set at its own position, as it does on the wire.
            //
            // T92 / L-121: on the live path only. At boot the node's own
            // `open` of the account may be one the signature pass is about to
            // hold (edited), which is exactly when the operator adds the hand
            // `open` the H-23 WARN prescribes; `finalize_operator_input`
            // judges L-77 once the pass has run. And no longer while a
            // node-written `open` of the account is held (T85 / L-110,
            // decision (20), retired 2026-09-26): with I9 the union over every
            // `open` (T91), a second `open` the mesh may re-supply changes no
            // verdict, and the refusal made the WARN's own remedy fail — boot
            // and live alike (L-121, L-125).
            if needs_stamp && path == AdoptionPath::Live {
                if let Directive::Open(open) = &directive {
                    if self.accounts.is_open(&open.account) {
                        tally.refuse(
                            content_id,
                            ServiceError::AccountAlreadyOpen {
                                account: open.account.clone(),
                            }
                            .to_string(),
                        );
                        return FileAdoption::Refused;
                    }
                }
            }
            // H-20, T80: see the transaction arm.
            if !needs_stamp {
                if let Some(owned) = self.reattributed_placeholder_record(&content_id, &directive) {
                    directive = owned;
                } else if let HistoryVerdict::Refused(reason) =
                    self.verify_history_directive(&content_id, &directive)
                {
                    tally.refuse(content_id, reason);
                    return FileAdoption::Refused;
                }
            }
            // L-11: a non-transaction body is stored exactly as parsed, so
            // its content id is the one computed at the top of the loop.
            self.sign_adopted_entry(&mut directive, &content_id);
            // Non-transaction directives: insert, then record any lifecycle
            // event under the content id the DAG assigned (M-09).
            match self.dag.insert(directive.clone(), false) {
                Ok(InsertResult::Inserted { .. }) => {
                    // L-55, T84: see the transaction arm.
                    let clock_before = self.lamport_clock;
                    if !provisional_stamp {
                        self.lamport_clock = next_lamport;
                    }
                    self.warn_if_adoption_opens_a_lamport_gap(
                        clock_before,
                        directive.lamport_clock(),
                        directive_author(&directive),
                    );
                    self.accounts.record_lifecycle(&directive, &content_id);
                    self.read_model.index_directive(&directive);
                    // M-46: see the transaction arm above.
                    self.adopted_from_file.insert(content_id.clone());
                    if path == AdoptionPath::Live {
                        self.refused_history_closure.remove(&content_id);
                    }
                    tally.new_directives += 1;
                    FileAdoption::Inserted(content_id)
                }
                Ok(InsertResult::Duplicate { .. }) => {
                    tally.duplicates += 1;
                    FileAdoption::Duplicate
                }
                Err(error) => {
                    tally.refuse(content_id, error.to_string());
                    FileAdoption::Refused
                }
            }
        }
    }

    /// Re-parse a file that `parse_file` refused, skipping only the blocks this
    /// service is already holding verbatim (L-45).
    ///
    /// Returns `Some((directives, retained))` when every block that is NOT
    /// already quarantined parses cleanly — `retained` being exactly the
    /// quarantined blocks this text still contains, which becomes the new
    /// [`Self::quarantined_text`]. Returns `None` the moment any other block
    /// fails, so the caller restores the pre-T51 behaviour: refuse the whole
    /// reconcile and leave the file alone.
    ///
    /// `None` also when nothing is quarantined, so a node that has never held
    /// an unparsable block pays one `is_empty` check and takes the original
    /// path — this is not a general relaxation of the parser, it is a way of
    /// reading back what this same service wrote.
    pub(super) fn parse_around_quarantined_text(
        &self,
        content: &str,
    ) -> Option<(Vec<Directive>, BTreeSet<String>)> {
        if self.quarantined_text.is_empty() {
            return None;
        }

        let mut directives = Vec::new();
        let mut retained = BTreeSet::new();
        for block in split_ledger_blocks(content) {
            if self.quarantined_text.contains(&block.text) {
                retained.insert(block.text);
                continue;
            }
            // L-62: the same per-block parser boot's salvage uses, so a block
            // the whole-file parser refused (a mid-file BOM) is refused here
            // too instead of being adopted.
            match parse_block(&block.text) {
                Ok(parsed) => directives.extend(parsed),
                Err(_) => return None,
            }
        }
        Some((directives, retained))
    }

    /// Sign an entry this reconcile is adopting, when this node can (L-11).
    ///
    /// ## The finding
    ///
    /// A hand-edited entry was adopted into the DAG and persisted, but carried
    /// no `openledger-signature`. With signing enabled every peer rejects an
    /// unsigned directive, so the entry lived on exactly one replica — and
    /// nothing said so. It looked adopted, it showed up in every local query and
    /// report, and it never replicated: split-brain by text editor, silent.
    ///
    /// ## The decision
    ///
    /// **Operator input is a local append.** A human editing this node's `.bean`
    /// is exercising exactly the authority the GraphQL mutations expose — same
    /// machine, same file, same trust boundary — so the entry gets the same
    /// treatment a mutation's would: this node's envelope, this node's author
    /// id, this node's signature, before the first persist. The alternative the
    /// audit offered (refuse reconcile whenever signing is on) fails the same
    /// edit *loudly* instead of silently, which is better but still refuses
    /// something the API would have accepted from the same person.
    ///
    /// ## When it does NOT sign, and why
    ///
    /// * **The entry already carries a signature.** Adopted unchanged, as
    ///   before: it came from a peer (or a round-trip of our own), the signature
    ///   is bound to that author's key, and re-signing would destroy it.
    /// * **`openledger-author` names someone else.** The signature is verified
    ///   against the *author's* public key, so signing another peer's directive
    ///   with our key produces a signature that fails everywhere — strictly
    ///   worse than none. The envelope stamp above only fills in an author when
    ///   the entry has none, so this is the hand-written-author case. It is
    ///   logged rather than silently skipped, because the entry still will not
    ///   replicate and the operator is the only one who can fix it.
    /// * **No signer installed, or signing disabled.** The callback returns
    ///   `None` and adoption is byte-for-byte what it was.
    pub(super) fn sign_adopted_entry(&self, directive: &mut Directive, content_id: &str) {
        let Some(ref signer) = self.signer else {
            return;
        };
        let is_transaction = matches!(directive, Directive::Transaction(_));
        let metadata = directive_metadata_mut(directive);

        if metadata.contains_key(ENVELOPE_KEY_SIGNATURE) {
            return;
        }
        match metadata.get(ENVELOPE_KEY_AUTHOR) {
            Some(author) if author == &self.author_id => {}
            Some(other_author) => {
                // Only reachable when the file itself named an author; the
                // stamp above never overwrites one.
                //
                // T79 / M-54: no longer reachable for OPERATOR INPUT — an
                // entry missing its lamport or signature that names another
                // node is refused before this (live path) or at finalisation
                // (boot), because adopted it was a parent of every later own
                // write and the reasons below did not hold for it (it is not
                // inert: it is a head). And since T80 a signing-off gl-node
                // installs no signer, so this function returns above; with
                // signing on, a complete envelope is judged by the verifier
                // before it gets here. What still reaches this arm is a
                // library caller that installs a signer and no verifier, with
                // a complete author + lamport envelope and no signature — the
                // history rule, "loaded as it is" (0925 §5).
                //
                // T41 — WARN AND ADOPT is the deliberate choice here; refusing
                // the entry was considered and rejected. Three reasons.
                //
                // (1) Refusing would be a data-loss default on the one path
                //     where the operator is physically present. A foreign
                //     `openledger-author` in this node's own `.bean` most often
                //     means a human pasted a peer's directive in by hand, or a
                //     backup/merge tool did — and silently discarding what they
                //     pasted is worse than keeping it and saying it will not
                //     replicate. The warning names the content id and the exact
                //     remedy (drop the author line).
                //
                // (2) The entry is not a forgery risk. It carries NO signature,
                //     so no peer with signing enabled will accept it; it is
                //     inert outside this node. The failure mode is "does not
                //     replicate", which is what the warning says, not "is
                //     accepted somewhere it should not be".
                //
                // (3) Refusing would not even be a consistent rule. Boot loads
                //     exactly this shape with no check at all — it must, under
                //     the brick-path rule — so a refusal here would reject on
                //     reconcile what the very next restart loads anyway.
                //
                // The remaining gap is a node holding an entry the mesh will not
                // take, which `verify` does not currently surface; that is
                // reported, not fixed.
                warn!(
                    content_id,
                    author = %other_author,
                    this_node = %self.author_id,
                    "adopted an unsigned ledger-file entry authored by another node; this node \
                     cannot sign for that author, so the entry will NOT replicate to peers with \
                     signing enabled — remove the openledger-author line to adopt it as our own"
                );
                return;
            }
            // No author at all: the stamp only fills one in when it also stamps
            // a Lamport value, so this is an entry that carried a Lamport value
            // and no author. Not ours to sign either.
            None => return,
        }

        let (parents, lamport) = Self::envelope_parents_and_lamport(metadata);
        if let Some(signature_hex) = signer(content_id, is_transaction, parents, lamport) {
            metadata.insert(ENVELOPE_KEY_SIGNATURE.to_owned(), signature_hex);
        }
    }
}
