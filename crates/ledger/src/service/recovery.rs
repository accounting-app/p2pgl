//! Recovery after a failed commit (L-13, T93): `begin_recovery` /
//! `finish_recovery`, the rollback of staged writes, and the reload.

use super::*;

impl LedgerService {
    /// Restore memory == disk after a commit that failed (L-13, T44 shape).
    ///
    /// The pre-T44 reasoning is unchanged and still exact: `persist_atomically`
    /// writes a sibling `.tmp` and renames, and a journal append either lands
    /// whole or leaves a torn tail the scanner drops, so **a failed commit
    /// always leaves the files in their last good state**. The unpersisted
    /// in-memory mutations are therefore discarded by reconstructing the entire
    /// service from disk via [`Self::boot`] — which now reads canonical ∪
    /// journal, so the reload lands on exactly the state the failed commit
    /// started from rather than on a pre-journal one.
    ///
    /// The fields that describe this *service* rather than its file are carried
    /// across the reload by [`Self::adopt_reloaded`] — the signer, the reconcile
    /// counter and the commit machinery. See there for the invariant and for the
    /// per-field reasoning.
    ///
    /// If the reload itself fails there is no better on-disk state to fall back
    /// to; memory is left as-is and the failure is logged, exactly as before.
    ///
    /// # Synchronous, and therefore for synchronous callers (L-43)
    ///
    /// This is [`Self::begin_recovery`] → [`RecoveryReload::load`] →
    /// [`Self::finish_recovery`] run back to back on the calling thread, so the
    /// whole `boot` — up to a 64 MiB read, a parse, a DAG insert per directive
    /// and a read-model build — happens under whatever lock the caller holds.
    /// That is right for `persist_or_reload`/`compact` (synchronous by
    /// contract). An async caller that holds the single-writer permit should
    /// use the split form instead, as `gl-node`'s `commit_pending` (a failed
    /// commit, L-43) and `prepare_or_recover` (a failed prepare, M-39) both
    /// do, so the rebuild runs on a blocking thread with no ledger lock held.
    pub fn recover_failed_commit(&mut self) {
        let reload = self.begin_recovery();
        let reloaded = reload.load();
        self.finish_recovery(reload, reloaded);
    }

    /// Capture what an L-13 reload needs, so the reload itself can run off the
    /// ledger lock (L-43).
    ///
    /// Takes `&self`: a read guard is enough, and nothing about the service
    /// changes until [`Self::finish_recovery`].
    ///
    /// # Caller contract
    ///
    /// Hold the single-writer permit ([`Self::commit_gate`]) from before this
    /// call until after `finish_recovery`. That — not the ledger lock — is what
    /// makes the split sound: while the rebuild runs no lock is held, so readers
    /// proceed (they see the pre-recovery memory, exactly as they already could
    /// for the duration of the commit that failed), but no other *writer* can
    /// touch the files or the service, so the files the rebuild reads are still
    /// the files when its result is installed.
    ///
    /// The reload also records a fingerprint of the service, and
    /// `finish_recovery` refuses to install a rebuild if the service moved in
    /// between — the one thing a writer that ignored the permit could do to
    /// make the snapshot stale. See [`RecoveryReload`].
    pub fn begin_recovery(&self) -> RecoveryReload {
        RecoveryReload {
            file_path: self.file_path.clone(),
            author_id: self.author_id.clone(),
            fingerprint: self.recovery_fingerprint(),
        }
    }

    /// Install the result of a [`RecoveryReload::load`] (L-13, L-43).
    ///
    /// Does no I/O on the expected path: the rebuild was done by `load`, and
    /// this is the same [`Self::adopt_reloaded`] swap `recover_failed_commit`
    /// has always ended in. Takes the write lock at the call site.
    ///
    /// If the service changed since [`Self::begin_recovery`] — something
    /// staged, committed or reconciled while the rebuild ran, which the
    /// single-writer contract makes impossible — the rebuild is stale and
    /// installing it could discard a write that is already durable (and a
    /// later compaction would then erase it from disk). So it is thrown away
    /// and the reload is redone here, synchronously, against the files as they
    /// are *now*: exactly the pre-L-43 behaviour, reached only by a caller that
    /// broke the contract, and logged as such.
    ///
    /// # A reload never installs a ledger that lost a record (H-15, M-46)
    ///
    /// A failed commit may legitimately leave a rebuild short of memory by
    /// exactly two sets, and by nothing else:
    ///
    /// * **`pending_ids`** — what this node staged (its own writes, peer
    ///   arrivals) since the last commit. The failed commit was its only way
    ///   onto disk.
    /// * **`adopted_from_file`** — what boot or a reconcile adopted from the
    ///   `.bean` since the last compaction, on disk only in the operator's raw
    ///   spelling. Counted out of the count floor only: since T86 (L-104) a
    ///   stamped line is this node's record, and since T84 every adopted line
    ///   is stamped at adoption, so the id check below holds it like any other
    ///   (T93 / L-124). T62's `floor (a)` — an operator removing their own hand
    ///   lines before the rewrite is obeyed — no longer applies.
    ///
    /// Every OTHER id memory holds was on disk in this node's spelling at the
    /// last commit, and the rebuild is **refused** — memory kept, the refusal
    /// logged with the counts and a sample of the ids — when any one of them
    /// is absent from it: the `.bean` removed, renamed, truncated, or replaced
    /// under the node (a backup copied over the live file: M acked records
    /// out, N ≥ M others in). Installing it would turn a disk incident into an
    /// acknowledged-write loss that the next successful write makes durable.
    /// The check is per id (one set lookup per directive, no hashing), because
    /// a count cannot tell "the operator removed their own two hand lines"
    /// from "the operator removed two acked records and kept their hand
    /// lines": both leave the same number behind. Until M-46 the floor was the
    /// count `dag.len() − pending_ids.len()` and file-adopted ids were in
    /// `pending_ids`, so each adopted line lowered it by one. The count floor
    /// (`dag.len()` minus both sets) is kept as a cross-check and for the log;
    /// the id check implies it.
    ///
    /// Refusing leaves memory ahead of disk by design; `force_compaction` is
    /// set so the next commit is a full rewrite that puts every in-memory
    /// directive back on disk (and removes a journal whose tail the failed
    /// commit may have torn — the reload that would have detected that tail is
    /// the one being refused). The rebuild's `journal_torn_at_boot` is ORed
    /// in, so that rewrite renames a torn journal to a `.torn-*` sidecar
    /// rather than unlinking it (M-43's policy survives a refusal).
    ///
    /// There is deliberately no "install it anyway" argument: the only
    /// wholesale reload in this workspace is this L-13 recovery, and no
    /// caller of it ever wants less than it has.
    ///
    /// Every installed reload logs the before/after directive counts and how
    /// many staged and file-adopted directives it discarded. And once
    /// installed, the rebuild's operator input (H-13; re-derived from the
    /// file, which still spells it raw until a compaction succeeds) is
    /// finalised with the carried signer, so the caller's next commit writes
    /// it signed.
    ///
    /// # A reload that fails (M-49)
    ///
    /// Memory is kept, as it always was — there is no better state to fall
    /// back to — and the refusing arm's two facts are armed: `force_compaction`,
    /// so the next commit is a rewrite and never an `Append` behind a tail the
    /// failed commit may have torn (the journal scanner classifies a record
    /// after a damaged one as `Corrupt`, and boot refuses it); and
    /// `journal_torn_at_boot`, **unconditionally**. The failed reload is the
    /// one read that would have told this service whether the journal is
    /// torn, and it did not complete; so whether or not the error names the
    /// journal, the rewrite keeps the journal as a sidecar instead of
    /// unlinking it — a journal is never destroyed on the strength of a
    /// judgement this service could not make. The cost when the journal was
    /// healthy is one redundant sidecar and a WARN naming it.
    pub fn finish_recovery(
        &mut self,
        reload: RecoveryReload,
        reloaded: Result<LedgerService, ServiceError>,
    ) {
        self.release_commit_in_flight();
        let reloaded = if reload.fingerprint == self.recovery_fingerprint() {
            reloaded
        } else {
            error!(
                "the ledger changed while an L-13 reload was being rebuilt off the lock; \
                 discarding the stale rebuild and reloading synchronously. The single-writer \
                 contract on LedgerService::commit_gate was violated (L-43)"
            );
            LedgerService::boot_with(
                self.file_path.clone(),
                self.author_id.clone(),
                BootMode::Reload,
            )
        };
        match reloaded {
            Ok(reloaded) => {
                let in_memory = self.dag.len();
                let staged = self.pending_ids.len();
                let adopted_from_file = self.adopted_from_file.len();
                let on_disk = reloaded.dag.len();
                // M-46: the count floor; implied by the id check below.
                let floor = in_memory
                    .saturating_sub(staged)
                    .saturating_sub(adopted_from_file);
                let missing = self.committed_ids_missing_from(&reloaded.dag);
                if on_disk < floor || !missing.is_empty() {
                    error!(
                        in_memory,
                        staged,
                        adopted_from_file,
                        on_disk,
                        floor,
                        missing = missing.len(),
                        missing_sample = %missing
                            .iter()
                            .take(RECOVERY_MISSING_SAMPLE)
                            .copied()
                            .collect::<Vec<_>>()
                            .join(","),
                        file = %self.file_path.display(),
                        "REFUSING to install an L-13 rebuild that lacks directives memory holds \
                         and no failed commit can explain — not staged since the last commit: \
                         the files lost records memory still holds. Memory is kept, ahead of disk; the next \
                         commit is a full rewrite that puts every in-memory directive back on \
                         disk (H-15, M-46)"
                    );
                    self.force_compaction = true;
                    // The Info item beside M-49: the rebuild saw a torn
                    // journal, and the rewrite that follows must rename it.
                    self.journal_torn_at_boot |= reloaded.journal_torn_at_boot;
                    self.discard_staged_writes();
                    return;
                }
                let mut reloaded = reloaded;
                let kept = match self.keep_committed_envelopes_in(&mut reloaded) {
                    Ok(kept) => kept,
                    Err(unresolved) => {
                        error!(
                            records = unresolved.len(),
                            sample = %unresolved
                                .iter()
                                .take(RECOVERY_MISSING_SAMPLE)
                                .map(|(id, parent)| format!("{id}->{parent}"))
                                .collect::<Vec<_>>()
                                .join(", "),
                            file = %self.file_path.display(),
                            "REFUSING to install an L-13 rebuild: records this node committed name \
                             parents the rebuild does not hold (a write staged in the failed commit, \
                             or a record the file no longer has). Installing it would serve them \
                             with a parent no replica can resolve. Memory is kept, ahead of disk; \
                             the next commit is a full rewrite that puts both back (M-59, L-81)"
                        );
                        self.force_compaction = true;
                        self.journal_torn_at_boot |= reloaded.journal_torn_at_boot;
                        self.discard_staged_writes();
                        return;
                    }
                };
                let discarded_staged = self
                    .pending_ids
                    .iter()
                    .filter(|id| reloaded.dag.get(id).is_none())
                    .count();
                let discarded_file_adopted = self
                    .adopted_from_file
                    .iter()
                    .filter(|id| reloaded.dag.get(id).is_none())
                    .count();
                warn!(
                    before = in_memory,
                    after = on_disk,
                    discarded_staged,
                    discarded_file_adopted,
                    file = %self.file_path.display(),
                    "L-13 reload installed: memory rebuilt from disk after a failed commit"
                );
                if kept > 0 {
                    warn!(
                        kept,
                        file = %self.file_path.display(),
                        "the rebuilt ledger read records this node had already stamped as raw hand \
                         input — still raw in the file because a rewrite failed, or a backup taken \
                         before they were canonicalised was restored over it; they keep the \
                         envelope this node committed, and the next commit writes it back (L-81)"
                    );
                }
                // T93 / L-115, decision (44): the clock never falls below a
                // lamport this node issued (M-18). The rebuild resumes at the
                // file's `max + 1`, and the staged writes the failed commit
                // discards are on no disk — but they were served while staged
                // (L-86), so a peer may hold them: the next write reusing one
                // of their lamports re-issued an (author, lamport) pair.
                let own = self.author_id.clone();
                let discarded_own_high = self
                    .pending_ids
                    .iter()
                    .filter(|id| reloaded.dag.get(id).is_none())
                    .filter_map(|id| self.dag.get(id))
                    .filter(|directive| {
                        directive_author(directive)
                            .is_some_and(|author| is_own_author(author, &own))
                    })
                    .filter_map(Directive::lamport_clock)
                    .max()
                    .unwrap_or(0);
                reloaded.lamport_clock = reloaded.lamport_clock.max(discarded_own_high);
                self.adopt_reloaded(reloaded);
                // H-20: the reload re-derived the history from the file; the
                // carried signer and verifier were installed by assignment,
                // not by the setters, so the pass runs here — and BEFORE the
                // operator input is finalised (T79 / H-22): the pass's
                // quarantine rebases what is still unsigned, and anything it
                // quarantined after the signing would stay a parent of a
                // signed record no peer can resolve.
                self.verify_own_history();
                // T93 / L-115: and the pass's L-87 release may not lower it
                // below them either, before finalisation stamps from it.
                self.lamport_clock = self.lamport_clock.max(discarded_own_high);
                self.finalize_operator_input();
                // T86 / M-58, decision (21): the fact decides whether writes
                // are refused before staging, and a rebuild whose operator
                // input the L-81 keep just emptied never measured it (boot
                // defers to finalisation, finalisation has nothing to do), so
                // it is measured here, over the history just installed.
                self.measure_canonical_over_cap(false);
            }
            Err(reload_error) => {
                // M-49: see the doc comment — the refusing arm's two facts,
                // the second one unconditionally.
                self.force_compaction = true;
                self.journal_torn_at_boot = true;
                error!(
                    %reload_error,
                    in_memory = self.dag.len(),
                    staged = self.pending_ids.len(),
                    "ledger reload-from-disk failed after a failed commit; memory is kept, ahead \
                     of disk. The next commit is a full rewrite, never an append behind a tail \
                     the failed commit may have torn, and it keeps the journal as a .torn-* \
                     sidecar instead of deleting it (L-13, M-49)"
                );
                self.discard_staged_writes();
            }
        }
    }

    /// Roll back what the failed commit staged, on the arms of
    /// [`Self::finish_recovery`] that keep memory instead of installing the
    /// rebuild (T100 / L-147, decision (62)): the committed-id floor, the M-59
    /// check and a reload that failed (the L-117 link refusal among them).
    /// Before T100 memory was kept as it stood, the write whose call had just
    /// returned an error included: counted and served at once, written by the
    /// next commit — "error, but durable". Since T93 a line adopted from the
    /// file takes committed parents (decision (43)), so taking the staged
    /// writes out strands nothing the node chose; a line that spells a staged
    /// write's id as its parent itself (M-47) is held — as the operator typed
    /// it, kept in the file — exactly as boot holds a hand-spelled parent that
    /// is not served (L-75). The clock is not lowered (decision (44)). The
    /// over-cap fact is measured again over what stays, since these arms return
    /// before the success path's measurement (M-74).
    pub(super) fn discard_staged_writes(&mut self) {
        if !self.pending_ids.is_empty() {
            let staged: BTreeSet<String> = self.pending_ids.iter().cloned().collect();
            let mut orphaned: BTreeSet<String> = BTreeSet::new();
            let mut frontier: Vec<String> = staged.iter().cloned().collect();
            while let Some(id) = frontier.pop() {
                for child in self.dag.children_of(&id).unwrap_or_default() {
                    if !staged.contains(child) && orphaned.insert(child.clone()) {
                        frontier.push(child.clone());
                    }
                }
            }
            let already_held: BTreeSet<String> = self
                .quarantined
                .keys()
                .filter(|id| staged.contains(*id))
                .cloned()
                .collect();
            // A line the file spells raw is held as it spells it: this node's
            // stamp is in memory only.
            let as_typed: Vec<(String, Directive)> = orphaned
                .iter()
                .filter(|id| self.adopted_from_file.contains(*id))
                .filter_map(|id| {
                    let mut written = self.dag.get(id)?.clone();
                    directive_metadata_mut(&mut written).retain(|key, _| {
                        !matches!(
                            key.as_str(),
                            ENVELOPE_KEY_AUTHOR | ENVELOPE_KEY_LAMPORT | ENVELOPE_KEY_SIGNATURE
                        )
                    });
                    Some((id.clone(), written))
                })
                .collect();
            let refused: BTreeSet<String> = staged.union(&orphaned).cloned().collect();
            self.rebuild_dag(&refused, &BTreeMap::new());
            self.quarantined
                .retain(|id, _| !staged.contains(id) || already_held.contains(id));
            for (content_id, written) in as_typed {
                self.adopted_from_file.remove(&content_id);
                self.quarantined.insert(content_id, written);
            }
            for content_id in &orphaned {
                warn!(
                    id = %content_id,
                    file = %self.file_path.display(),
                    "quarantining a ledger record, kept in the file: its openledger-parents \
                     names a write whose commit failed and which is rolled back (L-147, L-75)"
                );
            }
            warn!(
                discarded = staged.len(),
                file = %self.file_path.display(),
                "the writes staged in the failed commit are rolled back, as the calls that \
                 staged them were told (L-147)"
            );
        }
        self.measure_canonical_over_cap(false);
    }

    /// The ids memory holds that `rebuilt` lacks and that no failed commit can
    /// explain (M-46): every id not in `pending_ids` (staged, never on disk).
    /// Everything else was on disk as of the last commit — in this node's
    /// spelling, or as a line the operator typed and this node adopted and
    /// stamped — so a rebuild of the same files holds it under the same id.
    /// One set lookup per directive, no content hashing.
    ///
    /// T86 / L-104, decision (23): a file-adopted id is not exempt once it is
    /// stamped with this node's author and lamport — and since T84 every
    /// adopted line is, at boot (provisionally) and on the live path alike, so
    /// T93 / L-124 removed the "still unstamped" exemption that T86 left, which
    /// could no longer apply. A rebuild that lacks such a line is refused like
    /// one that lacks any other committed record, so the next commit writes it
    /// back — what the success path (the L-30 union) does anyway. Deleting a
    /// line this node has stamped is not a retraction (T62's floor (a) is
    /// gone); a reversing entry is.
    pub(super) fn committed_ids_missing_from<'a>(&'a self, rebuilt: &LedgerDag) -> Vec<&'a str> {
        let staged: HashSet<&str> = self.pending_ids.iter().map(String::as_str).collect();
        self.dag
            .ids()
            .filter(|id| !staged.contains(id))
            .filter(|id| rebuilt.get(id).is_none())
            .collect()
    }

    /// Keep the envelope memory already committed for records a rebuild reads
    /// back as raw operator input (T82 / L-81).
    ///
    /// A backup taken while a hand line was still raw, copied over the live
    /// file after this node had signed and acknowledged that line, is read by
    /// the rebuild as operator input under the SAME content id (the envelope
    /// is outside the hash), so the recovery floor passes — and the rebuild
    /// would then stamp a fresh lamport and signature over a record the mesh
    /// already holds under the old ones: two envelopes for one id, forever.
    /// The success path never does that (the pre-persist reconcile sees the
    /// raw line as a duplicate). Here memory's copy replaces the rebuilt one,
    /// the id leaves the rebuild's operator input, and the rebuild's DAG is
    /// re-derived around it; the next commit is a rewrite (the id stays
    /// file-adopted), which writes the committed envelope back to disk.
    /// Returns how many records kept their envelope.
    ///
    /// T86 / M-59, decision (22): a kept envelope names parents too, and the
    /// rebuild must hold them. The pre-persist reconcile can adopt a hand line
    /// with parents that include a local write staged in the SAME commit; the
    /// commit fails, the floor lets the staged write go (it never reached
    /// disk), and the kept envelope would name a record that exists nowhere —
    /// served, then written, then named by every later write, and adoptable by
    /// no peer. So when any kept envelope names a parent the rebuild lacks
    /// (and does not itself keep), nothing is changed and the ids and parents
    /// come back as `Err`: the install is refused, memory stays ahead of disk,
    /// and the next commit rewrites both records.
    pub(super) fn keep_committed_envelopes_in(
        &self,
        reloaded: &mut LedgerService,
    ) -> Result<usize, Vec<(String, String)>> {
        let pending_here: HashSet<&String> = self.unsigned_operator_input.iter().collect();
        let replacements: BTreeMap<String, Directive> = reloaded
            .unsigned_operator_input
            .iter()
            .filter(|id| !pending_here.contains(id))
            .filter_map(|id| {
                let committed = self.dag.get(id)?;
                (!Self::is_operator_input(committed)).then(|| (id.clone(), committed.clone()))
            })
            .collect();
        if replacements.is_empty() {
            return Ok(0);
        }
        let unresolved: Vec<(String, String)> = replacements
            .iter()
            .filter_map(|(id, directive)| match directive {
                Directive::Transaction(txn) => txn
                    .parent_ids()
                    .into_iter()
                    .find(|parent| {
                        reloaded.dag.get(parent).is_none() && !replacements.contains_key(*parent)
                    })
                    .map(|parent| (id.clone(), parent.to_owned())),
                _ => None,
            })
            .collect();
        if !unresolved.is_empty() {
            return Err(unresolved);
        }
        reloaded
            .unsigned_operator_input
            .retain(|id| !replacements.contains_key(id));
        reloaded
            .operator_input_with_file_author
            .retain(|id| !replacements.contains_key(id));
        reloaded
            .operator_input_as_written
            .retain(|id, _| !replacements.contains_key(id));
        // M-18: the clock never falls below a lamport this node issued.
        let highest = replacements
            .values()
            .filter_map(Directive::lamport_clock)
            .max()
            .unwrap_or(0);
        reloaded.lamport_clock = reloaded.lamport_clock.max(highest);
        reloaded.rebuild_dag(&BTreeSet::new(), &replacements);
        Ok(replacements.len())
    }

    /// Everything a writer changes, cheaply (L-43) — see [`RecoveryReload`].
    pub(super) fn recovery_fingerprint(&self) -> RecoveryFingerprint {
        RecoveryFingerprint {
            commit_generation: self.commit_generation,
            lamport_clock: self.lamport_clock,
            directive_count: self.dag.len(),
            pending: self.pending_ids.len(),
            quarantined: self.quarantined.len(),
            quarantined_text: self.quarantined_text.len(),
            external_reconcile_count: self.external_reconcile_count,
            force_compaction: self.force_compaction,
            unsigned_operator_input: self.unsigned_operator_input.len(),
            adopted_from_file: self.adopted_from_file.len(),
        }
    }

    /// Install a freshly booted service in place of this one, keeping everything
    /// that describes the SERVICE rather than the file (T44b).
    ///
    /// # The invariant
    ///
    /// **A reload replaces the ledger's CONTENT, never the service's
    /// configuration.** [`Self::boot`] derives its whole result from the two
    /// files plus the author id, so every field that was *installed* after boot
    /// — or *accumulated* since it — comes back at its default unless it is
    /// carried here. Every wholesale reload goes through this one function, so
    /// a field added to the carry set cannot be forgotten at a second site.
    ///
    /// # What is carried, and why each one
    ///
    /// * [`Self::signer`] (L-11). The bug this function exists for. `boot` sets
    ///   it to `None`, so a reconcile-adoption after a recovered commit failure
    ///   stamped an entry with **no** `openledger-signature` — adopted into the
    ///   DAG, written to the `.bean`, present in every local report, and refused
    ///   by every signing peer forever. That is exactly the silent split-brain
    ///   L-11 closed, re-opened by the recovery path; the signer is the node's
    ///   identity, not the file's content.
    /// * [`Self::external_reconcile_count`] (L-30). An observability counter
    ///   over the *process*, not a fact about the file. Resetting it to zero
    ///   would erase the evidence that someone is hand-editing a live ledger,
    ///   and would do so precisely on the failure path where an operator is most
    ///   likely to be doing it.
    /// * [`Self::commit_gate`] (T44). A fresh mutex would silently unserialize
    ///   any writer holding the old permit.
    /// * [`Self::commit_in_flight`] (H-11). The same argument one level down: a
    ///   fresh `Arc` is a slot no outstanding [`CommitInFlightGuard`] points
    ///   at, so the guard would release an orphan while the live service stayed
    ///   marked — the leak this reload is supposed to be incapable of causing.
    ///   Carrying the `Arc` keeps "the guard owns the flag" true across the one
    ///   operation that replaces every other field.
    /// * [`Self::commit_observer`] (T44). A test seam installed after boot; the
    ///   same argument as the signer, with no production consequence.
    /// * [`Self::commit_generation`] (T44). The receipt guard is only meaningful
    ///   while generations are never reused, and `boot` restarts them at zero —
    ///   which would make already-issued numbers issuable again. Carrying it
    ///   keeps the sequence monotonic for the life of the process.
    /// * [`Self::author_id`] (L-43). It used to be carried by construction —
    ///   `boot` is handed the current value — and on the synchronous path it
    ///   still is. But since L-43 the rebuild can run off the lock, so a
    ///   `set_author_id` can land between the snapshot `boot` was given and
    ///   this swap; carrying the live value is what makes the later call win,
    ///   exactly as it would have without the split.
    ///
    /// # What is deliberately NOT carried
    ///
    /// Everything else, because everything else is the file: the DAG, the
    /// account state, the read model, the Lamport clock, the leading comments,
    /// the L-30 file hash, and the whole T44 file-shape block (`canonical_*`,
    /// `pending_ids`, `adopted_from_file`, `force_compaction`). Discarding
    /// those *is* the L-13 reload.
    ///
    /// [`Self::quarantined`] is deliberately in that second list (H-08), and it
    /// is the one entry where "not carried" is a safety property rather than a
    /// tidiness one. A reload re-reads the `.bean`, and a failed commit leaves
    /// the `.bean` exactly as it was (temp + rename), so the reloaded boot
    /// re-derives the quarantine from the very bytes the old one was derived
    /// from — carrying the old set forward could only *add* entries the file no
    /// longer contains, which is how a "nothing is ever lost" rule turns into a
    /// "deleted records come back" one. `file_path` is configuration too, and
    /// is carried by construction — [`Self::begin_recovery`] passes it into
    /// `boot`, and `journal_path` is re-derived from the same path.
    ///
    /// # One file-shape fact IS carried, conditionally (L-64)
    ///
    /// `canonical_is_current` is a statement about the bytes on disk — "the
    /// `.bean` holds exactly what this service would write" — and `boot`
    /// answers it `false` because boot did not write the file. After a
    /// reload that made *every* later write a forced compaction, appends that
    /// would have fit included, and on a ledger whose canonical spelling is
    /// over the cap each of those compactions failed and reloaded again: a
    /// wedge entered by one failed append. But the reload has just hashed the
    /// bytes it read, and this service knows the hash of the bytes it last
    /// wrote; when the two agree the file is exactly as canonical as it was
    /// before the reload, so the flag is kept. Any other case (the file
    /// changed, or was never canonical) keeps boot's `false`.
    pub(super) fn adopt_reloaded(&mut self, reloaded: LedgerService) {
        // Moved out of the old `self` before the assignment drops it.
        let author_id = std::mem::take(&mut self.author_id);
        let signer = self.signer.take();
        // H-20: carried like the signer; `finish_recovery` re-runs the
        // verification over the re-derived history.
        let verifier = self.verifier.take();
        let external_reconcile_count = self.external_reconcile_count;
        let commit_gate = std::sync::Arc::clone(&self.commit_gate);
        let commit_in_flight = std::sync::Arc::clone(&self.commit_in_flight);
        let commit_observer = self.commit_observer.take();
        let commit_generation = self.commit_generation;
        // H-19: the join window is process state, like the signer.
        let join_trust = self.join_trust;
        // L-64: the rebuild read the very bytes this service last wrote or
        // read, so the file is as canonical as it was.
        let canonical_is_current =
            self.canonical_is_current && self.last_file_hash == reloaded.last_file_hash;

        *self = reloaded;

        self.author_id = author_id;
        self.signer = signer;
        self.verifier = verifier;
        self.external_reconcile_count = external_reconcile_count;
        self.commit_gate = commit_gate;
        self.commit_in_flight = commit_in_flight;
        self.commit_observer = commit_observer;
        self.commit_generation = commit_generation;
        self.join_trust = join_trust;
        self.canonical_is_current = canonical_is_current;
    }
}
