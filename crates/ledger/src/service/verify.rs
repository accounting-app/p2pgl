//! The history checks boot and a reload run: the signature pass (H-20), the
//! served-set rule (T84 / H-23), and the clock release after them.

use super::*;

impl LedgerService {
    /// Verify the signature of every enveloped directive boot loaded and
    /// quarantine what fails (H-20; decision (3)).
    ///
    /// Runs automatically when [`Self::set_signer`] or [`Self::set_verifier`]
    /// gives the service the means, and again from `finish_recovery` after a
    /// reload re-derives the history from the file; `gl-node` calls it once
    /// more explicitly, after the identity is complete and before the startup
    /// compaction, so the banner below states what could **not** be checked.
    /// Idempotent and cheap: [`Self::unverified_history`] is drained, so a
    /// second call on a verified ledger costs one `is_empty`.
    ///
    /// # The verdict, per directive
    ///
    /// * A verifier is installed: the signature must be present and verify
    ///   against the author id, own or foreign — the author id is the key.
    /// * No verifier, a signer, and the author is this node: the signer is
    ///   asked for the signature this node *would* produce over the same
    ///   message; Ed25519 is deterministic, so anything else on the envelope
    ///   was not made by this node over this record. A signer with signing
    ///   disabled (`None`) cannot decide and the record stays unverified.
    /// * Otherwise the record cannot be checked here and stays loaded.
    ///
    /// A missing signature is a refusal too: a record that carries an author
    /// and a lamport was written by a node, a signing node always signs, and
    /// every peer with signing enabled refuses it (`EnvelopeMissing`). A
    /// history written **before** this node enabled signing looks the same
    /// and is quarantined the same; it never replicated, and the remedy the
    /// warning names — delete the `openledger-*` lines to re-adopt the record
    /// as this node's own, operator input that boot stamps and signs — is a
    /// fixed point.
    ///
    /// # What a refusal does
    ///
    /// The directive leaves the DAG, the read model and the account state —
    /// the DAG is a grow-only set, so [`Self::quarantine_out_of_dag`] rebuilds
    /// the three from the surviving directives — and joins
    /// [`Self::quarantined`] **as loaded**, so the next compaction writes it
    /// back exactly as the file spelled it (H-08). Nothing is dropped and
    /// boot is never refused. Returns how many directives were quarantined.
    pub fn verify_own_history(&mut self) -> usize {
        let quarantined = self.verify_history_pass();
        self.warn_if_the_served_history_has_a_lamport_gap();
        // T80 / T89 (L-98, L-99): judged once, over every pass.
        if self.every_checked_signature_failed() {
            warn!(
                failed = self.signature_failed_total,
                file = %self.file_path.display(),
                "EVERY signature this node checked failed. That is not one edited record: the \
                 signature domain (p2p.meshId, or p2p.swarmTopic when meshId is unset) or the \
                 node key differs from the one this history was signed under. Check both \
                 before repairing anything — the records are quarantined, not lost, and load \
                 again once the domain and key are right. Do not author until then: this \
                 node's clock is left where the history put it, and records written under the \
                 wrong domain are quarantined at the next correct boot (H-20, T80, L-99)"
            );
        }
        if !self.unverified_history.is_empty() {
            warn!(
                unverified = self.unverified_history.len(),
                verifier_installed = self.verifier.is_some(),
                signer_installed = self.signer.is_some(),
                author = %self.author_id,
                file = %self.file_path.display(),
                "ledger history is UNVERIFIED: these directives carry an envelope whose \
                 signature this node has no means to check (no verifier installed, or \
                 signing disabled, or a foreign author with no verifier). They are served as \
                 loaded; an edited record among them is refused by every signing peer and \
                 orphans everything authored after it (H-20)"
            );
        }
        quarantined
    }

    /// The served records no fresh replica could hold, each with the reason a
    /// peer would give, and every record that descends from them (T84 / H-23,
    /// decision (15)).
    ///
    /// A peer adopts a transaction only when every parent it names is already
    /// in its DAG (`require_parents`) and it validates against the account
    /// state (`validate_transaction_as_data`: I1, I2, I3, I9 — T98's data
    /// rule, under which no `close` refuses it) and has every amount written
    /// (H-03: an elided posting would be stored under another id) — the checks
    /// [`Self::stage_remote_directive`] applies to a transaction's body and
    /// parents. A record this node serves that fails any of them is refused by
    /// every replica that lacks it, and so is
    /// everything written after it: its descendants wait on a parent that
    /// never arrives. T79 (d) asked only "is the parent in my quarantine", and
    /// T81 only "did this boot refuse it under a content rule"; a parent whose
    /// id vanished under an edit, a block held as text with no id, a record
    /// the operator deleted, and an account whose `open` is gone or does not
    /// admit the transaction are in neither. This asks the peer's question.
    ///
    /// Judged against the DAG and account state as they stand — call it once
    /// the history the node will serve is settled. `exempt` is operator input
    /// still awaiting finalisation: its parents are re-chosen by the rebase
    /// and its body was validated at adoption, so it is neither a seed nor a
    /// member here (the rebuild that quarantines the result rebases it).
    pub(super) fn unservable_history(&self, exempt: &HashSet<String>) -> BTreeMap<String, String> {
        let mut unservable: BTreeMap<String, String> = BTreeMap::new();
        for content_id in self.dag.ids() {
            if exempt.contains(content_id) {
                continue;
            }
            let Some(Directive::Transaction(txn)) = self.dag.get(content_id) else {
                continue;
            };
            if let Some(parent) = txn
                .parent_ids()
                .into_iter()
                .find(|parent| self.dag.get(parent).is_none())
            {
                let whereabouts = if self.quarantined.contains_key(parent) {
                    "which is only in this node's quarantine"
                } else {
                    "which exists nowhere on this node"
                };
                unservable.insert(
                    content_id.to_owned(),
                    format!("its parent {parent} is not served, {whereabouts}"),
                );
            } else if let Err(error) = validate_transaction_as_data(txn, &self.accounts) {
                unservable.insert(
                    content_id.to_owned(),
                    format!("a peer refuses it against the accounts this node serves: {error}"),
                );
            } else if elided_posting_count(txn) > 0 {
                unservable.insert(
                    content_id.to_owned(),
                    "a posting has no amount, and a peer takes a transaction only with every \
                     amount written (H-03) — write the amount back, which restores the \
                     record's id, or restore the record from a peer or a backup"
                        .to_owned(),
                );
            }
        }
        let mut frontier: Vec<String> = unservable.keys().cloned().collect();
        while let Some(id) = frontier.pop() {
            let children: Vec<String> = self
                .dag
                .children_of(&id)
                .map(<[String]>::to_vec)
                .unwrap_or_default();
            for child in children {
                if unservable.contains_key(&child) {
                    continue;
                }
                if exempt.contains(&child) {
                    // T99 / L-146, decision (60): pending input whose hand-
                    // spelled parent this walk holds would be refused by the
                    // rebuild that follows (`rebase_operator_input`, L-75), so
                    // it is held with the rest, and what descends from it is
                    // walked now, in this round. T92 left it to another round —
                    // one full rebuild and one recursion level per link of an
                    // alternating chain.
                    if self.is_hand_parented_input(&child) {
                        unservable.insert(
                            child.clone(),
                            format!(
                                "its openledger-parents names {id}, which is not served (L-75)"
                            ),
                        );
                        frontier.push(child);
                    }
                    continue;
                }
                unservable.insert(child.clone(), format!("it descends from {id}"));
                frontier.push(child);
            }
        }
        unservable
    }

    /// Whether `content_id` is pending operator input the file spelled with
    /// an `openledger-parents` line (M-47) — the input the rebuild refuses
    /// when a hand parent leaves the DAG.
    pub(super) fn is_hand_parented_input(&self, content_id: &str) -> bool {
        self.operator_input_as_written
            .get(content_id)
            .is_some_and(|(_, written)| {
                matches!(written, Directive::Transaction(_))
                    && written.metadata().contains_key(ENVELOPE_KEY_PARENTS)
            })
    }

    /// Quarantine what [`Self::unservable_history`] finds, naming every record
    /// and its reason (T84 / H-23, decision (15)). Kept in the file as loaded,
    /// out of the DAG and every balance, like every other quarantine (H-08);
    /// operator input still pending is rebased by the rebuild onto what stays.
    ///
    /// A peer that holds the missing parent re-supplies it and then these
    /// records (they are not in this node's DAG, so it wants them), which
    /// enter the DAG as ordinary inserts: on a mesh this heals by itself. On a
    /// node no peer can help, the remedy is in the file. Returns how many were
    /// quarantined.
    pub(super) fn quarantine_unservable_history(&mut self) -> usize {
        // T92 / M-64, decision (39): to a fixpoint, since a rebuild can itself
        // refuse pending input. T99 / L-146, decision (60): iterated, not
        // recursive — T92 recursed once per round, so a crafted chain of
        // hand-parented lines cost one full rebuild per link and aborted the
        // recovery reload's 2 MiB thread with a stack overflow — and the walk
        // goes through the input a rebuild would refuse, so a file needs one
        // round. Each round that changes nothing ends it; one that holds
        // shrinks the DAG, so the bound is never reached.
        let mut quarantined = 0usize;
        for _ in 0..=self.dag.len() {
            match self.quarantine_unservable_round() {
                Some(held) => quarantined += held,
                None => break,
            }
        }
        quarantined
    }

    /// One round of [`Self::quarantine_unservable_history`]: `None` when
    /// nothing is unservable, else how many records it held.
    pub(super) fn quarantine_unservable_round(&mut self) -> Option<usize> {
        let exempt: HashSet<String> = self.unsigned_operator_input.iter().cloned().collect();
        let unservable = self.unservable_history(&exempt);
        if unservable.is_empty() {
            return None;
        }
        // T99 / M-72, decision (58): another copy whose parents are served,
        // before the record is held.
        let doomed: BTreeSet<String> = unservable.keys().cloned().collect();
        let (doomed, replacements) = self.served_instead(doomed, true);
        // T99 / L-143, decision (59): a record retyped beside it is held
        // alone and the typed line adopted in its place; the next round judges
        // what descends from it against that copy.
        let retyped: BTreeSet<String> = doomed
            .iter()
            .filter(|id| self.typed_copies.contains_key(*id))
            .cloned()
            .collect();
        if !retyped.is_empty() {
            self.unverified_history.retain(|id| !retyped.contains(id));
            self.rebuild_dag(&retyped, &replacements);
            let adopted = self.adopt_typed_copies_of_held_records(&retyped);
            return Some(retyped.len() - adopted);
        }
        if doomed.is_empty() {
            self.rebuild_dag(&BTreeSet::new(), &replacements);
            return (!replacements.is_empty()).then_some(0);
        }
        for content_id in &doomed {
            let reason = &unservable[content_id];
            warn!(
                id = %content_id,
                reason = %reason,
                file = %self.file_path.display(),
                "quarantining a ledger record no fresh replica could hold — kept in the file \
                 as loaded, kept out of the DAG and every balance, NOT served (H-23, H-08)"
            );
        }
        let ids = doomed;
        self.unverified_history.retain(|id| !ids.contains(id));
        warn!(
            quarantined = ids.len(),
            ids = %ids.iter().cloned().collect::<Vec<_>>().join(", "),
            file = %self.file_path.display(),
            "ledger records QUARANTINED because no peer could adopt them: a parent this node \
             does not serve, or a transaction the accounts it serves do not admit, and what \
             descends from them. Serving them would make everything this node writes \
             afterwards unadoptable by every peer. They return when a peer that holds them \
             re-supplies the missing parent and then them; a record no peer holds stays held \
             even after its parent arrives. If no peer holds them: restore the \
             missing record from a backup; or, for this node's own record whose envelope \
             lines were edited, delete that block's openledger-* lines so it is re-adopted \
             under the same id; or add the missing open, dated no later than the first \
             transaction on the account (where the account's own open is served but dated \
             after it, correct that open's date instead); then restart. Otherwise rebuild \
             this node by the bootstrap join (H-23)"
        );
        let held = ids.len();
        self.rebuild_dag(&ids, &replacements);
        Some(held)
    }

    /// The pass behind [`Self::verify_own_history`], without the
    /// still-unverified banner: what the setters and `finalize_operator_input`
    /// run.
    pub(super) fn verify_history_pass(&mut self) -> usize {
        if self.unverified_history.is_empty() || (self.verifier.is_none() && self.signer.is_none())
        {
            return 0;
        }
        let ids = std::mem::take(&mut self.unverified_history);
        let mut refused: BTreeMap<String, String> = BTreeMap::new();
        let mut remaining: BTreeSet<String> = BTreeSet::new();
        let mut verified = 0usize;
        let mut reattributed: Vec<Directive> = Vec::new();
        // T92 / L-131: an id the file spells twice — a node-written copy boot
        // loaded as history (and held before the operator input was adopted:
        // the closure took it) and a hand-typed copy of the same body the
        // operator added beside it — is in the DAG as the hand copy, pending
        // operator input. That copy is not history and carries no signature
        // yet; judged as history it was quarantined ("no openledger-signature")
        // and the startup compaction dropped the typed block, silently.
        // `finalize_operator_input` signs it and checks it then. (A copy typed
        // beside a record this pass or the served-set rule holds is parked at
        // adoption and adopted when that happens — T99 / L-143.)
        let pending: HashSet<&str> = self
            .unsigned_operator_input
            .iter()
            .map(String::as_str)
            .collect();
        let mut retyped: Vec<String> = Vec::new();
        for content_id in ids {
            if pending.contains(content_id.as_str()) {
                retyped.push(content_id);
                continue;
            }
            let Some(directive) = self.dag.get(&content_id) else {
                continue;
            };
            // T80 / M-53: this node's own record from before T80, signed
            // under the placeholder author. The author only moves; the DAG's
            // structure (parents) and the id are untouched.
            if let Some(owned) = self.reattributed_placeholder_record(&content_id, directive) {
                if let Some(slot) = self.dag.get_mut(&content_id) {
                    *slot = owned.clone();
                }
                reattributed.push(owned);
                verified += 1;
                continue;
            }
            let Some(directive) = self.dag.get(&content_id) else {
                continue;
            };
            match self.verify_history_directive(&content_id, directive) {
                // T92 / L-114: this node's own signature of a moment ago is not
                // counted as verified history.
                HistoryVerdict::Verified => {
                    if !self.signed_by_finalize.remove(&content_id) {
                        verified += 1;
                    }
                }
                HistoryVerdict::Unverifiable => {
                    remaining.insert(content_id);
                }
                HistoryVerdict::Refused(reason) => {
                    refused.insert(content_id, reason);
                }
            }
        }
        self.unverified_history = remaining;
        if !retyped.is_empty() {
            info!(
                ids = %retyped.join(", "),
                file = %self.file_path.display(),
                "the ledger file spells these records twice — as loaded history and as a line \
                 typed by hand without an envelope; the typed line is adopted as this node's \
                 own and signed, and replaces the other copy at the next compaction (L-131)"
            );
        }
        if !reattributed.is_empty() {
            for directive in &reattributed {
                self.read_model.reindex_directive(directive);
            }
            // The file still spells the placeholder until a rewrite.
            self.force_compaction = true;
            info!(
                reattributed = reattributed.len(),
                author = %self.author_id,
                file = %self.file_path.display(),
                "records this node signed under the placeholder author before its author id \
                 was taken from its key now carry that id; their signatures verify under this \
                 node's key and do not cover the author, so they are unchanged, and the next \
                 compaction writes the new author (T80, M-53)"
            );
        }
        self.signature_verified_total += verified;
        if refused.is_empty() {
            info!(
                verified,
                unverified = self.unverified_history.len(),
                "ledger history verified: every checked signature is the one its author \
                 would have produced (H-20)"
            );
            // T89 / L-99: a release put on hold while nothing verified runs
            // once something does.
            if !self.release_on_hold.is_empty() && !self.every_checked_signature_failed() {
                let held = std::mem::take(&mut self.release_on_hold);
                self.release_clock_carried_by_edited_records(&held);
            }
            return 0;
        }
        // T99 / M-72, decision (58): a refused record the file spells twice is
        // served on its other copy when that one verifies and names served
        // parents — an API re-entry of a record whose file copy was edited
        // (A1-2). Before T99 the first copy loaded was the one judged, and the
        // startup compaction deleted the copy that verified.
        let edited: BTreeSet<String> = refused
            .iter()
            .filter(|(_, reason)| reason.starts_with("signature does not verify"))
            .map(|(id, _)| id.clone())
            .collect();
        let (held, replacements) = self.served_instead(refused.keys().cloned().collect(), false);
        refused.retain(|content_id, _| held.contains(content_id));
        for (content_id, reason) in &refused {
            warn!(
                id = %content_id,
                reason = %reason,
                file = %self.file_path.display(),
                "quarantining a ledger-file directive whose signature this node cannot \
                 accept — kept in the file as loaded, kept out of the DAG, NOT served; \
                 restore the original line from a peer's copy of the ledger or a backup. If no \
                 peer holds the original and only an openledger-* line was edited, delete that \
                 block's openledger-* lines instead, so it is re-adopted as this node's own under \
                 the same id; deleting the block leaves what descends from it held (H-23) \
                 (H-20, H-08)"
            );
        }
        let ids: BTreeSet<String> = refused.into_keys().collect();
        let any_edited = !edited.is_empty();
        self.signature_quarantined_total += ids.len();
        self.signature_failed_total += edited.len();
        self.rebuild_dag(&ids, &replacements);
        // T99 / L-143, decision (59): a line typed beside a record just held.
        self.adopt_typed_copies_of_held_records(&ids);
        // T89 / L-99, decision (32): while every signature checked so far has
        // failed, the failures say "wrong mesh id or key", not "edited
        // lamport lines", and releasing the clock past them would re-issue
        // pairs this node signed under the right domain. The release waits:
        // it runs once any pass verifies something, and never if nothing
        // ever does (the WARN in `verify_own_history` says not to author).
        if self.every_checked_signature_failed() {
            self.release_on_hold.extend(edited);
        } else {
            let mut release = std::mem::take(&mut self.release_on_hold);
            release.extend(edited);
            self.release_clock_carried_by_edited_records(&release);
        }
        // T84 / H-23: a signed record whose parent the pass just took out is a
        // record no peer lacking that parent can adopt; it goes too, with what
        // descends from it, and the operator input still pending is rebased
        // away from all of them.
        self.quarantine_unservable_history();
        if ids.is_empty() {
            return 0;
        }
        // T89 (0925 §5): the summary says what the refusals were. Records
        // that carry an author and a lamport but NO signature were not edited
        // — they are a history written before signing was enabled.
        let summary = if !any_edited {
            "they carry an author and a lamport but no openledger-signature: a history this \
             node wrote before signing was enabled, or pasted unsigned. Delete their \
             openledger-* lines to re-adopt them as this node's own, signed (H-20)"
        } else {
            "signature does not verify — was this record edited? History is append-only: a \
             correction is a new reversing entry, never an edit of a signed line (H-20)"
        };
        warn!(
            quarantined = ids.len(),
            verified,
            ids = %ids.iter().cloned().collect::<Vec<_>>().join(", "),
            file = %self.file_path.display(),
            "ledger directives QUARANTINED at signature verification: {summary}"
        );
        ids.len()
    }

    /// How many directives the signature pass has quarantined in this
    /// service's life, across every pass (T80). `gl-node` reports this at
    /// boot: the setters' passes quarantine before its explicit
    /// [`Self::verify_own_history`] call, whose return counts only its own.
    pub fn signature_quarantined_total(&self) -> usize {
        self.signature_quarantined_total
    }

    /// The H-19 diagnostic (T72; a content property since T83 / L-94), judged
    /// on the history this node serves (T89 / L-100) and worded by
    /// [`lamport_gap_verdict`] (L-111, L-113): a gap of at least
    /// [`LAMPORT_GAP_WARN`] between two consecutive lamports, naming the
    /// author at the top of it.
    pub(super) fn warn_if_the_served_history_has_a_lamport_gap(&self) {
        let (gap, top) = self.lamport_gap_and_top();
        if gap < LAMPORT_GAP_WARN {
            return;
        }
        let named = self
            .dag
            .directives()
            .into_iter()
            .find(|directive| directive.lamport_clock() == Some(top))
            .and_then(directive_author)
            .unwrap_or("(unknown)")
            .to_owned();
        // T96 / L-127: the gap a joiner faces once that author is removed.
        let (without_named, _) = largest_lamport_gap(
            self.dag
                .directives()
                .into_iter()
                .filter(|directive| directive_author(directive) != Some(named.as_str()))
                .filter_map(Directive::lamport_clock),
        );
        warn!(
            gap,
            without_named,
            below = top - gap,
            top,
            threshold = LAMPORT_GAP_WARN,
            author = %named,
            file = %self.file_path.display(),
            "the ledger history carries a lamport gap no honest mesh makes. Existing nodes \
             are unaffected. {}",
            lamport_gap_verdict(gap, without_named)
        );
    }

    /// Every signature checked so far, over every pass, has failed — at least
    /// two, none accepted, and every refusal a failure (not a missing
    /// signature) (T89 / L-98, L-99). One edited record does not look like
    /// that; a signature domain or node key that differs from the one the
    /// history was signed under does.
    pub(super) fn every_checked_signature_failed(&self) -> bool {
        self.signature_verified_total == 0
            && self.signature_failed_total >= 2
            && self.signature_failed_total == self.signature_quarantined_total
    }

    /// Lower the clock to what boot would have resumed at without the edited
    /// lamports in `edited` — records the signature pass quarantined because
    /// their signature does not verify (T83 / L-87; T84 / M-57, L-97).
    ///
    /// Boot folds every enveloped record into the clock before any signature
    /// is checked, so an own record whose lamport line was edited to ~2^32
    /// carried the clock there; quarantined, it no longer does anything else,
    /// but the node's next writes would carry the jump and the mesh would
    /// follow. What stays counted is everything else boot counts: every
    /// lamport the DAG still holds (any author) **except operator input still
    /// awaiting finalisation** — it was never issued, and
    /// [`Self::finalize_operator_input`] stamps it from the clock this leaves
    /// (M-57: counting its boot stamp pinned the clock above the edit) — this
    /// node's own records in the quarantine for any other reason, its own
    /// records boot saw outside the DAG, **and each edited record's own
    /// lamport unless it lies [`LAMPORT_GAP_WARN`] or more above all of that**
    /// (decision (17)). An edited record's lamport is usually the one this
    /// node issued — a narration fix leaves the lamport line alone, and the
    /// record may sit more than one above what remains (the first stamp after
    /// a restart, or after an adoption, both skip a value) — so it is a pair
    /// M-18 protects (L-97); only a jump no honest mesh makes is released.
    /// Never raises the clock; a no-op when `edited` is empty.
    pub(super) fn release_clock_carried_by_edited_records(&mut self, edited: &BTreeSet<String>) {
        if edited.is_empty() {
            return;
        }
        let own = self.author_id.clone();
        let pending: HashSet<&str> = self
            .unsigned_operator_input
            .iter()
            .map(String::as_str)
            .collect();
        let remaining = self
            .dag
            .ids()
            .filter(|id| !pending.contains(id))
            .filter_map(|id| self.dag.get(id).and_then(Directive::lamport_clock))
            .chain(
                self.quarantined
                    .iter()
                    .filter(|(id, _)| !edited.contains(*id))
                    .filter(|(_, directive)| {
                        directive_author(directive)
                            .is_some_and(|author| is_own_author(author, own.as_str()))
                    })
                    .filter_map(|(_, directive)| directive.lamport_clock()),
            )
            .chain(self.boot_outside_dag_lamports.get(&own).copied())
            .chain(
                self.boot_outside_dag_lamports
                    .get(PLACEHOLDER_AUTHOR)
                    .copied(),
            )
            .max()
            .unwrap_or(0);
        let plausible_edited = edited
            .iter()
            .filter_map(|id| self.quarantined.get(id).and_then(Directive::lamport_clock))
            .filter(|lamport| *lamport < remaining.saturating_add(LAMPORT_GAP_WARN))
            .max()
            .unwrap_or(0);
        let highest = remaining.max(plausible_edited);
        let resume = if highest > 0 {
            highest.saturating_add(1)
        } else {
            0
        };
        if resume < self.lamport_clock {
            info!(
                from = self.lamport_clock,
                to = resume,
                file = %self.file_path.display(),
                "the clock boot resumed at was carried by a record quarantined because its \
                 signature does not verify, whose lamport line was edited to a value no honest \
                 mesh reaches; it resumes above what remains instead, so this node's next \
                 writes do not carry the edit (L-87, M-57)"
            );
            self.lamport_clock = resume;
        }
    }

    /// `directive` re-attributed to this node, when it is a record this node
    /// signed under [`PLACEHOLDER_AUTHOR`] (T80 / M-53, decision (9)).
    ///
    /// Before T80 a node that signed with P2P off never learnt its author id,
    /// so it wrote `openledger-author: "local"` over a real signature by its
    /// key. The signature covers the content id, the transaction flag, the
    /// parents and the lamport — not the author — so when it verifies as this
    /// node's own, the record is this node's and only the author line was
    /// wrong: writing this node's id there leaves the signature valid. With
    /// P2P off such a record never left the node, so no replica holds the old
    /// spelling. `None` when the record does not qualify — not the
    /// placeholder, no envelope, no signature, this node still under the
    /// placeholder itself, or a signature that does not verify as this
    /// node's (which the normal verdict then refuses).
    pub(super) fn reattributed_placeholder_record(
        &self,
        content_id: &str,
        directive: &Directive,
    ) -> Option<Directive> {
        if self.author_id == PLACEHOLDER_AUTHOR {
            return None;
        }
        let metadata = directive.metadata();
        if metadata.get(ENVELOPE_KEY_AUTHOR).map(String::as_str) != Some(PLACEHOLDER_AUTHOR) {
            return None;
        }
        let lamport = metadata.get(ENVELOPE_KEY_LAMPORT)?;
        let signature = metadata.get(ENVELOPE_KEY_SIGNATURE)?;
        let parents = metadata
            .get(ENVELOPE_KEY_PARENTS)
            .map(String::as_str)
            .unwrap_or("");
        let is_transaction = matches!(directive, Directive::Transaction(_));
        let verifies = if let Some(verifier) = &self.verifier {
            verifier(
                content_id,
                is_transaction,
                parents,
                lamport,
                &self.author_id,
                signature,
            )
        } else if let Some(signer) = &self.signer {
            signer(content_id, is_transaction, parents, lamport).as_deref()
                == Some(signature.as_str())
        } else {
            false
        };
        if !verifies {
            return None;
        }
        let mut owned = directive.clone();
        directive_metadata_mut(&mut owned)
            .insert(ENVELOPE_KEY_AUTHOR.to_owned(), self.author_id.clone());
        Some(owned)
    }

    /// One directive's signature verdict — see [`Self::verify_own_history`].
    ///
    /// `content_id` is the id the DAG stores the directive under, which is
    /// the id its signature was made over.
    pub(super) fn verify_history_directive(
        &self,
        content_id: &str,
        directive: &Directive,
    ) -> HistoryVerdict {
        let metadata = directive.metadata();
        let Some(author) = metadata.get(ENVELOPE_KEY_AUTHOR) else {
            return HistoryVerdict::Verified;
        };
        let Some(lamport) = metadata.get(ENVELOPE_KEY_LAMPORT) else {
            return HistoryVerdict::Refused(
                "carries openledger-author but no openledger-lamport; a node never writes \
                 that, and every peer refuses it (M-47)"
                    .to_owned(),
            );
        };
        let parents = metadata
            .get(ENVELOPE_KEY_PARENTS)
            .map(String::as_str)
            .unwrap_or("");
        let is_transaction = matches!(directive, Directive::Transaction(_));
        let signature = metadata.get(ENVELOPE_KEY_SIGNATURE).map(String::as_str);
        let missing = || {
            HistoryVerdict::Refused(
                "no openledger-signature; every peer with signing enabled refuses it — was \
                 the signature line deleted, or was this record written before signing was \
                 enabled? Delete its openledger-* lines to re-adopt it as this node's own \
                 (H-20)"
                    .to_owned(),
            )
        };
        let does_not_verify = || {
            HistoryVerdict::Refused(
                "signature does not verify — was this record edited? (H-20)".to_owned(),
            )
        };
        if let Some(verifier) = &self.verifier {
            return match signature {
                None => missing(),
                Some(signature)
                    if verifier(
                        content_id,
                        is_transaction,
                        parents,
                        lamport,
                        author,
                        signature,
                    ) =>
                {
                    HistoryVerdict::Verified
                }
                Some(_) => does_not_verify(),
            };
        }
        if author != &self.author_id {
            return HistoryVerdict::Unverifiable;
        }
        let Some(signer) = &self.signer else {
            return HistoryVerdict::Unverifiable;
        };
        match signer(content_id, is_transaction, parents, lamport) {
            // Signing disabled: this node produces no signatures and cannot
            // say what one should look like.
            None => HistoryVerdict::Unverifiable,
            Some(expected) => match signature {
                None => missing(),
                Some(signature) if signature == expected => HistoryVerdict::Verified,
                Some(_) => does_not_verify(),
            },
        }
    }
}
