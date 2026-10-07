//! The quarantine: rebuilding the DAG without what it holds, the closure of
//! refused history, the copy chooser (T99), and re-admission.

use super::*;

impl LedgerService {
    /// Move `refused` from the DAG into [`Self::quarantined`], rebuilding the
    /// DAG, the account state and the read model from what survives (H-20).
    ///
    /// The DAG is a grow-only G-Set with no removal, by design (L-35 keys a
    /// snapshot cache on its size for exactly that reason), so the three
    /// structures are re-derived from the surviving directives in the
    /// original insertion order — the same construction boot performs, which
    /// is what keeps a rebuilt service identical to a fresh boot over a file
    /// without those records. Each refused directive is held as loaded, so
    /// the compaction writes it back (H-08). The lamport clock is left where
    /// boot put it: an own record's value still counts whether it is served
    /// or quarantined (`BootLamportHigh`), and a clock never walks backwards
    /// (M-18).
    ///
    /// # Operator input still awaiting finalisation (T79 / H-22)
    ///
    /// Boot stamps the parents of operator input from the heads it holds
    /// *before* the signature pass has judged the history under them, so an
    /// edited own record (a new content id under its old envelope) can be
    /// the head a hand-appended line names. Signed over that parent, the
    /// line is refused by every peer — a quarantined record is never served
    /// — and so is everything this node writes after it. The rebuild is
    /// where that is put right, because it is the one point that knows what
    /// survives: each entry of [`Self::unsigned_operator_input`] is rebased
    /// onto the DAG being rebuilt, exactly as boot would have adopted it
    /// over a file without the refused records —
    ///
    /// * parents this node chose are chosen again, by the same rule, from
    ///   the rebuilt heads (nothing is signed or served yet, so nothing has
    ///   seen the old choice; the content id is unchanged, since parents are
    ///   envelope);
    /// * parents the operator spelled must all have survived, else the entry
    ///   is refused;
    /// * a transaction must still validate against the rebuilt account
    ///   state (an `open` it relied on may be what was refused).
    ///
    /// A refused entry joins the quarantine as the FILE spelled it
    /// ([`Self::operator_input_as_written`]), and a later entry that relied
    /// on it is judged against a DAG without it, so the refusal cascades
    /// exactly as far as it must. Signed history is never re-parented.
    pub(super) fn quarantine_out_of_dag(&mut self, refused: &BTreeSet<String>) {
        self.rebuild_dag(refused, &BTreeMap::new());
    }

    /// [`Self::quarantine_out_of_dag`], also putting each directive in
    /// `replacements` in place of the DAG's copy of the same id (T82 / L-81) —
    /// envelope only: the id, and so the body, is the same.
    pub(super) fn rebuild_dag(
        &mut self,
        refused: &BTreeSet<String>,
        replacements: &BTreeMap<String, Directive>,
    ) {
        if refused.is_empty() && replacements.is_empty() {
            return;
        }
        let entries: Vec<(String, Directive)> = self
            .dag
            .content_ids()
            .into_iter()
            .filter_map(|id| Some((id.to_owned(), self.dag.get(id)?.clone())))
            .collect();
        let pending: HashSet<String> = self.unsigned_operator_input.iter().cloned().collect();
        let hand_parented: HashSet<String> = self
            .operator_input_as_written
            .iter()
            .filter(|(_, (_, written))| {
                matches!(written, Directive::Transaction(_))
                    && written.metadata().contains_key(ENVELOPE_KEY_PARENTS)
            })
            .map(|(stored_id, _)| stored_id.clone())
            .collect();
        let mut refused_now: BTreeSet<String> = refused.clone();
        let mut rebased = 0usize;
        let mut cascaded: Vec<(String, String)> = Vec::new();
        let mut dag = LedgerDag::new();
        let mut accounts = AccountState::new();
        for (content_id, mut directive) in entries {
            if let Some(committed) = replacements.get(&content_id) {
                directive = committed.clone();
            }
            if refused_now.contains(&content_id) {
                self.hold_refused_in_quarantine(&content_id, directive);
                continue;
            }
            if pending.contains(&content_id) {
                match Self::rebase_operator_input(
                    &content_id,
                    &mut directive,
                    hand_parented.contains(&content_id),
                    &dag,
                    &accounts,
                ) {
                    Ok(true) => rebased += 1,
                    Ok(false) => {}
                    Err(reason) => {
                        refused_now.insert(content_id.clone());
                        cascaded.push((content_id.clone(), reason));
                        self.hold_refused_in_quarantine(&content_id, directive);
                        continue;
                    }
                }
            }
            match dag.insert(directive.clone(), false) {
                Ok(InsertResult::Inserted { content_id }) => {
                    accounts.record_lifecycle(&directive, &content_id);
                }
                Ok(InsertResult::Duplicate { .. }) => {}
                Err(error) => {
                    // Unreachable — a subset of an acyclic graph inserted in
                    // the same order is acyclic, and a rebased entry names
                    // only admissible heads — but a refusal here must cost
                    // the directive its place in the DAG, never in the file.
                    error!(
                        %error,
                        id = %content_id,
                        "the DAG refused a directive while being rebuilt after a signature \
                         quarantine; the directive is quarantined too (H-08)"
                    );
                    refused_now.insert(content_id.clone());
                    self.hold_refused_in_quarantine(&content_id, directive);
                }
            }
        }
        let kept: Vec<Directive> = dag.directives().into_iter().cloned().collect();
        self.read_model = ReadModel::build(&kept);
        self.dag = dag;
        self.accounts = accounts;
        self.pending_ids.retain(|id| !refused_now.contains(id));
        self.adopted_from_file
            .retain(|id| !refused_now.contains(id));
        self.unsigned_operator_input
            .retain(|id| !refused_now.contains(id));
        self.operator_input_with_file_author
            .retain(|id| !refused_now.contains(id));
        self.operator_input_as_written
            .retain(|id, _| !refused_now.contains(id));
        // L-35: the snapshot cache is keyed by DAG size, which just shrank
        // and can grow back to the same number over a different set.
        *self
            .directive_id_snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        *self
            .served_id_snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        *self
            .withheld_snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        *self
            .staged_frontier
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        if rebased > 0 {
            info!(
                rebased,
                file = %self.file_path.display(),
                "operator input adopted at boot named a record this boot has since \
                 quarantined; its parents were chosen again from what survives, before it is \
                 signed (H-22)"
            );
        }
        for (content_id, reason) in &cascaded {
            warn!(
                id = %content_id,
                reason = %reason,
                file = %self.file_path.display(),
                "quarantining operator input adopted at boot, kept in the file as written: it \
                 depended on a record this boot has since quarantined (H-22, H-08)"
            );
        }
    }

    /// Whether `parent` is a record the closure holds back AND this node holds
    /// no copy of (T90 / H-24, decision (36)).
    ///
    /// `refused_history_closure` is a set of content ids, but it was computed
    /// from the parents of ONE copy of each record — the file's. A content id
    /// hashes the body alone, so another copy of the same record can name
    /// parents every peer holds; once such a copy is in the DAG, what descends
    /// from the id is as adoptable as anything else this node serves.
    pub(super) fn names_a_held_back_parent(&self, parent: &str) -> bool {
        self.refused_history_closure.contains(parent) && self.dag.get(parent).is_none()
    }

    /// Keep a complete-envelope file entry the live path refuses, for a reason
    /// boot would hold the same bytes for, in the quarantine — so the canonical
    /// re-persist writes it back instead of deleting it (T90 / L-126).
    ///
    /// Boot never drops history from the file (H-08): a body over a limit, a
    /// transaction the accounts do not admit, one that descends from a record
    /// no peer accepts are all quarantined and written back. Before T90 the
    /// live reconcile refused the same bytes into the `rejected` tally only,
    /// and the rewrite that followed deleted them. Only history is held:
    /// operator input a live reconcile refuses is still dropped, as the
    /// reconcile's summary says.
    pub(super) fn hold_refused_file_entry(&mut self, content_id: &str, directive: &Directive) {
        if Self::is_operator_input(directive) {
            return;
        }
        self.fold_held_own_lamport(directive);
        Self::quarantine_keeping_envelope(
            &mut self.quarantined,
            content_id.to_owned(),
            directive.clone(),
        );
    }

    /// A record of this node's own that a live reconcile holds in the file
    /// moves the clock to at least its lamport, as boot counts it
    /// (`BootLamportHigh::note_if_own`) — T103 / L-141, decision (70a). Before,
    /// the clock stayed where it was (L-55 governs what is refused and
    /// dropped, not what is kept), and the node's next writes stamped the held
    /// record's `(author, lamport)` pair again; once the record was admitted
    /// (its account opened by hand) both were served.
    pub(super) fn fold_held_own_lamport(&mut self, directive: &Directive) {
        if let (Some(author), Some(lamport)) =
            (directive_author(directive), directive.lamport_clock())
        {
            if is_own_author(author, &self.author_id) {
                self.lamport_clock = self.lamport_clock.max(lamport);
            }
        }
    }

    /// The boot WARN for a block refused only for an amount past the cap (T81
    /// / M-52), once the closure, the operator input and the served-set rule
    /// have spoken (T103 / M-73, decision (68a)). While a record this node
    /// holds back still names one of the block's ids, the remedy is the
    /// restatement — on ONE node: two operators following it restate one
    /// deposit twice, two ids every replica serves. Once nothing does, the
    /// block is what is left of a record whose restatement this node may
    /// already serve (adopted from the node that restated it), and the WARN
    /// says to delete it — or, if no node has restated it, to restate it on
    /// one.
    pub(super) fn warn_amount_cap_block(&self, line: usize, ids: &[String]) {
        let held: Vec<&str> = self
            .quarantined
            .iter()
            .filter(|(_, directive)| match directive {
                Directive::Transaction(txn) => txn
                    .parent_ids()
                    .into_iter()
                    .any(|parent| ids.iter().any(|id| id == parent)),
                _ => false,
            })
            .map(|(id, _)| id.as_str())
            .collect();
        if held.is_empty() {
            warn!(
                line,
                ids = %ids.join(", "),
                max = %crate::limits::MAX_AMOUNT_MAGNITUDE,
                file = %self.file_path.display(),
                "a ledger-file block with an amount past the cap (|amount| ≤ 10^21) is kept in \
                 the file byte-for-byte, out of the DAG and every balance, and nothing this node \
                 holds descends from it. If its restatement is served here — typed on this node, \
                 or adopted from the one node that restated it — delete this block: it is a \
                 stale copy of a record the mesh already carries. If no node has restated it, \
                 restate it on ONE node only, in a larger unit and without its openledger-* \
                 lines; every other node adopts it from there and must NOT restate (M-52, M-73)"
            );
        } else {
            warn!(
                line,
                ids = %ids.join(", "),
                held = %held.join(", "),
                max = %crate::limits::MAX_AMOUNT_MAGNITUDE,
                file = %self.file_path.display(),
                "quarantining a ledger-file block with an amount past the cap \
                 (|amount| ≤ 10^21) — kept in the file byte-for-byte, kept out of the DAG, NOT \
                 in any balance, and with it every record that descends from it (held names \
                 its children): no peer accepts the block, so nothing built on it can \
                 replicate. A history written before T65 with base-unit amounts looks like \
                 this. Restating the amount in a larger unit gives the record a new id, so what \
                 descends from it (whose parents name the old id) stays held (H-23): restate \
                 the chain on ONE node only — the record in a larger unit and without its own \
                 openledger-* lines, and each record that descends from it without its \
                 openledger-* lines; every other node adopts the restated records from that one \
                 and must NOT restate (a second restatement is a second deposit every replica \
                 counts). Or join nodes by bootstrap (M-52, M-50, H-08)"
            );
        }
    }

    /// Quarantine every record that descends from `refused` — history boot
    /// refused under a content rule every peer holds it to (T81 / M-51,
    /// M-52; decision (6)).
    ///
    /// No peer accepts a refused record, so nothing whose parents reach it can
    /// replicate: each would be buffered on its missing parent on every peer,
    /// forever, while this node served it and counted it. Quarantining the
    /// closure makes what this node serves the set a fresh replica can hold —
    /// loudly, every id named, every record kept in the file (H-08) — rather
    /// than a history no one can sync past. Walks both the children a record
    /// in the DAG has and the children still waiting on one that is absent.
    ///
    /// A refused `open` has dependants without being anyone's parent: the
    /// transactions on its account. T81 took every transaction on an account
    /// "no surviving `open` opens" here, before the operator input — by name,
    /// blind to dates and currencies, and to a hand `open` adopted a moment
    /// later (M-56). Since T85 (decision (18)) those are judged by
    /// [`Self::quarantine_unservable_history`] instead, after the operator
    /// input, with the check a peer applies (`validate_transaction` against the
    /// accounts this node serves), so a hand `open` that admits them frees them
    /// in the same boot and one that does not leaves them held. What remains
    /// here is parenthood, which no later step can repair.
    ///
    /// Since T99 (M-72, decision (58)) a member with another copy whose
    /// parents are served — the journal's copy of a record re-entered through
    /// the API or adopted from a peer — is served on that copy instead of
    /// being held ([`Self::choose_servable_copies`]). Returns the members it
    /// held, for [`Self::readmit_closure_members_now_servable`].
    pub(super) fn quarantine_descendants_of_refused_history(
        &mut self,
        refused: &BTreeSet<String>,
    ) -> BTreeSet<String> {
        if refused.is_empty() {
            return BTreeSet::new();
        }
        let mut closure: BTreeSet<String> = BTreeSet::new();
        let mut frontier: Vec<String> = refused.iter().cloned().collect();
        while let Some(id) = frontier.pop() {
            let children: Vec<String> = match self.dag.children_of(&id) {
                Some(children) => children.to_vec(),
                None => self.dag.children_awaiting(&id).to_vec(),
            };
            for child in children {
                if !refused.contains(&child) && closure.insert(child.clone()) {
                    frontier.push(child);
                }
            }
        }
        let (closure, replacements) = self.served_instead(closure, true);
        self.refused_history_closure
            .extend(refused.iter().cloned().chain(closure.iter().cloned()));
        if closure.is_empty() {
            self.rebuild_dag(&BTreeSet::new(), &replacements);
            return closure;
        }
        warn!(
            quarantined = closure.len(),
            ids = %closure.iter().cloned().collect::<Vec<_>>().join(", "),
            refused = %refused.iter().cloned().collect::<Vec<_>>().join(", "),
            file = %self.file_path.display(),
            "quarantining every record that descends from a ledger record no peer accepts — \
             kept in the file, kept out of the DAG and every balance: nothing built on a \
             refused record can replicate, so serving it would leave this node and every \
             fresh replica with different ledgers. A repair that changes the refused record's \
             body gives it a new id, and what descends from it (whose parents name the old id) \
             stays held (H-23): repair the chain on ONE node only — restate the refused record \
             without its own openledger-* lines, and delete the openledger-* lines of each \
             record that descends from it, so each is re-adopted under its own id with parents \
             that node serves. Every other node adopts the restated records from it and must \
             NOT restate: a second restatement is a second record, served and counted by every \
             replica. Or join nodes by bootstrap (M-51, M-52, H-08, H-24, M-73)"
        );
        self.rebuild_dag(&closure, &replacements);
        closure
    }

    /// Of `doomed` — records in the DAG a step is about to hold — the ones
    /// another copy saves, as `(still doomed, replacements)` (T99 / M-72,
    /// decision (58)). A replacement is served in place of the DAG's copy; the
    /// displaced copy joins [`Self::alternative_copies`], and each chosen
    /// alternative leaves it. `dag_copy_acceptable` is false for the
    /// signature pass, whose doomed copies are the ones it refused.
    pub(super) fn served_instead(
        &mut self,
        doomed: BTreeSet<String>,
        dag_copy_acceptable: bool,
    ) -> (BTreeSet<String>, BTreeMap<String, Directive>) {
        if doomed.is_empty() {
            return (doomed, BTreeMap::new());
        }
        let chosen = self.choose_servable_copies(&doomed, dag_copy_acceptable, false);
        let mut doomed = doomed;
        let mut replacements: BTreeMap<String, Directive> = BTreeMap::new();
        for (content_id, copy) in chosen {
            doomed.remove(&content_id);
            if self.dag.get(&content_id) == Some(&copy) {
                continue;
            }
            if let Some(displaced) = self.dag.get(&content_id).cloned() {
                let others = self
                    .alternative_copies
                    .entry(content_id.clone())
                    .or_default();
                others.retain(|other| other != &copy);
                others.push(displaced);
            }
            replacements.insert(content_id, copy);
        }
        if !replacements.is_empty() {
            info!(
                ids = %replacements.keys().cloned().collect::<Vec<_>>().join(", "),
                file = %self.file_path.display(),
                "the ledger file holds two copies of these records; serving the copy every                  peer can adopt — its parents served, its signature verified — instead of                  holding the record (H-24, M-72)"
            );
        }
        (doomed, replacements)
    }

    /// Which copy of each record in `doomed` a fresh replica could adopt, in
    /// the order they become adoptable (T99 / M-72, decision (58); L-142).
    ///
    /// The candidates for an id are the DAG's copy (when
    /// `dag_copy_acceptable`), its held copy in the quarantine (when
    /// `from_quarantine`), and every copy in [`Self::alternative_copies`]. A
    /// candidate is admissible on its own when its body validates as data
    /// against the accounts this node serves and — for a copy other than the
    /// DAG's, once the node has the means — its signature verifies. It is
    /// chosen once every parent it names is served: a record outside `doomed`
    /// in the DAG, or a record already chosen. That is a least fixpoint
    /// computed in one pass over a parent → waiting-candidates index, so the
    /// cost is linear in the candidates and their parents, and every chosen
    /// copy's parents were served before it — the choice can never close a
    /// cycle (A1's D-first re-entry: the file's `D` names `C`, the journal's
    /// `C` names `D`; only the journal's `D`, naming a served record, starts
    /// the chain, and T90's per-record descendant walk, quadratic on a
    /// crafted file, is gone).
    pub(super) fn choose_servable_copies(
        &self,
        doomed: &BTreeSet<String>,
        dag_copy_acceptable: bool,
        from_quarantine: bool,
    ) -> Vec<(String, Directive)> {
        let judge_signature = self.verifier.is_some() || self.signer.is_some();
        let mut served: HashSet<String> = self
            .dag
            .ids()
            .filter(|id| !doomed.contains(*id))
            .map(str::to_owned)
            .collect();
        let mut candidates: Vec<(String, Directive)> = Vec::new();
        let mut unmet: Vec<usize> = Vec::new();
        let mut waiting: HashMap<String, Vec<usize>> = HashMap::new();
        let mut ready: std::collections::VecDeque<usize> = std::collections::VecDeque::new();
        for content_id in doomed {
            let own = self.dag.get(content_id);
            let mut copies: Vec<&Directive> = Vec::new();
            if dag_copy_acceptable {
                copies.extend(own);
            }
            if from_quarantine {
                copies.extend(
                    self.quarantined
                        .get(content_id)
                        .filter(|held| !Self::is_operator_input(held)),
                );
            }
            copies.extend(
                self.alternative_copies
                    .get(content_id)
                    .into_iter()
                    .flatten(),
            );
            for copy in copies {
                // The served-set rule's body questions (`unservable_history`):
                // a copy that fails them is no rescue.
                match copy {
                    Directive::Transaction(txn) => {
                        if validate_transaction_as_data(txn, &self.accounts).is_err()
                            || elided_posting_count(txn) > 0
                        {
                            continue;
                        }
                    }
                    // R-15: an assertion's account is not a matter of which
                    // copy, so no copy of one the rule holds is servable.
                    Directive::Balance(balance)
                        if validate_balance_as_data(balance, &self.accounts).is_err() =>
                    {
                        continue;
                    }
                    _ => {}
                }
                if judge_signature
                    && Some(copy) != own
                    && matches!(
                        self.verify_history_directive(content_id, copy),
                        HistoryVerdict::Refused(_)
                    )
                {
                    continue;
                }
                let parents: BTreeSet<String> = match copy {
                    Directive::Transaction(txn) => txn
                        .parent_ids()
                        .into_iter()
                        .filter(|parent| !served.contains(*parent))
                        .map(str::to_owned)
                        .collect(),
                    _ => BTreeSet::new(),
                };
                let index = candidates.len();
                candidates.push((content_id.clone(), copy.clone()));
                unmet.push(parents.len());
                if parents.is_empty() {
                    ready.push_back(index);
                }
                for parent in parents {
                    waiting.entry(parent).or_default().push(index);
                }
            }
        }
        let mut chosen: Vec<(String, Directive)> = Vec::new();
        while let Some(index) = ready.pop_front() {
            let content_id = candidates[index].0.clone();
            if !served.insert(content_id.clone()) {
                continue;
            }
            chosen.push(candidates[index].clone());
            for waiter in waiting.remove(&content_id).unwrap_or_default() {
                unmet[waiter] -= 1;
                if unmet[waiter] == 0 {
                    ready.push_back(waiter);
                }
            }
        }
        chosen
    }

    /// Put back closure members whose held copy — or another copy — names only
    /// records the DAG now holds (T99 / L-144): after the operator input,
    /// whose retyped copy of a closure member (T92 / L-131) is such a record.
    /// Each re-admitted record re-enters the DAG, the accounts and the read
    /// model, leaves the quarantine and the closure, and is judged by the
    /// signature pass like all history.
    pub(super) fn readmit_closure_members_now_servable(&mut self, members: &BTreeSet<String>) {
        let held: BTreeSet<String> = members
            .iter()
            .filter(|id| self.dag.get(id.as_str()).is_none())
            .cloned()
            .collect();
        if held.is_empty() {
            return;
        }
        let chosen = self.choose_servable_copies(&held, false, true);
        if chosen.is_empty() {
            return;
        }
        let mut readmitted: Vec<String> = Vec::new();
        for (content_id, copy) in chosen {
            match self.dag.insert(copy.clone(), false) {
                Ok(InsertResult::Inserted { .. }) => {
                    self.accounts.record_lifecycle(&copy, &content_id);
                    self.read_model.index_directive(&copy);
                    self.quarantined.remove(&content_id);
                    self.refused_history_closure.remove(&content_id);
                    self.unverified_history.insert(content_id.clone());
                    readmitted.push(content_id);
                }
                Ok(InsertResult::Duplicate { .. }) | Err(_) => {}
            }
        }
        *self
            .directive_id_snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        *self
            .served_id_snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        if !readmitted.is_empty() {
            info!(
                ids = %readmitted.join(", "),
                file = %self.file_path.display(),
                "records the closure held are served again: every parent they name is a                  record this node now serves — a copy of it retyped in the file (L-144, L-131)"
            );
        }
    }

    /// Hold a directive the rebuild refused in [`Self::quarantined`] (T79):
    /// as the file spelled it when it is operator input still awaiting
    /// finalisation, never a half-stamped copy the next boot would take for
    /// history; as loaded otherwise.
    pub(super) fn hold_refused_in_quarantine(&mut self, content_id: &str, directive: Directive) {
        match self.operator_input_as_written.get(content_id).cloned() {
            Some((file_id, written)) => {
                self.hold_operator_input_as_written(file_id, written);
            }
            None => {
                self.quarantined
                    .entry(content_id.to_owned())
                    .or_insert(directive);
            }
        }
    }

    /// Rebase one entry of operator input onto the DAG being rebuilt (T79 /
    /// H-22) — see [`Self::quarantine_out_of_dag`]. `Ok(true)` when its
    /// parents changed; `Err` names why it can no longer be adopted.
    pub(super) fn rebase_operator_input(
        content_id: &str,
        directive: &mut Directive,
        hand_parented: bool,
        dag: &LedgerDag,
        accounts: &AccountState,
    ) -> Result<bool, String> {
        let txn = match directive {
            Directive::Transaction(txn) => txn,
            // R-15: an assertion has no parents to rebase, but its account's
            // `open` may be one this boot quarantined — judged now, as the
            // served-set rule would judge it at the next boot.
            Directive::Balance(balance) => {
                return validate_balance_as_data(balance, accounts)
                    .map(|()| false)
                    .map_err(|error| {
                        format!(
                            "{error} — without the records this boot quarantined, the entry no \
                             longer validates (H-22)"
                        )
                    });
            }
            _ => return Ok(false),
        };
        let before = txn.metadata.get(ENVELOPE_KEY_PARENTS).cloned();
        if hand_parented {
            if let Some(parent) = txn
                .parent_ids()
                .into_iter()
                .find(|parent| dag.get(parent).is_none())
            {
                return Err(format!(
                    "openledger-parents names {parent}, a record this boot quarantined, which is \
                     never served (H-22); a hand-spelled parent must be a record this node \
                     serves — remove the openledger-parents line to let this node choose the \
                     parents (L-75)"
                ));
            }
        } else {
            txn.metadata.insert(
                ENVELOPE_KEY_PARENTS.to_owned(),
                choose_parents_in(dag, content_id),
            );
        }
        if let Err(error) = validate_transaction_as_data(txn, accounts) {
            return Err(format!(
                "{error} — without the records this boot quarantined, the entry no longer \
                 validates (H-22)"
            ));
        }
        Ok(txn.metadata.get(ENVELOPE_KEY_PARENTS) != before.as_ref())
    }

    /// How many boot-adopted operator-input directives still await
    /// [`Self::finalize_operator_input`] (H-13). Zero on every node-written
    /// file, and zero again once finalised.
    pub fn unsigned_operator_input_count(&self) -> usize {
        self.unsigned_operator_input.len()
    }
}
