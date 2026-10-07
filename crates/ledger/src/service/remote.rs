//! Directives from peers: `insert_remote_directive` / `stage_remote_directive`.

use super::*;

/// Who delivered a remote directive, for the adoption ratchet (H-19).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteSource {
    /// Any peer: the ratchet applies ([`MAX_LAMPORT_ADVANCE`]).
    Peer,
    /// The peer this node joins from (`p2p.joinFrom`). While the join window
    /// is open ([`LedgerService::open_join_trust`]) its directives are adopted
    /// without the ratchet, as boot adopts a copy of its `.bean`; otherwise it
    /// is any peer.
    JoinPeer,
}

impl LedgerService {
    /// Open the join window (H-19): from now until [`Self::close_join_trust`],
    /// a directive staged with [`RemoteSource::JoinPeer`] is adopted without
    /// the adoption ratchet — the trusted-bootstrap join, taken over the wire
    /// instead of by copying the peer's `.bean`.
    ///
    /// Refused (returns `false`) when this ledger holds a record of this
    /// node's own: a node that has written is not joining, and its clock is
    /// the one the ratchet protects. Only the ratchet is lifted: the ceiling
    /// (`lamport_value_is_legal`), the allowlist, the signature and every
    /// content rule still apply, so the trust is exactly the file copy's — the
    /// join peer's history, whatever its lamport gaps.
    pub fn open_join_trust(&mut self) -> bool {
        let own = self.author_id.clone();
        let holds_own = self.dag.directives().into_iter().any(|directive| {
            directive_author(directive).is_some_and(|author| is_own_author(author, &own))
        });
        self.join_trust = !holds_own;
        self.join_trust
    }

    /// Close the join window: the ratchet applies to every peer again. The
    /// node calls this once it holds everything the join peer serves.
    pub fn close_join_trust(&mut self) {
        self.join_trust = false;
    }

    /// Whether the join window is open ([`Self::open_join_trust`]).
    pub fn join_trust_open(&self) -> bool {
        self.join_trust
    }

    /// Insert a validated remote directive into the ledger, persisting after it
    /// (P2P receive path, single-insert semantics).
    ///
    /// This is [`Self::stage_remote_directive`] followed by a persist: it merges
    /// the directive into memory and, only if that changed state, writes the
    /// whole `.bean` file. A failed write reloads from disk (L-13), so a caller
    /// can treat one insert as an atomic memory+disk step.
    ///
    /// For catch-up of many entries, prefer staging the whole batch with
    /// [`Self::stage_remote_directive`] and persisting once with
    /// [`Self::persist_or_reload`] — persisting per entry is the O(M×N) cost
    /// M-15 removes.
    ///
    /// Returns `Ok(Some(content_id))` if inserted, `Ok(None)` if duplicate, or `Err` if rejected.
    pub fn insert_remote_directive(
        &mut self,
        directive: Directive,
    ) -> Result<Option<String>, ServiceError> {
        let result = self.stage_remote_directive(directive)?;
        if result.is_some() {
            self.persist_or_reload()?;
        }
        Ok(result)
    }

    /// Stage a validated remote directive into in-memory state — NO persist.
    ///
    /// This is the in-memory commit half of the P2P receive path: the bridge
    /// between `p2p::union_merge::validate_supply_entry()` (which validates wire
    /// format, content hash, and envelope) and the ledger's internal state. It:
    ///
    /// 1. Adopts the Lamport clock (§3.4.2)
    /// 2. For transactions: validates I1, I2, I3 against local account state
    /// 3. Inserts into DAG (G-Set dedup handles idempotency)
    /// 4. Updates the read model incrementally
    ///
    /// It does NOT touch the file. The caller is responsible for persisting once
    /// the desired set of directives is staged, via [`Self::persist_or_reload`]
    /// (M-15: one persist per batch, not one per entry).
    ///
    /// Returns `Ok(Some(content_id))` if inserted, `Ok(None)` if duplicate, or `Err` if rejected.
    pub fn stage_remote_directive(
        &mut self,
        directive: Directive,
    ) -> Result<Option<String>, ServiceError> {
        self.stage_remote_directive_from(directive, RemoteSource::Peer)
    }

    /// [`Self::stage_remote_directive`], naming who delivered the directive:
    /// the join peer's directives skip the adoption ratchet while the join
    /// window is open (H-19, [`Self::open_join_trust`]).
    pub fn stage_remote_directive_from(
        &mut self,
        directive: Directive,
        source: RemoteSource,
    ) -> Result<Option<String>, ServiceError> {
        let content_id = compute_content_id(&directive);

        // G-Set dedup: if already present, no-op.
        if self.dag.get(&content_id).is_some() {
            return Ok(None);
        }
        // T85 / M-56, decision (18): a record naming a parent boot's closure
        // holds — a record refused under a content rule every peer applies, or
        // one descending from such a record — is refused here as the file path
        // refuses it (`adopt_file_directive`), so a running node and a
        // restarted one serve the same set.
        //
        // T90 / H-24, decision (36): judged on THIS copy's parents, and only on
        // a parent this node does not hold. Closure membership is a property
        // of the file's copy of a record, while a content id hashes the body
        // alone: a restated chain, or an API re-entry, carries the same id
        // with parents every peer can resolve, and refusing it by id kept it
        // out of this node for good (the README's own "restate the chain"
        // remedy, applied on another node, never reached this one). A record
        // whose own body breaks a content rule is refused by those rules
        // below, whatever its id. Permanent (`InvalidInput`) for what it
        // judges: gl-node buffers a directive whose parent is absent before
        // staging it, so this only sees a parent that stays refused.
        if !self.refused_history_closure.is_empty() {
            let refused_parent = match &directive {
                Directive::Transaction(txn) => txn
                    .parent_ids()
                    .into_iter()
                    .find(|parent| self.names_a_held_back_parent(parent))
                    .map(str::to_owned),
                _ => None,
            };
            if let Some(parent) = refused_parent {
                return Err(ServiceError::InvalidInput {
                    message: format!(
                        "{content_id} names parent {parent}, which this node's ledger holds back \
                         because it, or a record it descends from, breaks a content rule every \
                         peer applies to history (M-51, M-52, L-101); a copy naming parents \
                         every peer holds is adopted (M-56, H-24)"
                    ),
                });
            }
        }
        // T83 / L-94: for the lamport-gap diagnostic once it is adopted.
        let adopted_lamport = directive.lamport_clock();
        let adopted_author = directive_author(&directive).map(str::to_owned);

        // T81 / M-51: a peer's directive is history — the legacy ceilings
        // for the two T75 caps, as the wire's parser and boot apply them.
        enforce_resource_limits_for(&directive, ResourceRule::History)?;
        // H-04: reject before the Lamport clock is adopted or the DAG touched.
        validate_directive_dates(&directive)?;
        // H-06: the merged envelope legitimately sits at directive level here,
        // so the envelope keys are allowed there — but nothing else with
        // the prefix, and nothing at all at posting level (defense in depth
        // behind `validate_supply_entry`, which allows none anywhere).
        validate_body_envelope_keys(&directive, ENVELOPE_KEYS)?;
        // L-26: control characters would be persisted verbatim into the file.
        validate_body_strings(&directive)?;
        // L-25 (T37 follow-up): account/tag/link charsets. Redundant behind
        // `validate_supply_entry`'s re-parse by design — see
        // [`validate_body_names`] for why it is here anyway.
        validate_body_names(&directive)?;
        // L-02: the wire cap, re-applied to the *merged* directive. The
        // envelope is stripped from the economic form, so this is the same
        // number `validate_supply_entry` checked against the raw
        // `economic_bean`, and it also guards the library callers that reach
        // this `pub` entry point without going through the wire path.
        enforce_economic_bean_limit(&directive)?;

        if let Directive::Transaction(transaction) = &directive {
            // H-03: a remote transaction must arrive resolved. Insert stores the
            // *resolved* postings, so an elided body would be stored — and
            // re-hashed — under an id different from the one it was accepted
            // and signed under, and could then never propagate.
            if elided_posting_count(transaction) > 0 {
                return Err(ServiceError::InvalidInput {
                    message: "remote transaction has an elided posting; \
                              remote bodies must arrive with every amount resolved"
                        .to_owned(),
                });
            }
            // T41: defence in depth behind `validate_supply_entry`'s own cap,
            // for the library callers that reach this `pub` entry point without
            // the wire path — the same reason `validate_body_names` exists.
            validate_parent_fan_in(&directive)?;
            for parent_id in transaction.parent_ids() {
                if !parent_txid_is_well_formed(parent_id) {
                    return Err(ServiceError::InvalidInput {
                        message: format!(
                            "openledger-parents entry must be a 64-character lowercase hex txid, got {parent_id}"
                        ),
                    });
                }
            }
        }

        // Lamport adoption (§3.4.2): `lamport = max(local, remote) + 1`,
        // computed and bounds-checked HERE, applied only once the directive has
        // been validated and inserted. Two changes, for two different failures
        // (H-07):
        //
        // * **Checked, not clamped.** A remote value that would carry the clock
        //   to [`LAMPORT_CEILING`] is refused outright rather than adopted.
        //   Before T46 the cap bounded only what a peer could *send*, and this
        //   `+1` walked the victim straight past it; every directive the victim
        //   then stamped was out of range and refused by every peer, across
        //   reboots. `p2p::union_merge` aliases the same constant and refuses
        //   the same values one layer further out — this is the copy that
        //   protects library callers reaching this `pub` entry point directly,
        //   the same reason `validate_body_names` and `validate_parent_fan_in`
        //   are repeated above.
        // * **Applied after validation, not before.** A directive that is
        //   ultimately rejected — by `validate_transaction_as_data`, by the
        //   DAG — must leave the clock exactly
        //   where it was. Adoption used to run first, so a peer could ratchet a
        //   victim's clock with directives it knew would be thrown away, and
        //   every such bump was persisted into the next locally stamped
        //   envelope. This is the same rejection-ordering rule H-04 and L-02
        //   already follow on the local paths.
        //
        // `saturating_add` stays even though the ceiling makes overflow
        // unreachable: it is the cheapest statement of "this arithmetic never
        // wraps", and it remains correct if the cap ever moves.
        //
        // T41: the `+1` here and its absence on the reconcile path are both
        // correct — see the long note at the reconcile site for why, and for
        // why they are deliberately left different.
        //
        // T63 / H-12 — the one rule and the ratchet:
        //
        // * **The rule** is applied to `max(local, remote)`: it must be a legal
        //   value (`value + 1 < LAMPORT_CEILING`), so the clock this adopts,
        //   `max + 1`, is at most `LAMPORT_CEILING - 1`. That is the same
        //   predicate the wire applies to `remote` and the stamp applies to
        //   the value it writes — before T63 this site bounded `max + 1`
        //   against the same number the other two applied to the value, which
        //   is how `CEILING - 1` was legal to stamp and to send yet refused
        //   here.
        // * **The ratchet** refuses a `remote` more than `MAX_LAMPORT_ADVANCE`
        //   above the local clock. Without it the rule is reachable in one
        //   step: a legal directive at `CEILING - 2` stopped authoring on every
        //   adopter. See `check_lamport_advance` for why it is relative to the
        //   local clock and has no first-contact exemption.
        //
        // Ceiling first: an illegal VALUE is refused as such whatever the
        // local clock; the ratchet is the state-dependent second opinion.
        // H-19: the join peer's history is taken as a copy of its `.bean` is
        // at boot — past any gap — while the join window is open.
        let ratchet = !(source == RemoteSource::JoinPeer && self.join_trust);
        let author = directive_author(&directive);
        let next_lamport = directive
            .lamport_clock()
            .map(|remote| {
                let next = checked_lamport(self.lamport_clock.max(remote), author)?;
                if ratchet {
                    check_lamport_advance(self.lamport_clock, remote, author)?;
                }
                Ok::<u64, ServiceError>(next.saturating_add(1))
            })
            .transpose()?;

        // Validate and insert based on directive type.
        let outcome = match &directive {
            Directive::Transaction(txn) => {
                // Validate I1, I2, I3, I9 against local account state, by the
                // data rule (T98 / M-09, decision (54)): no `close` refuses a
                // peer's transaction, so the admitted set does not depend on
                // whether the `close` or the posting arrived first.
                let validated = validate_transaction_as_data(txn, &self.accounts)?;
                let final_txn = Transaction {
                    postings: validated.postings,
                    ..txn.clone()
                };
                let final_directive = Directive::Transaction(final_txn);
                match self.dag.insert(final_directive.clone(), true)? {
                    InsertResult::Inserted { content_id } => {
                        self.read_model.index_directive(&final_directive);
                        // T44: staged in memory, durable on the caller's commit.
                        self.pending_ids.push(content_id.clone());
                        Some(content_id)
                    }
                    InsertResult::Duplicate { .. } => None,
                }
            }
            Directive::Open(_) => {
                // M-09: a remote `open` is DATA. It is not applied to a mutable
                // flag that the arrival order could decide — it joins the
                // account's lifecycle event set at its own deterministic
                // position, and every query folds the set. Conflicting opens
                // and closes therefore resolve identically on every replica, so
                // there is no error left to swallow with `let _ =`.
                match self.dag.insert(directive.clone(), false)? {
                    InsertResult::Inserted { content_id } => {
                        self.accounts.record_lifecycle(&directive, &content_id);
                        self.read_model.index_directive(&directive);
                        self.pending_ids.push(content_id.clone());
                        Some(content_id)
                    }
                    InsertResult::Duplicate { .. } => None,
                }
            }
            Directive::Close(_) => {
                // T98 / M-09 remainder, decision (54): a remote `close` is data
                // too. It was refused when a held transaction fell in the
                // interval it would close, which made the verdict depend on
                // arrival order: a `close` and a posting inside its interval
                // left replicas that took them in opposite orders apart for
                // good, and since T91 a `close` staged before its own re-`open`
                // was refused and cached permanent by gl-node (H-25). Data is
                // admitted without the `close`s (`validate_transaction_as_data`),
                // so the `close` is inert over any interval that holds a
                // transaction and binds only this node's own API writes.
                match self.dag.insert(directive.clone(), false)? {
                    InsertResult::Inserted { content_id } => {
                        self.accounts.record_lifecycle(&directive, &content_id);
                        self.read_model.index_directive(&directive);
                        self.pending_ids.push(content_id.clone());
                        Some(content_id)
                    }
                    InsertResult::Duplicate { .. } => None,
                }
            }
            Directive::Balance(balance) => {
                // R-15: an assertion is data on an account the ledger opened
                // by its date. Refused until then with `AccountNotOpen`, which
                // gl-node buffers on the account (as it does a transaction),
                // so every arrival order admits the same assertions — and a
                // peer can no longer add them on accounts that never existed.
                validate_balance_as_data(balance, &self.accounts)?;
                match self.dag.insert(directive.clone(), false)? {
                    InsertResult::Inserted { content_id } => {
                        self.read_model.index_directive(&directive);
                        self.pending_ids.push(content_id.clone());
                        Some(content_id)
                    }
                    InsertResult::Duplicate { .. } => None,
                }
            }
            _ => {
                // All other directive types: insert directly.
                match self.dag.insert(directive.clone(), false)? {
                    InsertResult::Inserted { content_id } => {
                        self.read_model.index_directive(&directive);
                        self.pending_ids.push(content_id.clone());
                        Some(content_id)
                    }
                    InsertResult::Duplicate { .. } => None,
                }
            }
        };

        // T90 / H-24: a copy of a closure member is in the DAG now, parents and
        // all, so the id is no longer held back.
        if let Some(adopted) = &outcome {
            self.refused_history_closure.remove(adopted);
        }

        // H-07: adopt now — after validation, after the insert, and only when
        // the insert actually stored something. A directive we already hold was
        // folded into this clock by the ingest that stored it, and
        // `max(local, remote) + 1` is not idempotent, so re-folding a duplicate
        // would let a peer ratchet the clock by one per replayed copy.
        if outcome.is_some() {
            if let Some(next) = next_lamport {
                let clock_before = self.lamport_clock;
                self.lamport_clock = next;
                self.warn_if_adoption_opens_a_lamport_gap(
                    clock_before,
                    adopted_lamport,
                    adopted_author.as_deref(),
                );
            }
        }

        Ok(outcome)
    }

    /// Stamp a signature onto a directive's metadata after insert (§3.8.1).
    ///
    /// Prefer `append_transaction_signing` / `open_account_signing` /
    /// `close_account_signing` so the first persist already includes the signature.
    pub fn stamp_signature(
        &mut self,
        content_id: &str,
        signature_hex: &str,
    ) -> Result<(), ServiceError> {
        if let Some(directive) = self.dag.get_mut(content_id) {
            let metadata = match directive {
                Directive::Transaction(txn) => &mut txn.metadata,
                Directive::Open(d) => &mut d.metadata,
                Directive::Close(d) => &mut d.metadata,
                Directive::Commodity(d) => &mut d.metadata,
                Directive::Pad(d) => &mut d.metadata,
                Directive::Balance(d) => &mut d.metadata,
                Directive::Note(d) => &mut d.metadata,
                Directive::Document(d) => &mut d.metadata,
                Directive::Event(d) => &mut d.metadata,
                Directive::Price(d) => &mut d.metadata,
            };
            metadata.insert(ENVELOPE_KEY_SIGNATURE.to_owned(), signature_hex.to_owned());
            // T44: this edits a directive that may ALREADY be on disk, and an
            // append cannot express an edit — a journal record carrying the
            // same content id would be dropped by the G-Set on the way back in,
            // losing the signature forever. Force the full rewrite.
            self.force_compaction = true;
            // L-13: reload from disk if the persist fails, so the in-memory
            // signature stamp never gets ahead of the on-disk file.
            self.persist_or_reload()?;
        }
        Ok(())
    }
}
