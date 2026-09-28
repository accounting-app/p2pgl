//! This node's own writes: the input types, the `append` / `open` / `close`
//! mutations, and envelope stamping (§3.3.1, §3.4.2).

use super::*;

// ─── Input types ─────────────────────────────────────────────────────────────

/// Input for appending a transaction (domain-level; GraphQL layer converts to this).
#[derive(Debug, Clone)]
pub struct TransactionInput {
    pub date: NaiveDate,
    pub flag: Flag,
    pub payee: Option<String>,
    pub narration: Option<String>,
    pub tags: Vec<String>,
    pub links: Vec<String>,
    pub postings: Vec<PostingInput>,
}

/// A single posting in a transaction input.
#[derive(Debug, Clone)]
pub struct PostingInput {
    pub account: String,
    pub amount: Option<Amount>,
    pub cost: Option<CostSpec>,
    pub price: Option<PriceSpec>,
}

/// What a local append actually did (§3.5 write path, M-10 interim signal).
///
/// The content id hashes the economic body only — every `openledger-*` envelope
/// key (author, parents, lamport, signature) is excluded — so an append whose
/// body is already in the DAG is a no-op that keeps the *existing* entry's
/// envelope. That entry may have been authored by another peer, which is the
/// M-10 authorship-squatting shape; it may equally be a legitimately distinct
/// but identical event (two identical same-day coffees) collapsed into one
/// posting. Either way the caller must be able to tell the two apart from a
/// fresh insert, so the append path reports it instead of returning the
/// pre-existing txid as if it had just been created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendOutcome {
    /// The transaction's content id — newly inserted, or the pre-existing one.
    pub txid: String,
    /// `true` when this exact economic body was already in the ledger and
    /// nothing new was recorded.
    pub already_existed: bool,
}

impl LedgerService {
    // ── Mutations ────────────────────────────────────────────────────────

    /// Append a new transaction to the ledger (§3.5 write path).
    ///
    /// Validates I1 (balance), I2 (elision), I3 (lifecycle), I9 (currency),
    /// stamps envelope metadata, inserts into DAG, and persists to file.
    /// Returns the `txid` together with whether the body was already present
    /// ([`AppendOutcome`], M-10).
    pub fn append_transaction(
        &mut self,
        input: TransactionInput,
    ) -> Result<AppendOutcome, ServiceError> {
        self.append_transaction_signing(input, |_, _, _| None)
    }

    /// Append a transaction, attaching `openledger-signature` before the first persist (M-11).
    ///
    /// Durable when it returns: this is
    /// [`Self::append_transaction_staged`] followed by an inline
    /// [`Self::persist_or_reload`]. Callers that want the fsync off the ledger
    /// write lock (T44) use the staged form and drive the commit themselves.
    pub fn append_transaction_signing(
        &mut self,
        input: TransactionInput,
        sign: impl FnOnce(&str, &str, &str) -> Option<String>,
    ) -> Result<AppendOutcome, ServiceError> {
        let outcome = self.append_transaction_staged(input, sign)?;
        // A duplicate body staged nothing, so this is a no-op for it (T44:
        // `prepare_commit` returns `None` when there is nothing to write and
        // nobody has touched the file).
        self.persist_or_reload()?;
        Ok(outcome)
    }

    /// Append a transaction into **memory only** — no file write (T44).
    ///
    /// Everything [`Self::append_transaction_signing`] does except the durable
    /// write: validate, stamp, sign, insert, index. The directive is recorded
    /// as pending, so the next [`Self::prepare_commit`] carries it to disk.
    ///
    /// The caller owes the ledger a commit. Until one lands, in-memory state is
    /// ahead of disk — which is exactly the window L-13 exists to close, and is
    /// why the node layer takes the single-writer gate around the whole
    /// stage → prepare → commit → finish sequence.
    pub fn append_transaction_staged(
        &mut self,
        input: TransactionInput,
        sign: impl FnOnce(&str, &str, &str) -> Option<String>,
    ) -> Result<AppendOutcome, ServiceError> {
        // H-04: a date the file grammar cannot read back would brick the next
        // boot, so refuse it before anything is built, stamped, or persisted.
        validate_ledger_date(input.date)?;

        // Build the Transaction from the input up-front (no envelope yet), so
        // every check below runs on exactly the value that will be hashed,
        // stamped, inserted and persisted — and so the shared `&Directive`
        // validators the remote path uses can run here unchanged (L-02).
        let directive = Directive::Transaction(Transaction {
            date: input.date,
            flag: input.flag,
            payee: input.payee,
            narration: input.narration,
            tags: input.tags,
            links: input.links,
            postings: input
                .postings
                .into_iter()
                .map(|p| Posting {
                    account: p.account,
                    amount: p.amount,
                    cost: p.cost,
                    price: p.price,
                    metadata: BTreeMap::new(),
                })
                .collect(),
            metadata: BTreeMap::new(),
        });

        // §3.12: resource limit checks — the same `enforce_resource_limits` the
        // peer-ingest path runs, rather than a second copy of the same five
        // comparisons against the same five constants (L-02).
        enforce_resource_limits(&directive)?;
        // L-02: and the wire size cap, so this node cannot author a directive
        // every peer is obliged to refuse.
        enforce_economic_bean_limit(&directive)?;

        let Directive::Transaction(txn) = &directive else {
            unreachable!("constructed as a transaction directly above")
        };

        if let Some(ref narration) = txn.narration {
            reject_control_characters("narration", narration)
                .map_err(|message| ServiceError::InvalidInput { message })?;
        }
        if let Some(ref payee) = txn.payee {
            reject_control_characters("payee", payee)
                .map_err(|message| ServiceError::InvalidInput { message })?;
        }
        for tag in &txn.tags {
            validate_tag(tag).map_err(|_| ServiceError::InvalidTag { tag: tag.clone() })?;
        }
        for link in &txn.links {
            validate_link(link).map_err(|_| ServiceError::InvalidLink { link: link.clone() })?;
        }
        for posting in &txn.postings {
            validate_account_name(&posting.account).map_err(|_| {
                ServiceError::InvalidAccountName {
                    account: posting.account.clone(),
                }
            })?;
            if let Some(ref amount) = posting.amount {
                validate_currency(&amount.currency).map_err(|_| ServiceError::InvalidCurrency {
                    currency: amount.currency.clone(),
                })?;
            }
            if let Some(ref cost) = posting.cost {
                if let Some(ref cost_amount) = cost.amount {
                    validate_currency(&cost_amount.currency).map_err(|_| {
                        ServiceError::InvalidCurrency {
                            currency: cost_amount.currency.clone(),
                        }
                    })?;
                }
                // H-04: cost dates serialize as `%Y-%m-%d` too.
                if let Some(cost_date) = cost.date {
                    validate_ledger_date(cost_date)?;
                }
            }
            if let Some(ref price) = posting.price {
                let currency = match price {
                    PriceSpec::Unit(amount) | PriceSpec::Total(amount) => &amount.currency,
                };
                validate_currency(currency).map_err(|_| ServiceError::InvalidCurrency {
                    currency: currency.clone(),
                })?;
            }
        }

        // Validate (I1, I2, I3, I9). Returns resolved txn with elided posting filled.
        let mut resolved = self.validate_own_transaction(txn)?;

        // The content id hashes the economic body only — the envelope stamped
        // next is excluded — so it is known before stamping, and the stamp
        // needs it to choose parents that cannot close a cycle (L-40).
        let content_id = compute_content_id(&Directive::Transaction(resolved.clone()));

        // Stamp envelope metadata (§3.3.1, §3.4.2). Refuses at the Lamport
        // ceiling (H-07); nothing has been mutated yet, so the refusal costs
        // the caller an error and nothing else.
        self.stamp_transaction_envelope(&mut resolved.metadata, &content_id)?;

        let (parents, lamport) = Self::envelope_parents_and_lamport(&resolved.metadata);
        if let Some(signature_hex) = sign(&content_id, parents, lamport) {
            resolved
                .metadata
                .insert(ENVELOPE_KEY_SIGNATURE.to_owned(), signature_hex);
        }

        // T64 / H-16: the fan-in cap every peer applies, as an invariant on the
        // local insert. `choose_parents` already names at most `MAX_PARENTS`,
        // so this cannot fire today; it is here because the only fan-in check
        // this path used to reach was the FILE one at the next boot, which is
        // how an over-cap append was accepted locally, refused everywhere, and
        // then quarantined out of this node's own DAG. A refusal here has moved
        // the clock by one unused value, which is harmless: gaps never collide.
        let directive = Directive::Transaction(resolved);
        validate_parent_fan_in(&directive)?;

        // Insert into DAG.
        let content_id = match self.dag.insert(directive.clone(), false)? {
            InsertResult::Inserted { content_id } => content_id,
            InsertResult::Duplicate { content_id } => {
                // FR-1 AC4: idempotent by content. Nothing is inserted, nothing
                // is persisted, and the envelope just stamped above is thrown
                // away — the entry that stays is whichever one landed first,
                // with *its* author and signature. M-10: say so rather than
                // handing the caller a pre-existing txid that looks fresh.
                return Ok(AppendOutcome {
                    txid: content_id,
                    already_existed: true,
                });
            }
        };

        // Update read model incrementally.
        self.read_model.index_directive(&directive);

        // T44: durable on the next commit, not before this call returns.
        self.pending_ids.push(content_id.clone());

        Ok(AppendOutcome {
            txid: content_id,
            already_existed: false,
        })
    }

    /// Open a new account (FR-3 AC1).
    ///
    /// Validates that the account is not already open, creates the directive,
    /// stamps envelope, inserts into DAG, and persists.
    /// Returns the `directiveId`.
    pub fn open_account(
        &mut self,
        account: String,
        date: NaiveDate,
        currencies: Vec<String>,
    ) -> Result<String, ServiceError> {
        self.open_account_signing(account, date, currencies, |_, _, _| None)
    }

    /// Open an account, attaching `openledger-signature` before the first persist (M-11).
    ///
    /// Durable when it returns — see [`Self::append_transaction_signing`].
    pub fn open_account_signing(
        &mut self,
        account: String,
        date: NaiveDate,
        currencies: Vec<String>,
        sign: impl FnOnce(&str, &str, &str) -> Option<String>,
    ) -> Result<String, ServiceError> {
        let content_id = self.open_account_staged(account, date, currencies, sign)?;
        self.persist_or_reload()?;
        Ok(content_id)
    }

    /// Open an account into **memory only** — no file write (T44).
    ///
    /// See [`Self::append_transaction_staged`] for the contract.
    pub fn open_account_staged(
        &mut self,
        account: String,
        date: NaiveDate,
        currencies: Vec<String>,
        sign: impl FnOnce(&str, &str, &str) -> Option<String>,
    ) -> Result<String, ServiceError> {
        validate_account_name(&account).map_err(|_| ServiceError::InvalidAccountName {
            account: account.clone(),
        })?;
        // H-04: refuse an unrepresentable date before any state change.
        validate_ledger_date(date)?;
        for currency in &currencies {
            validate_currency(currency).map_err(|_| ServiceError::InvalidCurrency {
                currency: currency.clone(),
            })?;
        }

        // FR-3 AC1: opening an already-open account errors.
        if self.accounts.is_open(&account) {
            return Err(ServiceError::AccountAlreadyOpen {
                account: account.clone(),
            });
        }

        // Build the Open directive with an EMPTY envelope so the size checks
        // below can run before `stamp_directive_envelope` moves the Lamport
        // clock — a refused write must leave the clock exactly where it was
        // (L-02, same rejection-ordering rule as H-04's).
        let mut directive = Directive::Open(Open {
            date,
            account: account.clone(),
            currencies,
            metadata: BTreeMap::new(),
        });
        enforce_resource_limits(&directive)?;
        // L-02: `currencies` has no cardinality cap and currency codes are 24
        // bytes each, so an `open` is as able to exceed the wire limit as a
        // transaction is.
        enforce_economic_bean_limit(&directive)?;

        let Directive::Open(open) = &mut directive else {
            unreachable!("constructed as an open directly above")
        };
        self.stamp_directive_envelope(&mut open.metadata)?;

        let content_id = compute_content_id(&directive);
        let Directive::Open(open) = &mut directive else {
            unreachable!("constructed as an open directly above")
        };
        let (parents, lamport) = Self::envelope_parents_and_lamport(&open.metadata);
        if let Some(signature_hex) = sign(&content_id, parents, lamport) {
            open.metadata
                .insert(ENVELOPE_KEY_SIGNATURE.to_owned(), signature_hex);
        }

        // Insert into DAG.
        let content_id = match self.dag.insert(directive.clone(), false)? {
            InsertResult::Inserted { content_id } => content_id,
            InsertResult::Duplicate { content_id } => return Ok(content_id),
        };

        // Update account state (M-09): record the event under the content id
        // and envelope the DAG just stored, so that this node's live state and
        // its state after a reboot from the same file are identical.
        self.accounts.record_lifecycle(&directive, &content_id);

        // T44: durable on the next commit.
        self.pending_ids.push(content_id.clone());

        Ok(content_id)
    }

    /// Close an account (FR-3 AC2).
    ///
    /// Validates that the account is open and has no transactions after the close date.
    /// Returns the `directiveId`.
    pub fn close_account(
        &mut self,
        account: String,
        date: NaiveDate,
    ) -> Result<String, ServiceError> {
        self.close_account_signing(account, date, |_, _, _| None)
    }

    /// Close an account, attaching `openledger-signature` before the first persist (M-11).
    ///
    /// Durable when it returns — see [`Self::append_transaction_signing`].
    pub fn close_account_signing(
        &mut self,
        account: String,
        date: NaiveDate,
        sign: impl FnOnce(&str, &str, &str) -> Option<String>,
    ) -> Result<String, ServiceError> {
        let content_id = self.close_account_staged(account, date, sign)?;
        self.persist_or_reload()?;
        Ok(content_id)
    }

    /// Close an account into **memory only** — no file write (T44).
    ///
    /// See [`Self::append_transaction_staged`] for the contract.
    pub fn close_account_staged(
        &mut self,
        account: String,
        date: NaiveDate,
        sign: impl FnOnce(&str, &str, &str) -> Option<String>,
    ) -> Result<String, ServiceError> {
        validate_account_name(&account).map_err(|_| ServiceError::InvalidAccountName {
            account: account.clone(),
        })?;
        // H-04: refuse an unrepresentable date before any state change.
        validate_ledger_date(date)?;

        // Must be currently open.
        if !self.accounts.is_open(&account) {
            return Err(ServiceError::AccountNotOpen {
                account: account.clone(),
            });
        }

        // FR-3 AC2: no transactions after the close date.
        if let Some(latest) = self.latest_posting_date(&account) {
            if latest > date {
                return Err(ServiceError::AccountHasLaterTransactions {
                    account: account.clone(),
                    latest_date: latest,
                });
            }
        }

        // Build the Close directive with an EMPTY envelope — see
        // `open_account_signing` for why the size checks precede the stamp.
        let mut directive = Directive::Close(Close {
            date,
            account: account.clone(),
            metadata: BTreeMap::new(),
        });
        enforce_resource_limits(&directive)?;
        // L-02: a `close` is bounded by its account name, which has a charset
        // but no length limit of its own.
        enforce_economic_bean_limit(&directive)?;

        let Directive::Close(close) = &mut directive else {
            unreachable!("constructed as a close directly above")
        };
        self.stamp_directive_envelope(&mut close.metadata)?;

        let content_id = compute_content_id(&directive);
        let Directive::Close(close) = &mut directive else {
            unreachable!("constructed as a close directly above")
        };
        let (parents, lamport) = Self::envelope_parents_and_lamport(&close.metadata);
        if let Some(signature_hex) = sign(&content_id, parents, lamport) {
            close
                .metadata
                .insert(ENVELOPE_KEY_SIGNATURE.to_owned(), signature_hex);
        }

        // Insert into DAG.
        let content_id = match self.dag.insert(directive.clone(), false)? {
            InsertResult::Inserted { content_id } => content_id,
            InsertResult::Duplicate { content_id } => return Ok(content_id),
        };

        // Update account state (M-09) — see `open_account_staged`.
        self.accounts.record_lifecycle(&directive, &content_id);

        // T44: durable on the next commit.
        self.pending_ids.push(content_id.clone());

        Ok(content_id)
    }

    // ── Envelope stamping (§3.3.1, §3.4.2) ───────────────────────────────

    /// Stamp transaction-level envelope metadata (parents + author + lamport).
    ///
    /// Writes only keys from [`ENVELOPE_KEYS`] — the closed set every ingest
    /// path enforces.
    ///
    /// Refuses — rather than saturating — when the value to be stamped is not
    /// legal under [`lamport_value_is_legal`] (H-07, H-12): the largest value
    /// this node stamps is `LAMPORT_CEILING - 2`, the largest every peer's wire
    /// check and every peer's adoption accept. A directive stamped past that is
    /// not a degraded write, it is an invisible one: this node would return
    /// success while every peer refused the result forever. The caller is told
    /// at the point of writing instead. The check runs before any mutation, so
    /// a refusal leaves the clock and the metadata exactly as they were — the
    /// same rejection-ordering rule H-04 and L-02 follow.
    ///
    /// `content_id` is the id the transaction will be stored under; parents are
    /// chosen by [`Self::choose_parents`] (L-40, and at most [`MAX_PARENTS`] of
    /// them since T64).
    pub(super) fn stamp_transaction_envelope(
        &mut self,
        metadata: &mut Metadata,
        content_id: &str,
    ) -> Result<(), ServiceError> {
        let parents = self.choose_parents(content_id);
        self.lamport_clock = self.next_stamp()?;
        metadata.insert(ENVELOPE_KEY_AUTHOR.to_owned(), self.author_id.clone());
        metadata.insert(
            ENVELOPE_KEY_LAMPORT.to_owned(),
            self.lamport_clock.to_string(),
        );
        metadata.insert(ENVELOPE_KEY_PARENTS.to_owned(), parents);
        Ok(())
    }

    /// The `openledger-parents` value for a transaction this node stamps, whose
    /// content id will be `content_id` (§3.3.1, L-40, T64 / H-16).
    ///
    /// The current heads this transaction can name without closing a cycle
    /// ([`LedgerDag::heads_admissible_as_parents_of`]), sorted ascending, and —
    /// since T64 — **at most [`MAX_PARENTS`] of them**, picked by
    /// [`select_parents`]: author diversity first, then smallest id. The rest
    /// stay heads and are merged by later appends.
    ///
    /// Before T64 this named every admissible head. One allowlisted peer
    /// sending 257 valid parentless transactions therefore made the victim's
    /// next append name 257 parents: it returned success, was refused by every
    /// peer (`openledger-parents has 257 entries`), and was quarantined out of
    /// the victim's own DAG at its next boot — its own posting gone from its
    /// own balances — while the planted heads stayed heads, so it happened
    /// again. Naming fewer parents loses nothing: parents record what the
    /// author had seen, and any subset of the heads is a valid, acyclic choice
    /// (a subset of an admissible set is admissible). The choice is a pure
    /// function of the head set, so two replicas holding the same heads name
    /// the same parents.
    ///
    /// Shared by every site that stamps parents — the local append and the file
    /// path's adoption of a parentless operator entry — so they cannot drift.
    pub(super) fn choose_parents(&self, content_id: &str) -> String {
        choose_parents_in(&self.dag, content_id)
    }

    /// [`Self::choose_parents`] for a line adopted from the FILE: the heads
    /// among records a commit has already written, never a write staged and
    /// not yet committed (T93 / M-65, decision (43)).
    ///
    /// A hand edit is adopted inside the `prepare` of whatever write comes
    /// next. Its parents used to be every head, the write staged in that same
    /// call included; if that commit then failed, the recovery reload found a
    /// kept hand-line envelope naming a record the rebuild lacked and refused
    /// to install (M-59) — so memory, with the write whose call had just
    /// returned an error, was kept, counted and served, and on an over-cap
    /// ledger every later write staged, failed and was kept too. A staged
    /// head is replaced by its own parents, walked back to what is committed,
    /// and a candidate that a committed record already names is dropped, so
    /// the choice is exactly the heads of the committed DAG.
    ///
    /// T100 / L-149: the staged set and the committed records it names are
    /// computed once per staged set ([`Self::staged_frontier`]), not per
    /// adopted line — an adoption pass stages nothing — so a large hand edit
    /// adopted beside a large staged batch costs the lines plus the batch, not
    /// their product.
    pub(super) fn choose_committed_parents(&self, content_id: &str) -> String {
        if self.pending_ids.is_empty() {
            return self.choose_parents(content_id);
        }
        let frontier = self.staged_frontier();
        let (pending, named_by_staged) = (&frontier.0, &frontier.1);
        let mut committed: BTreeSet<&str> = self
            .dag
            .heads_admissible_as_parents_of(content_id)
            .into_iter()
            .filter(|head| !pending.contains(*head))
            .collect();
        committed.extend(
            named_by_staged
                .iter()
                .map(String::as_str)
                .filter(|id| *id != content_id),
        );
        committed.retain(|id| {
            self.dag.children_of(id).is_none_or(|children| {
                children
                    .iter()
                    .all(|child| pending.contains(child.as_str()) || child == content_id)
            })
        });
        let mut candidates: Vec<(&str, Option<&str>)> = committed
            .into_iter()
            .map(|head| (head, self.dag.get(head).and_then(directive_author)))
            .collect();
        select_parents(&mut candidates).join(",")
    }

    /// The staged ids and the committed records a staged transaction names as
    /// a parent (T100 / L-149), cached under the staged count and last id —
    /// `pending_ids` only grows by staging and is emptied by a commit, and a
    /// rebuild that shrinks it resets the cache.
    pub(super) fn staged_frontier(&self) -> std::sync::Arc<(HashSet<String>, Vec<String>)> {
        let key = (self.pending_ids.len(), self.pending_ids.last().cloned());
        let mut cache = self
            .staged_frontier
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((cached, frontier)) = cache.as_ref() {
            if *cached == key {
                return std::sync::Arc::clone(frontier);
            }
        }
        let pending: HashSet<String> = self.pending_ids.iter().cloned().collect();
        let mut named: BTreeSet<String> = BTreeSet::new();
        for id in &self.pending_ids {
            if let Some(Directive::Transaction(txn)) = self.dag.get(id) {
                named.extend(
                    txn.parent_ids()
                        .into_iter()
                        .filter(|parent| {
                            !pending.contains(*parent) && self.dag.get(parent).is_some()
                        })
                        .map(str::to_owned),
                );
            }
        }
        let frontier = std::sync::Arc::new((pending, named.into_iter().collect()));
        *cache = Some((key, std::sync::Arc::clone(&frontier)));
        frontier
    }

    /// The value this node stamps next, checked against the one Lamport rule
    /// (H-07, H-12) — see [`checked_lamport`].
    ///
    /// On a refusal the error names the author of the highest-lamport
    /// directive this node holds (DAG or quarantine): that is the directive
    /// that carried the clock to the ceiling, and its author is the first thing
    /// the mesh-wide remedy needs. Found by a scan, on the refusal path only —
    /// a node that reaches it can no longer author, so the scan costs nothing
    /// that matters, and no extra state has to survive reloads.
    pub(super) fn next_stamp(&self) -> Result<u64, ServiceError> {
        let next = self.lamport_clock.saturating_add(1);
        checked_lamport(next, None).map_err(|_| ServiceError::LamportCeiling {
            next,
            author: self.highest_lamport_author(),
        })
    }

    /// Author to name for the clock's height (H-12 / H-19 diagnostics; refusal
    /// and warning paths only, both gated or terminal, so the scan is free).
    ///
    /// The highest-lamport directive this node holds, in the DAG or in the
    /// quarantine, **preferring one not authored by this node** when any
    /// exists (T72 (d)). Once this node has authored on top of a peer's jump
    /// its own record is the highest of all, and naming it named the victim;
    /// the peer that carried the clock there is the one the remedy starts
    /// with. A node holding only its own records names itself, which is then
    /// the truth.
    pub(super) fn highest_lamport_author(&self) -> Option<String> {
        self.dag
            .directives()
            .into_iter()
            .chain(self.quarantined.values())
            .filter_map(|directive| {
                let author = directive_author(directive)?;
                Some((directive.lamport_clock()?, author))
            })
            // L-91 (T80): and what boot saw outside the DAG — envelopes held
            // in unparsable text are in neither map above.
            .chain(
                self.boot_outside_dag_lamports
                    .iter()
                    .map(|(author, lamport)| (*lamport, author.as_str())),
            )
            .map(|(lamport, author)| (!is_own_author(author, &self.author_id), lamport, author))
            .max_by_key(|(foreign, lamport, _)| (*foreign, *lamport))
            // T89 / L-96: the placeholder is this node — name it by its id.
            .map(|(foreign, _, author)| {
                if foreign {
                    author.to_owned()
                } else {
                    self.author_id.clone()
                }
            })
    }

    /// T72 / H-19 (T83 / L-94, L-83): warn when an adoption opens a lamport
    /// gap in the history — see [`LAMPORT_GAP_WARN`]. A gap is opened by
    /// exactly one adoption (the one whose lamport sits that far above the
    /// clock before it), so this fires once per jump without any gating, names
    /// the author of the jumping directive itself, and never fires on an
    /// adoption BELOW the clock — however high this node's own records outside
    /// the ledger carried the clock (L-83).
    pub(super) fn warn_if_adoption_opens_a_lamport_gap(
        &self,
        clock_before: u64,
        lamport: Option<u64>,
        author: Option<&str>,
    ) {
        let Some(lamport) = lamport else {
            return;
        };
        let gap = lamport.saturating_sub(clock_before);
        if gap < LAMPORT_GAP_WARN {
            return;
        }
        warn!(
            gap,
            below = clock_before,
            top = lamport,
            threshold = LAMPORT_GAP_WARN,
            author = author.unwrap_or("(unknown)"),
            "an adopted directive opened a lamport gap in the history no honest mesh makes; \
             this node is unaffected. {}",
            lamport_gap_verdict(gap, gap)
        );
    }

    /// Stamp non-transaction directive envelope (author + lamport, no parents).
    ///
    /// Writes only keys from [`ENVELOPE_KEYS`]. Refuses at [`LAMPORT_CEILING`]
    /// for the reason spelled out on [`Self::stamp_transaction_envelope`]
    /// (H-07) — opens, closes and every other kind are stamped from the same
    /// clock and are refused by peers on the same bound.
    pub(super) fn stamp_directive_envelope(
        &mut self,
        metadata: &mut Metadata,
    ) -> Result<(), ServiceError> {
        self.lamport_clock = self.next_stamp()?;
        metadata.insert(ENVELOPE_KEY_AUTHOR.to_owned(), self.author_id.clone());
        metadata.insert(
            ENVELOPE_KEY_LAMPORT.to_owned(),
            self.lamport_clock.to_string(),
        );
        Ok(())
    }

    pub(super) fn envelope_parents_and_lamport(metadata: &Metadata) -> (&str, &str) {
        (
            metadata
                .get("openledger-parents")
                .map(String::as_str)
                .unwrap_or(""),
            metadata
                .get("openledger-lamport")
                .map(String::as_str)
                .unwrap_or(""),
        )
    }
}
