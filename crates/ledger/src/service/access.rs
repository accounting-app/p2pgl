//! Read access and configuration: accessors, the served views (T93), the
//! author, signer and verifier.

use super::*;

impl LedgerService {
    // ── Helpers ──────────────────────────────────────────────────────────

    /// I1, I2, I3 and I9 for a transaction this node authors (T98 / M-09,
    /// decision (54)): the lifecycle fold with its `close`s, except a `close`
    /// already inert over the transaction's date because a transaction dated
    /// inside its interval is held — see
    /// [`crate::validate::validate_transaction_as_author`]. The local API and
    /// gl-node's pre-stage estimate both use it, so the estimate predicts the
    /// stage.
    pub fn validate_own_transaction(
        &self,
        txn: &Transaction,
    ) -> Result<Transaction, ValidationError> {
        validate_transaction_as_author(txn, &self.accounts, &|account, interval| {
            self.read_model.holds_posting_in(account, interval)
        })
    }

    /// Find the latest transaction date referencing a given account.
    ///
    /// Served from the read model's per-account index rather than by scanning
    /// the DAG. This runs on every local close (FR-3 AC2), and the scan it
    /// replaces was O(N) in the whole ledger. The index is
    /// maintained by `ReadModel::index_directive`, which every insert path
    /// already calls, and rebuilt wholesale by `ReadModel::build` at boot and
    /// after an L-13 reload, so the two views cannot drift.
    pub(super) fn latest_posting_date(&self, account: &str) -> Option<NaiveDate> {
        self.read_model.latest_posting_date(account)
    }

    // ── Accessors ────────────────────────────────────────────────────────

    /// The underlying DAG (for queries and read model).
    pub fn dag(&self) -> &LedgerDag {
        &self.dag
    }

    /// The account state tracker.
    pub fn accounts(&self) -> &AccountState {
        &self.accounts
    }

    /// The in-memory read model (for report queries).
    pub fn read_model(&self) -> &ReadModel {
        &self.read_model
    }

    /// Current Lamport clock value.
    pub fn lamport_clock(&self) -> u64 {
        self.lamport_clock
    }

    /// The author ID (Iroh EndpointId or placeholder).
    pub fn author_id(&self) -> &str {
        &self.author_id
    }

    /// How many persists have found the `.bean` changed underneath them and
    /// adopted the external edit before writing (L-30).
    ///
    /// Stays 0 on a node whose file nobody edits by hand — that is exactly what
    /// the recorded-hash fast path guarantees, and what makes a rising count a
    /// usable signal that someone is editing a live ledger file.
    pub fn external_reconcile_count(&self) -> u64 {
        self.external_reconcile_count
    }

    /// The file path being managed.
    pub fn file_path(&self) -> &Path {
        &self.file_path
    }

    /// Total number of directives.
    pub fn directive_count(&self) -> usize {
        self.dag.len()
    }

    /// Current DAG head count.
    pub fn head_count(&self) -> usize {
        self.dag.heads().len()
    }

    /// Get a directive by content ID.
    pub fn get_directive(&self, content_id: &str) -> Option<&Directive> {
        self.dag.get(content_id)
    }

    /// The directive a peer may be SERVED under `content_id` (T93 / L-116,
    /// decision (45)): what [`Self::get_directive`] returns, except a line
    /// adopted from the `.bean` whose canonical rewrite has not succeeded yet.
    ///
    /// Such a line is stamped and signed in memory only. Served before its
    /// compaction, a failed compaction plus a restart re-stamped it — boot
    /// reads the raw line again and gives it a new lamport and signature — and
    /// the mesh then held two envelopes for one id. Held back until the
    /// rewrite puts its envelope on disk, the only envelope any peer ever sees
    /// is the one the file keeps. The id is the body's, so a record naming it
    /// (a local write on top) stays valid either way.
    pub fn served_directive(&self, content_id: &str) -> Option<&Directive> {
        if self
            .withheld_ids()
            .is_some_and(|withheld| withheld.contains(content_id))
        {
            return None;
        }
        self.dag.get(content_id)
    }

    /// The records this node does not offer peers yet, or `None` when there
    /// are none: lines adopted from the `.bean` whose canonical rewrite has
    /// not succeeded (T93 / L-116) **and everything that descends from them**
    /// (T100 / L-154) — a signed child of such a line, offered alone, is a
    /// record no peer can adopt — plus every write staged and not yet
    /// committed (T100 / L-148, decision (63)): offered in the window before
    /// its commit, a write a failed commit then rolled back could be held by a
    /// peer under the `(author, lamport)` pair this node reissues after a
    /// restart. Cached under its [`WithheldKey`]; computed only while either
    /// set is non-empty.
    pub(super) fn withheld_ids(&self) -> Option<std::sync::Arc<HashSet<String>>> {
        if self.adopted_from_file.is_empty() && self.pending_ids.is_empty() {
            return None;
        }
        let key: WithheldKey = (
            self.dag.len(),
            self.adopted_from_file.len(),
            self.pending_ids.len(),
            self.pending_ids.last().cloned(),
        );
        let mut snapshot = self
            .withheld_snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((cached, withheld)) = snapshot.as_ref() {
            if *cached == key {
                return Some(std::sync::Arc::clone(withheld));
            }
        }
        let mut withheld: HashSet<String> = self.pending_ids.iter().cloned().collect();
        let mut frontier: Vec<String> = self.adopted_from_file.iter().cloned().collect();
        withheld.extend(frontier.iter().cloned());
        while let Some(id) = frontier.pop() {
            for child in self.dag.children_of(&id).unwrap_or_default() {
                if withheld.insert(child.clone()) {
                    frontier.push(child.clone());
                }
            }
        }
        let withheld = std::sync::Arc::new(withheld);
        *snapshot = Some((key, std::sync::Arc::clone(&withheld)));
        Some(withheld)
    }

    /// [`Self::head_txids`] over what this node serves (T93 / L-116; T100): a
    /// head [`Self::served_directive`] withholds is replaced by those of its
    /// parents that no served record names.
    pub fn served_head_txids(&self) -> std::collections::HashSet<String> {
        let Some(withheld) = self.withheld_ids() else {
            return self.head_txids();
        };
        let unserved = |id: &str| withheld.contains(id);
        let mut served_heads: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut seen: HashSet<String> = HashSet::new();
        let mut frontier: Vec<String> = self.dag.heads().iter().cloned().collect();
        while let Some(id) = frontier.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }
            if !unserved(&id) {
                let named_by_served = self
                    .dag
                    .children_of(&id)
                    .is_some_and(|children| children.iter().any(|child| !unserved(child)));
                if !named_by_served {
                    served_heads.insert(id);
                }
                continue;
            }
            if let Some(Directive::Transaction(txn)) = self.dag.get(&id) {
                frontier.extend(
                    txn.parent_ids()
                        .into_iter()
                        .filter(|parent| self.dag.get(parent).is_some())
                        .map(str::to_owned),
                );
            }
        }
        served_heads
    }

    /// [`Self::sorted_directive_ids`] over what this node serves (T93 /
    /// L-116; T100).
    pub fn served_sorted_directive_ids(&self) -> std::sync::Arc<[String]> {
        let all = self.sorted_directive_ids();
        let Some(withheld) = self.withheld_ids() else {
            return all;
        };
        let key: WithheldKey = (
            self.dag.len(),
            self.adopted_from_file.len(),
            self.pending_ids.len(),
            self.pending_ids.last().cloned(),
        );
        let mut snapshot = self
            .served_id_snapshot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((cached, ids)) = snapshot.as_ref() {
            if *cached == key {
                return std::sync::Arc::clone(ids);
            }
        }
        let served: std::sync::Arc<[String]> = all
            .iter()
            .filter(|id| !withheld.contains(id.as_str()))
            .cloned()
            .collect::<Vec<_>>()
            .into();
        *snapshot = Some((key, std::sync::Arc::clone(&served)));
        served
    }

    /// Compute the content ID for a directive (for lookups).
    pub fn content_id(directive: &Directive) -> String {
        compute_content_id(directive)
    }

    /// Update the author identity (called when P2P boots and we learn our EndpointId).
    ///
    /// # L-67 (T78): the clock learns what "own" meant at boot
    ///
    /// Boot counts a record that did not reach the DAG (quarantined, a
    /// duplicate body's envelope, an envelope in unparsable text) only when it
    /// is this node's own ([`BootLamportHigh`]) — and `gl-node` boots under a
    /// placeholder author, so at a process boot nothing was "own", the clock
    /// resumed below the node's own quarantined records, and the node
    /// re-issued `(author, lamport)` pairs it had already signed (M-18). So
    /// here, when the author changes, the new author's out-of-DAG high is
    /// folded exactly as boot would have folded it:
    ///
    /// * the clock is raised to resume above it;
    /// * operator input boot adopted and has not yet been finalised is stamped
    ///   from that clock by [`Self::finalize_operator_input`] (T84 / M-57,
    ///   decision (16)), so each record carries the lamport a boot under the
    ///   real author — an L-13 reload — gives it, and the envelope the mesh
    ///   sees does not depend on whether a startup compaction ever failed.
    ///   (T78 re-stamped it here by the same shift; stamping at finalisation
    ///   subsumes that.)
    ///
    /// Nothing moves when boot already counted the value (booted with this
    /// author) or the DAG already carries the clock above it. A shift that
    /// would stamp past [`LAMPORT_CEILING`] is not applied (the node cannot
    /// author there anyway); the clock is still raised, so every later stamp
    /// refuses loudly instead of re-issuing a pair.
    pub fn set_author_id(&mut self, author_id: String) {
        self.author_id = author_id;
        // T89 / L-96: the placeholder's records are this node's too.
        let placeholder_high = self
            .boot_outside_dag_lamports
            .get(PLACEHOLDER_AUTHOR)
            .copied()
            .unwrap_or(0);
        let own_high = self
            .boot_outside_dag_lamports
            .get(self.author_id.as_str())
            .copied()
            .unwrap_or(0)
            .max(placeholder_high);
        // Boot's own rule: resume at `max + 1` when anything is non-zero.
        let resume = if own_high > 0 {
            own_high.saturating_add(1)
        } else {
            0
        };
        // Boot counts the placeholder's records as its own on every path, so
        // they never move the clock here. When they are what carries it, boot
        // (under the placeholder, as the node always boots) named author
        // `local` with the mesh-wide allowlist remedy; the L-91 WARN below is
        // the correct one — a pre-signing record of this node's own file
        // (T89 / L-96).
        let carried_by_placeholder =
            placeholder_high > 0 && placeholder_high.saturating_add(1) >= self.lamport_clock;
        if resume <= self.boot_clock_base && !carried_by_placeholder {
            return;
        }
        // T84 / M-57, decision (16): operator input adopted at boot is stamped
        // by `finalize_operator_input` from this clock, so raising the clock is
        // all L-67 needs here — the re-stamp of its placeholder lamports that
        // lived here is gone with them.
        let before = self.lamport_clock;
        if resume > self.boot_clock_base {
            self.boot_clock_base = resume;
            self.lamport_clock = self.lamport_clock.max(resume);
        }
        // L-91 (T80): boot warns when the next stamp will refuse, but under
        // the placeholder author it could not count this node's own records
        // outside the DAG — they are folded only here. Same predicates as
        // boot; the source is this node's own file, so the remedy is to repair
        // it, never to remove an author from anyone's allowlist.
        if self.lamport_clock != before || carried_by_placeholder {
            if !lamport_value_is_legal(self.lamport_clock.saturating_add(1)) {
                warn!(
                    author = %self.author_id,
                    own_high,
                    lamport_clock = self.lamport_clock,
                    ceiling = LAMPORT_CEILING,
                    file = %self.file_path.display(),
                    "this node's OWN records outside the ledger (quarantined, or held as \
                     unparsable text) carry an openledger-lamport at the Lamport ceiling, and the \
                     clock now resumes above them: this node will refuse to author. No other node \
                     carried it here — find the block with this node's openledger-author (or \
                     \"local\", written before signing) and that lamport in the .bean and delete \
                     or repair it, then restart (L-91, L-96, H-12)"
                );
            } else if LAMPORT_CEILING - self.lamport_clock <= MAX_LAMPORT_ADVANCE {
                warn!(
                    author = %self.author_id,
                    own_high,
                    lamport_clock = self.lamport_clock,
                    ceiling = LAMPORT_CEILING,
                    file = %self.file_path.display(),
                    "this node's OWN records outside the ledger carry an openledger-lamport \
                     within one adoption step (2^32) of the Lamport ceiling, and the clock now \
                     resumes above them; no honest history gets here. Find the block with this \
                     node's openledger-author (or \"local\", written before signing) and that \
                     lamport in the .bean (L-91, L-96, H-12)"
                );
            }
        }
        if self.lamport_clock != before {
            info!(
                author = %self.author_id,
                own_high,
                lamport_clock = self.lamport_clock,
                "this node's own records outside the DAG (quarantined, or held as unparsable \
                 text) carry lamports above the clock boot resumed at under its placeholder \
                 author; the clock now resumes above them so no (author, lamport) pair is \
                 issued twice (L-67, M-18)"
            );
        }
    }

    /// Install the signer reconcile uses to stamp adopted entries (L-11).
    ///
    /// Called once at boot, alongside [`Self::set_author_id`] and before the
    /// file watcher starts, so an adoption can never race an unset signer.
    /// Passing a provider that has signing disabled is fine and is what a
    /// signing-off node does: the callback returns `None` and adoption behaves
    /// exactly as it did before this existed.
    pub fn set_signer(&mut self, signer: DirectiveSigner) {
        self.signer = Some(signer);
        // H-20: the node can now say what its own signatures look like, so
        // its own history is checked here and now; see `verify_own_history`.
        self.verify_history_pass();
    }

    /// L-114: write even while every signature this node checked failed —
    /// the operator's override (`signing.allowWritesWhenEverySignatureFails`).
    /// Off by default: such a write would be signed under the wrong domain
    /// and hide the verdict at the next boot.
    pub fn set_write_despite_signature_verdict(&mut self, allow: bool) {
        self.write_despite_signature_verdict = allow;
    }

    /// Install the verifier [`Self::verify_own_history`] checks loaded
    /// signatures with (H-20).
    ///
    /// Mirrors [`Self::set_signer`]: installed once, right after the signer,
    /// before the file watcher and before anything is served; carried across
    /// every L-13 reload. Installing it runs the verification pass over
    /// whatever the signer's pass could not decide — every foreign-authored
    /// record — so each directive is checked exactly once.
    pub fn set_verifier(&mut self, verifier: DirectiveVerifier) {
        self.verifier = Some(verifier);
        self.verify_history_pass();
    }

    /// The largest lamport gap in the history this node serves (T83 / L-94) —
    /// the quantity the H-19 warning compares with [`LAMPORT_GAP_WARN`]. O(n
    /// log n); diagnostics and tests only.
    pub fn lamport_gap(&self) -> u64 {
        self.lamport_gap_and_top().0
    }

    /// [`largest_lamport_gap`] over the DAG: the gap and the lamport at its top.
    pub(super) fn lamport_gap_and_top(&self) -> (u64, u64) {
        largest_lamport_gap(
            self.dag
                .directives()
                .into_iter()
                .filter_map(Directive::lamport_clock),
        )
    }

    /// Get the set of current DAG head txids (for anti-entropy exchange).
    pub fn head_txids(&self) -> std::collections::HashSet<String> {
        self.dag.heads().iter().cloned().collect()
    }

    /// Get the set of all directive content IDs in the DAG (for anti-entropy exchange).
    ///
    /// **O(N) `String` clones per call** (L-35). Kept, with its signature, for
    /// the callers that genuinely want an owned, mutable set; the anti-entropy
    /// hot paths should use [`Self::contains_directive`] /
    /// [`Self::is_head`] for membership and [`Self::sorted_directive_ids`] for
    /// the advert.
    pub fn all_directive_ids(&self) -> std::collections::HashSet<String> {
        self.dag
            .content_ids()
            .into_iter()
            .map(|s| s.to_owned())
            .collect()
    }

    /// Is `content_id` in the DAG? O(1), no allocation (L-35).
    ///
    /// The membership half of what `all_directive_ids()` was being cloned for:
    /// computing a Want list against a peer's advert, and `drain_orphans`'
    /// "is this parent here yet?". Exact under the write lock too — a staged
    /// directive is in the DAG from the moment it is staged — so a caller that
    /// kept a cloned set in step with its own inserts can drop the set.
    pub fn contains_directive(&self, content_id: &str) -> bool {
        self.dag.get(content_id).is_some()
    }

    /// Is `txid` one of the current DAG heads? O(1), no allocation (L-35).
    pub fn is_head(&self, txid: &str) -> bool {
        self.dag.heads().contains(txid)
    }

    /// Every content id in the DAG, sorted ascending, as a shared snapshot
    /// (L-35).
    ///
    /// # Why
    ///
    /// `all_directive_ids()` clones every id into a fresh `HashSet<String>`,
    /// and anti-entropy called it twice per peer per tick plus once per
    /// inbound advert — O(N) allocations each time, under the ledger's read
    /// lock, whether or not anything had changed. The advert then copied the
    /// set into a `Vec` and sorted it, a second O(N log N) pass.
    ///
    /// # What it costs now
    ///
    /// The snapshot is built — once, sorted, in exactly the order the advert
    /// pages need — the first time it is asked for after the DAG has grown,
    /// and every later call until the next insert is an `Arc` clone. On a mesh
    /// at rest that is O(1) per tick instead of O(N); on a busy one it is at
    /// most one rebuild per batch of arrivals, however many peers ask. The
    /// invalidation key is the DAG's size, which is exact because the DAG is
    /// grow-only (see `directive_id_snapshot`).
    pub fn sorted_directive_ids(&self) -> std::sync::Arc<[String]> {
        let size = self.dag.len();
        let mut snapshot = self
            .directive_id_snapshot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((taken_at, ids)) = snapshot.as_ref() {
            if *taken_at == size {
                return std::sync::Arc::clone(ids);
            }
        }
        let mut ids: Vec<String> = self
            .dag
            .content_ids()
            .into_iter()
            .map(str::to_owned)
            .collect();
        ids.sort_unstable();
        let ids: std::sync::Arc<[String]> = ids.into();
        *snapshot = Some((size, std::sync::Arc::clone(&ids)));
        ids
    }

    /// Parent txids on `directive` that are not yet in the local DAG (§3.4.4).
    pub fn missing_parent_ids(&self, directive: &Directive) -> Vec<String> {
        let Directive::Transaction(transaction) = directive else {
            return Vec::new();
        };
        transaction
            .parent_ids()
            .into_iter()
            .filter(|parent_id| !parent_id.is_empty() && self.dag.get(parent_id).is_none())
            .map(|parent_id| parent_id.to_owned())
            .collect()
    }
}
