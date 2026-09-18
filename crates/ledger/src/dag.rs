//! Transaction Merkle-DAG and directive G-Set (§3.3, §3.4).
//!
//! The DAG tracks parent→child edges for transactions. Non-transaction directives
//! are stored in a flat G-Set keyed by `directiveId`. Both are content-addressed
//! and deduplicated.

use std::collections::{HashMap, HashSet};

use crate::hash::compute_content_id;
use crate::model::*;

// ─── DAG node ────────────────────────────────────────────────────────────────

/// A node in the transaction DAG.
#[derive(Debug, Clone)]
struct DagNode {
    directive: Directive,
    /// Parent txids (transactions only). Empty for genesis or non-transactions.
    parents: Vec<String>,
    /// Child txids (reverse edges for traversal).
    children: Vec<String>,
}

// ─── Ledger DAG ──────────────────────────────────────────────────────────────

/// The core data structure: a G-Set of directives with a Merkle-DAG over transactions.
#[derive(Debug, Clone)]
pub struct LedgerDag {
    /// All directives keyed by content ID.
    nodes: HashMap<String, DagNode>,
    /// Transaction IDs that have no children — the frontier.
    heads: HashSet<String>,
    /// Insertion order (for deterministic iteration).
    insertion_order: Vec<String>,
    /// Reverse edges recorded for parents that were not in the DAG yet, keyed by
    /// the missing parent's content ID (L-17).
    ///
    /// A `.bean` file can list a child before its parent, and anti-entropy can
    /// deliver them in either order, so `insert` regularly runs with the parent
    /// absent. Without this the child's reverse edge was simply dropped: when the
    /// parent finally arrived it came in with an empty `children` vector and was
    /// recorded as a head even though a child already pointed at it — a
    /// permanently wrong frontier, advertised to every peer. Entries are drained
    /// by the parent's own insert, so this only ever holds edges whose parent is
    /// still missing.
    ///
    /// It is also the *exact* index the I8 cycle check needs (L-14): see
    /// [`LedgerDag::check_no_cycle`].
    ///
    /// ## Growth bound (T41 — verified, no pruning added)
    ///
    /// Edges parked for a parent that NEVER arrives are never pruned: nothing
    /// expires them, and only the parent's own insert drains them. That is
    /// deliberate — there is no safe moment to decide a parent will not arrive,
    /// since an anti-entropy round or a hand edit can supply it at any time, and
    /// dropping the edge early reintroduces exactly the wrong-frontier bug
    /// (L-17) this index exists to fix.
    ///
    /// It is bounded, and tightly, which is why no pruning is warranted:
    ///
    /// * One parked edge per (child, missing-parent) pair, so the total is at
    ///   most `transactions × MAX_PARENTS`.
    /// * `MAX_PARENTS` (256) is now enforced on **every** ingress — the wire
    ///   path always did, and T41 added it at boot and at reconcile. Before
    ///   that, a hand-written file could name unboundedly many parents on one
    ///   transaction, and this map was bounded only by file size.
    /// * Transactions are bounded by the 64 MiB ledger-file cap.
    /// * Each edge is two 64-character ids, so the map is the same order of
    ///   magnitude as the DAG itself — it cannot be the thing that exhausts
    ///   memory before the DAG does.
    ///
    /// It also cannot grow without inserts (no timer, no background writer), and
    /// a reboot rebuilds it from the file under the same bound.
    pending_children: HashMap<String, Vec<String>>,
    /// Per-insert node-visit budget for the I8 check (L-14).
    ///
    /// Always [`MAX_CYCLE_CHECK_VISITS`] in production; overridable only from
    /// tests, so the exhaustion branch can be exercised without building a
    /// 16,384-node adversarial graph.
    cycle_check_budget: usize,
}

/// Node visits one insert's I8 check may make before it refuses to answer (L-14).
///
/// The check below is designed so that honest data costs nothing: it does no
/// work at all unless a node already in the DAG names the incoming directive as
/// a parent, and in the shapes that legitimately produce such a dangling forward
/// reference (a backdated append re-read at boot) the search it then runs
/// terminates within a handful of visits. This budget is the backstop for a
/// crafted file that manages to make **both** search directions large at once —
/// it turns an unbounded per-insert cost into a constant one, at the price of
/// refusing that directive. 16,384 is far above anything the honest shapes can
/// reach and far below the point where the cost is noticeable.
const MAX_CYCLE_CHECK_VISITS: usize = 16_384;

/// Result of inserting a directive into the DAG.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsertResult {
    /// Successfully inserted (new directive).
    Inserted { content_id: String },
    /// Already present (G-Set idempotency).
    Duplicate { content_id: String },
}

/// Error from a DAG insert operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DagError {
    /// I8: adding this transaction would create a cycle.
    CycleDetected { txid: String },
    /// A parent txid is not (yet) in the DAG.
    MissingParent { txid: String, parent: String },
    /// L-14: the I8 acyclicity check could not be answered within
    /// [`MAX_CYCLE_CHECK_VISITS`], so the directive is refused rather than
    /// admitted unchecked. Only reachable on a deliberately crafted parent
    /// graph — see [`LedgerDag::check_no_cycle`].
    CycleCheckExhausted { txid: String, visits: usize },
}

impl std::fmt::Display for DagError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DagError::CycleDetected { txid } => {
                write!(f, "Cycle detected: adding {txid} would create a cycle")
            }
            DagError::MissingParent { txid, parent } => {
                write!(
                    f,
                    "Missing parent: {txid} references unknown parent {parent}"
                )
            }
            DagError::CycleCheckExhausted { txid, visits } => {
                write!(
                    f,
                    "Acyclicity check for {txid} exceeded {visits} node visits; \
                     refusing the directive rather than admitting it unchecked"
                )
            }
        }
    }
}

impl std::error::Error for DagError {}

impl LedgerDag {
    pub fn new() -> Self {
        LedgerDag {
            nodes: HashMap::new(),
            heads: HashSet::new(),
            insertion_order: Vec::new(),
            pending_children: HashMap::new(),
            cycle_check_budget: MAX_CYCLE_CHECK_VISITS,
        }
    }

    /// Insert a directive into the G-Set / DAG.
    ///
    /// For transactions: validates parent links and acyclicity (I8).
    /// For non-transactions: simple G-Set insert.
    ///
    /// `require_parents` controls whether missing parents cause an error or are
    /// tolerated (e.g., during boot where directives are loaded in file order,
    /// parents may arrive later via anti-entropy).
    pub fn insert(
        &mut self,
        directive: Directive,
        require_parents: bool,
    ) -> Result<InsertResult, DagError> {
        let content_id = compute_content_id(&directive);

        // G-Set dedup: if already present, no-op.
        if self.nodes.contains_key(&content_id) {
            return Ok(InsertResult::Duplicate { content_id });
        }

        let parents = match &directive {
            Directive::Transaction(txn) => txn.parent_ids().iter().map(|s| s.to_string()).collect(),
            _ => Vec::new(),
        };

        // Validate parent links for transactions.
        if matches!(directive, Directive::Transaction(_)) && require_parents {
            for parent_id in &parents {
                if !parent_id.is_empty() && !self.nodes.contains_key(parent_id) {
                    return Err(DagError::MissingParent {
                        txid: content_id,
                        parent: parent_id.clone(),
                    });
                }
            }
        }

        // I8: check for cycles (would this txid already be an ancestor of any parent?).
        //
        // One check for the whole directive, not one per parent (L-14): the
        // search shares a single budget and a single visited set across all of
        // them, so a transaction with K parents costs one traversal rather than
        // K independent ones.
        if matches!(directive, Directive::Transaction(_)) {
            self.check_no_cycle(&content_id, &parents)?;
        }

        // Insert the node, adopting any reverse edges that were parked while
        // this directive was still missing (L-17). An out-of-order file or an
        // out-of-order anti-entropy batch lands the child first; its
        // `children.push` below found no node to write into and parked the edge
        // here instead.
        let is_transaction = matches!(directive, Directive::Transaction(_));
        let backfilled_children = self
            .pending_children
            .remove(&content_id)
            .unwrap_or_default();
        let has_children = !backfilled_children.is_empty();
        let node = DagNode {
            directive,
            parents: parents.clone(),
            children: backfilled_children,
        };
        self.nodes.insert(content_id.clone(), node);
        self.insertion_order.push(content_id.clone());

        // Update parent→child edges and head tracking.
        if is_transaction {
            // A transaction is a head only while nothing points at it. A
            // backfilled child means it was superseded by a directive that
            // arrived earlier, so it must NOT enter the frontier (L-17).
            if !has_children {
                self.heads.insert(content_id.clone());
            }

            // Parents are no longer heads (they now have a child).
            for parent_id in &parents {
                if !parent_id.is_empty() {
                    self.heads.remove(parent_id);
                    match self.nodes.get_mut(parent_id) {
                        Some(parent_node) => parent_node.children.push(content_id.clone()),
                        // Parent not here (yet): park the reverse edge so the
                        // parent's own insert can adopt it.
                        None => self
                            .pending_children
                            .entry(parent_id.clone())
                            .or_default()
                            .push(content_id.clone()),
                    }
                }
            }
        }

        Ok(InsertResult::Inserted { content_id })
    }

    /// I8: refuse `new_id` if adding it with these `parents` would close a cycle.
    ///
    /// # What has to be true for a cycle (L-14)
    ///
    /// `new_id` is not in the DAG — [`Self::insert`] checked that immediately
    /// above — so a cycle means some path `parent → … → new_id` already exists.
    /// The final hop of that path is an edge *into* `new_id`, and only a node
    /// that is present can carry one. By [`Self::pending_children`]'s invariant,
    /// the present nodes naming an absent id as a parent are exactly
    /// `pending_children[new_id]`. So, writing `S = pending_children[new_id]`:
    ///
    /// > a cycle exists **iff** `new_id` is one of its own parents, or some
    /// > `x ∈ S` is an ancestor-or-self of one of the parents.
    ///
    /// Two consequences, and they are the whole fix:
    ///
    /// 1. **`S` empty ⇒ no cycle, with no traversal at all.** This replaces the
    ///    M-6 fast path, which tested a `referenced_parent_ids` set that was
    ///    never pruned: once anything had *ever* named an id, every insert of a
    ///    directive with that id paid a full ancestor walk. `pending_children`
    ///    is drained the moment the parent arrives, so the skip stays true.
    ///    A well-formed ledger has no dangling parent pointers at all outside
    ///    boot's re-read of backdated appends, so this is almost always the
    ///    answer.
    /// 2. **The question is symmetric, so search from both ends at once.**
    ///    "Is some `x ∈ S` an ancestor of a parent" is the same as "is some
    ///    parent a descendant of some `x ∈ S`", and *either* search answers
    ///    `false` the moment it runs out of nodes. Stepping them in lockstep
    ///    therefore costs the **smaller** of the two closures. That matters
    ///    because the two are lopsided in practice: `S` holds freshly-arrived
    ///    leaves with no descendants, while the parent's ancestry is the entire
    ///    ledger history.
    ///
    /// # The attack this closes
    ///
    /// A crafted file plants one decoy transaction, dated early so boot's
    /// canonical sort loads it first, whose `openledger-parents` names every
    /// content id in a long chain that follows. Parents live in the envelope and
    /// are excluded from the content hash, so every id is computable offline and
    /// nothing has to be mined. That single line made `referenced_parent_ids`
    /// contain the whole chain, so each of the N links then walked its entire
    /// ancestry: O(N²) visits, each cloning a 64-character `String`. Measured on
    /// a 5,000-link file: 19.6 s to boot (debug), scaling ~5× for a 2× file.
    /// With the decoy as the only seed and nothing descending from it, the
    /// descendant side now exhausts immediately and boot is linear.
    ///
    /// # Residual
    ///
    /// A more elaborate file can still make both closures large at once (two
    /// long chains, one hanging off the seed and one above the parent). That is
    /// what [`MAX_CYCLE_CHECK_VISITS`] is for: the budget caps each insert's
    /// cost and the directive is refused rather than admitted unchecked. Boot
    /// tolerates that refusal per directive (L-17) and logs it.
    fn check_no_cycle(&self, new_id: &str, parents: &[String]) -> Result<(), DagError> {
        let targets: HashSet<&str> = parents
            .iter()
            .map(String::as_str)
            .filter(|parent| !parent.is_empty())
            .collect();
        if targets.is_empty() {
            return Ok(());
        }
        // A directive naming itself as a parent is a one-node cycle.
        if targets.contains(new_id) {
            return Err(DagError::CycleDetected {
                txid: new_id.to_owned(),
            });
        }

        let Some(seeds) = self.pending_children.get(new_id) else {
            return Ok(());
        };
        let seed_set: HashSet<&str> = seeds.iter().map(String::as_str).collect();

        // Downward frontier: descendants of the seeds, looking for a parent.
        let mut down: Vec<&str> = seed_set.iter().copied().collect();
        let mut down_seen: HashSet<&str> = seed_set.clone();
        // Upward frontier: ancestors of the parents, looking for a seed.
        let mut up: Vec<&str> = targets.iter().copied().collect();
        let mut up_seen: HashSet<&str> = targets.clone();

        let mut budget = self.cycle_check_budget;
        loop {
            // Either frontier running dry settles the question: that side's
            // whole closure has been enumerated without a hit. Checked BEFORE
            // the budget, because an answer we already have costs nothing.
            let (Some(descendant), Some(ancestor)) = (down.pop(), up.pop()) else {
                return Ok(());
            };
            if budget < 2 {
                return Err(DagError::CycleCheckExhausted {
                    txid: new_id.to_owned(),
                    visits: self.cycle_check_budget,
                });
            }
            budget -= 2;

            if targets.contains(descendant) || seed_set.contains(ancestor) {
                return Err(DagError::CycleDetected {
                    txid: new_id.to_owned(),
                });
            }

            if let Some(node) = self.nodes.get(descendant) {
                for child in &node.children {
                    if down_seen.insert(child.as_str()) {
                        down.push(child.as_str());
                    }
                }
            }
            if let Some(node) = self.nodes.get(ancestor) {
                for parent in &node.parents {
                    if !parent.is_empty() && up_seen.insert(parent.as_str()) {
                        up.push(parent.as_str());
                    }
                }
            }
        }
    }

    // ─── Accessors ───────────────────────────────────────────────────────

    /// The current head txids (transactions with no children).
    pub fn heads(&self) -> &HashSet<String> {
        &self.heads
    }

    /// Total number of directives in the G-Set.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Whether the G-Set is empty.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Get a directive by its content ID.
    pub fn get(&self, content_id: &str) -> Option<&Directive> {
        self.nodes.get(content_id).map(|n| &n.directive)
    }

    /// Get a mutable reference to a directive by its content ID.
    ///
    /// Used for post-insert metadata stamping (e.g., signatures).
    pub fn get_mut(&mut self, content_id: &str) -> Option<&mut Directive> {
        self.nodes.get_mut(content_id).map(|n| &mut n.directive)
    }

    /// Iterate all directives in insertion order.
    pub fn directives(&self) -> Vec<&Directive> {
        self.insertion_order
            .iter()
            .filter_map(|id| self.nodes.get(id).map(|n| &n.directive))
            .collect()
    }

    /// Iterate only transaction directives.
    pub fn transactions(&self) -> Vec<&Transaction> {
        self.directives()
            .into_iter()
            .filter_map(|d| match d {
                Directive::Transaction(t) => Some(t),
                _ => None,
            })
            .collect()
    }

    /// Get the parent txids for a given content ID.
    pub fn parents_of(&self, content_id: &str) -> Option<&[String]> {
        self.nodes.get(content_id).map(|n| n.parents.as_slice())
    }

    /// Get the child txids for a given content ID.
    pub fn children_of(&self, content_id: &str) -> Option<&[String]> {
        self.nodes.get(content_id).map(|n| n.children.as_slice())
    }

    /// All content IDs in the G-Set.
    pub fn content_ids(&self) -> Vec<&str> {
        self.insertion_order.iter().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
impl LedgerDag {
    /// Test-only: a DAG whose I8 check gives up after `budget` node visits.
    pub fn with_cycle_check_budget(budget: usize) -> Self {
        LedgerDag {
            cycle_check_budget: budget,
            ..LedgerDag::new()
        }
    }

    /// Test-only: insert a directive under a fake/tampered content ID.
    ///
    /// This bypasses the normal content-hash computation so we can test
    /// `verify_dag` detection of mismatched hashes (CT-8).
    ///
    /// It deliberately maintains `pending_children` exactly as [`Self::insert`]
    /// does. That index is not bookkeeping any more — since L-14 it is what
    /// [`Self::check_no_cycle`] reads to decide whether a cycle is even
    /// possible — so a helper that skipped it would leave the DAG in a state no
    /// real insert can produce and would quietly disable the check in every test
    /// that uses it.
    pub fn insert_with_fake_id(
        &mut self,
        fake_id: String,
        directive: Directive,
        parents: Vec<String>,
    ) {
        let backfilled_children = self.pending_children.remove(&fake_id).unwrap_or_default();
        let node = DagNode {
            directive,
            parents: parents.clone(),
            children: backfilled_children,
        };
        self.nodes.insert(fake_id.clone(), node);
        self.insertion_order.push(fake_id.clone());

        // Update parent→child edges.
        for parent_id in &parents {
            if !parent_id.is_empty() {
                self.heads.remove(parent_id);
                match self.nodes.get_mut(parent_id) {
                    Some(parent_node) => parent_node.children.push(fake_id.clone()),
                    None => self
                        .pending_children
                        .entry(parent_id.clone())
                        .or_default()
                        .push(fake_id.clone()),
                }
            }
        }
        self.heads.insert(fake_id);
    }
}

impl Default for LedgerDag {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use rust_decimal_macros::dec;
    use std::collections::BTreeMap;

    fn make_date(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).unwrap()
    }

    fn make_txn(narration: &str, parent_ids: &[&str]) -> Directive {
        let mut metadata = BTreeMap::new();
        let parents_str = parent_ids.join(",");
        metadata.insert("openledger-parents".to_owned(), parents_str);
        metadata.insert("openledger-author".to_owned(), "test-peer".to_owned());
        metadata.insert("openledger-lamport".to_owned(), "1".to_owned());

        Directive::Transaction(Transaction {
            date: make_date(2024, 1, 15),
            flag: Flag::Complete,
            payee: None,
            narration: Some(narration.to_owned()),
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
        })
    }

    fn make_open(account: &str) -> Directive {
        Directive::Open(Open {
            date: make_date(2024, 1, 1),
            account: account.to_owned(),
            currencies: vec!["USD".to_owned()],
            metadata: BTreeMap::new(),
        })
    }

    #[test]
    fn test_cycle_still_detected_after_fast_path() {
        // M-6 regression: the O(1) fast-path short-circuit must not cause a false
        // negative. A directive whose content hash is *already referenced* as a
        // parent (an out-of-order / crafted case) must still be rejected as a
        // cycle — the fast path only skips the walk for hashes nothing points to.
        let mut dag = LedgerDag::new();

        // The directive we will eventually insert; its content id is `h`.
        let d = make_txn("cycle-node", &["PID"]);
        let h = compute_content_id(&d);

        // Pre-insert a node "PID" that references `h` as a parent, making `h` an
        // ancestor of "PID". Inserting `d` (id `h`, parent "PID") then closes the
        // cycle h -> PID -> h.
        dag.insert_with_fake_id(
            "PID".to_owned(),
            make_txn("parent-node", &[]),
            vec![h.clone()],
        );

        let result = dag.insert(d, false);
        assert!(
            matches!(result, Err(DagError::CycleDetected { .. })),
            "expected CycleDetected, got {result:?}"
        );
    }

    // ── L-14: the I8 check must be cheap, and bounded when it is not ─────

    /// Insert a chain of `length` transactions, returning every content id in
    /// order. `first_parent` is the chain root's parent (`None` for genesis).
    fn insert_chain(
        dag: &mut LedgerDag,
        tag: &str,
        length: usize,
        root_parent: Option<&str>,
    ) -> Vec<String> {
        let mut ids = Vec::with_capacity(length);
        let mut parent = root_parent.map(str::to_owned);
        for index in 0..length {
            let txn = match &parent {
                Some(p) => make_txn(&format!("{tag}-{index}"), &[p.as_str()]),
                None => make_txn(&format!("{tag}-{index}"), &[]),
            };
            let id = match dag.insert(txn, false).unwrap() {
                InsertResult::Inserted { content_id } => content_id,
                other => panic!("expected insert, got {other:?}"),
            };
            parent = Some(id.clone());
            ids.push(id);
        }
        ids
    }

    #[test]
    fn test_dangling_reference_does_not_trigger_an_ancestry_walk() {
        // The L-14 mechanism, in miniature. A decoy transaction names a long
        // chain's ids as parents before any of them exist. Under the old
        // `referenced_parent_ids` fast path every one of those inserts then paid
        // a full ancestor walk; under `pending_children` the decoy is the only
        // possible completion of a cycle, it has no children, and the search
        // exhausts at once.
        //
        // Asserted behaviourally rather than by timing: with a visit budget of
        // TWO, all 200 chained inserts still succeed — they cannot be doing an
        // O(depth) walk.
        let mut dag = LedgerDag::with_cycle_check_budget(2);

        // Pre-compute the chain ids, exactly as an attacker would offline.
        let mut probe = LedgerDag::new();
        let ids = insert_chain(&mut probe, "link", 200, None);

        let decoy = make_txn("decoy", &ids.iter().map(String::as_str).collect::<Vec<_>>());
        dag.insert(decoy, false).unwrap();

        let inserted = insert_chain(&mut dag, "link", 200, None);
        assert_eq!(inserted, ids, "the chain must load identically");
        assert_eq!(dag.len(), 201);
    }

    #[test]
    fn test_cycle_check_refuses_rather_than_walking_an_unbounded_graph() {
        // The residual the budget exists for: a shape where BOTH search
        // directions are large. `seed` has a long descendant chain and a
        // dangling parent `X`; `X` itself arrives with a long ancestor chain.
        // Neither side can be exhausted cheaply, so the check gives up and the
        // directive is refused — never admitted unchecked.
        let mut dag = LedgerDag::with_cycle_check_budget(8);

        // Work out `X`'s id first: it is the next link of a separate chain.
        let mut probe = LedgerDag::new();
        let above = insert_chain(&mut probe, "above", 40, None);
        let x_id = compute_content_id(&make_txn("x", &[above[39].as_str()]));

        // Seed references the not-yet-present X, and a long chain hangs off it.
        let seed = make_txn("seed", &[x_id.as_str()]);
        let seed_id = match dag.insert(seed, false).unwrap() {
            InsertResult::Inserted { content_id } => content_id,
            other => panic!("{other:?}"),
        };
        insert_chain(&mut dag, "below", 40, Some(&seed_id));
        let above = insert_chain(&mut dag, "above", 40, None);

        let error = dag
            .insert(make_txn("x", &[above[39].as_str()]), false)
            .unwrap_err();
        assert!(
            matches!(error, DagError::CycleCheckExhausted { visits: 8, .. }),
            "expected the budget to stop the walk, got {error:?}"
        );
        assert!(
            error.to_string().contains("refusing the directive"),
            "{error}"
        );
    }

    #[test]
    fn test_cycle_through_a_long_chain_is_still_detected() {
        // No false negatives from the tighter fast path: a genuine cycle that
        // only closes after a long ancestry walk is still caught, at the full
        // production budget.
        let mut dag = LedgerDag::new();

        // `x` will be inserted last, with the chain tip as its parent; the chain
        // ROOT names `x` as its parent, closing x -> tip -> … -> root -> x.
        let mut probe = LedgerDag::new();
        let probe_chain = insert_chain(&mut probe, "c", 1, None);
        let _ = probe_chain;
        let x_body = make_txn("x", &[]);
        let x_id = compute_content_id(&x_body);

        let root = make_txn("chain-root", &[x_id.as_str()]);
        let root_id = match dag.insert(root, false).unwrap() {
            InsertResult::Inserted { content_id } => content_id,
            other => panic!("{other:?}"),
        };
        let chain = insert_chain(&mut dag, "c", 64, Some(&root_id));

        let error = dag
            .insert(make_txn("x", &[chain[63].as_str()]), false)
            .unwrap_err();
        assert!(
            matches!(error, DagError::CycleDetected { .. }),
            "got {error:?}"
        );
    }

    #[test]
    fn test_self_parent_is_a_cycle() {
        let mut dag = LedgerDag::new();
        let body = make_txn("self", &[]);
        let own_id = compute_content_id(&body);
        let error = dag
            .insert(make_txn("self", &[own_id.as_str()]), false)
            .unwrap_err();
        assert!(matches!(error, DagError::CycleDetected { .. }), "{error:?}");
    }

    #[test]
    fn test_forward_chain_takes_fast_path() {
        // The common case: a plain forward chain never trips the cycle check and
        // inserts cleanly (the fast path returns false for each fresh hash).
        let mut dag = LedgerDag::new();
        let mut parent = String::new();
        for i in 0..64 {
            let txn = if parent.is_empty() {
                make_txn(&format!("n{i}"), &[])
            } else {
                make_txn(&format!("n{i}"), &[parent.as_str()])
            };
            parent = match dag.insert(txn, false).unwrap() {
                InsertResult::Inserted { content_id } => content_id,
                other => panic!("expected insert, got {other:?}"),
            };
        }
        assert_eq!(dag.len(), 64);
    }

    // ── Basic insert ─────────────────────────────────────────────────────

    #[test]
    fn test_empty_dag() {
        let dag = LedgerDag::new();
        assert!(dag.is_empty());
        assert_eq!(dag.len(), 0);
        assert!(dag.heads().is_empty());
    }

    #[test]
    fn test_insert_non_transaction() {
        let mut dag = LedgerDag::new();
        let open = make_open("Assets:Cash");
        let result = dag.insert(open, false).unwrap();
        assert!(matches!(result, InsertResult::Inserted { .. }));
        assert_eq!(dag.len(), 1);
        // Non-transactions don't affect heads.
        assert!(dag.heads().is_empty());
    }

    #[test]
    fn test_insert_genesis_transaction() {
        let mut dag = LedgerDag::new();
        let txn = make_txn("Genesis", &[]);
        let result = dag.insert(txn, false).unwrap();
        match result {
            InsertResult::Inserted { ref content_id } => {
                assert!(dag.heads().contains(content_id));
            }
            _ => panic!("Expected Inserted"),
        }
        assert_eq!(dag.heads().len(), 1);
    }

    // ── G-Set dedup ──────────────────────────────────────────────────────

    #[test]
    fn test_duplicate_is_noop() {
        let mut dag = LedgerDag::new();
        let txn = make_txn("Dedup test", &[]);
        let first = dag.insert(txn.clone(), false).unwrap();
        let second = dag.insert(txn, false).unwrap();

        assert!(matches!(first, InsertResult::Inserted { .. }));
        assert!(matches!(second, InsertResult::Duplicate { .. }));
        assert_eq!(dag.len(), 1);
    }

    // ── Parent-child edges ───────────────────────────────────────────────

    #[test]
    fn test_parent_child_edges() {
        let mut dag = LedgerDag::new();

        // Genesis.
        let genesis = make_txn("Genesis", &[]);
        let genesis_id = match dag.insert(genesis, false).unwrap() {
            InsertResult::Inserted { content_id } => content_id,
            _ => panic!("Expected Inserted"),
        };

        // Child referencing genesis.
        let child = make_txn("Child", &[&genesis_id]);
        let child_id = match dag.insert(child, false).unwrap() {
            InsertResult::Inserted { content_id } => content_id,
            _ => panic!("Expected Inserted"),
        };

        // Genesis is no longer a head; child is.
        assert!(!dag.heads().contains(&genesis_id));
        assert!(dag.heads().contains(&child_id));
        assert_eq!(dag.heads().len(), 1);

        // Parent → child edge.
        assert!(dag.children_of(&genesis_id).unwrap().contains(&child_id));
    }

    /// L-17: the same two directives, inserted child-first.
    ///
    /// A `.bean` file can list a child above its parent (a hand edit, a paste,
    /// a merge) and anti-entropy can deliver them in either order. Before the
    /// backfill the late-arriving parent came in with an empty `children` vector
    /// and was recorded as a head, so the frontier this node advertised named a
    /// transaction that had already been superseded.
    #[test]
    fn test_out_of_order_insert_backfills_children_and_heads() {
        let genesis = make_txn("Genesis", &[]);
        let genesis_id = compute_content_id(&genesis);
        let child = make_txn("Child", &[&genesis_id]);
        let child_id = compute_content_id(&child);

        let mut dag = LedgerDag::new();
        // Child first — its parent does not exist yet.
        dag.insert(child, false).unwrap();
        assert_eq!(
            dag.heads().len(),
            1,
            "with the parent still missing the child is the only head"
        );
        // ... and only now the parent.
        dag.insert(genesis, false).unwrap();

        assert!(
            dag.children_of(&genesis_id).unwrap().contains(&child_id),
            "L-17: the parent must adopt the reverse edge parked by its child"
        );
        assert!(
            !dag.heads().contains(&genesis_id),
            "L-17: a parent that already has a child is not a head"
        );
        assert!(dag.heads().contains(&child_id));
        assert_eq!(
            dag.heads().len(),
            1,
            "L-17: arrival order must not change the frontier"
        );
    }

    /// The frontier and the reverse edges must not depend on insertion order at
    /// all — forward and reversed loads of the same chain agree exactly (L-17).
    #[test]
    fn test_heads_and_children_are_insertion_order_independent() {
        let a = make_txn("A", &[]);
        let a_id = compute_content_id(&a);
        let b = make_txn("B", &[&a_id]);
        let b_id = compute_content_id(&b);
        let c = make_txn("C", &[&b_id]);
        let c_id = compute_content_id(&c);

        let forward = [a.clone(), b.clone(), c.clone()];
        let reversed = [c, b, a];

        let mut snapshots = Vec::new();
        for order in [forward, reversed] {
            let mut dag = LedgerDag::new();
            for directive in order {
                dag.insert(directive, false).unwrap();
            }
            let mut children: Vec<(String, Vec<String>)> = [&a_id, &b_id, &c_id]
                .iter()
                .map(|id| ((*id).clone(), dag.children_of(id).unwrap().to_vec()))
                .collect();
            children.sort();
            let mut heads: Vec<String> = dag.heads().iter().cloned().collect();
            heads.sort();
            snapshots.push((heads, children));
        }

        assert_eq!(
            snapshots[0], snapshots[1],
            "L-17: insertion order must not change heads or children"
        );
        assert_eq!(snapshots[0].0, vec![c_id], "only C is a head either way");
    }

    // ── Missing parent (strict mode) ─────────────────────────────────────

    #[test]
    fn test_missing_parent_strict_rejected() {
        let mut dag = LedgerDag::new();
        let txn = make_txn("Orphan", &["nonexistent_parent_id"]);
        let err = dag.insert(txn, true).unwrap_err();
        assert!(matches!(err, DagError::MissingParent { .. }));
    }

    #[test]
    fn test_missing_parent_lenient_accepted() {
        let mut dag = LedgerDag::new();
        let txn = make_txn("Orphan", &["nonexistent_parent_id"]);
        let result = dag.insert(txn, false);
        assert!(result.is_ok());
    }

    // ── Head tracking ────────────────────────────────────────────────────

    #[test]
    fn test_multiple_heads() {
        let mut dag = LedgerDag::new();

        // Two independent genesis transactions.
        let genesis_a = make_txn("Genesis A", &[]);
        let genesis_b = make_txn("Genesis B", &[]);

        dag.insert(genesis_a, false).unwrap();
        dag.insert(genesis_b, false).unwrap();

        assert_eq!(dag.heads().len(), 2);
    }

    #[test]
    fn test_merge_reduces_heads() {
        let mut dag = LedgerDag::new();

        let genesis_a = make_txn("Genesis A", &[]);
        let id_a = match dag.insert(genesis_a, false).unwrap() {
            InsertResult::Inserted { content_id } => content_id,
            _ => panic!(),
        };

        let genesis_b = make_txn("Genesis B", &[]);
        let id_b = match dag.insert(genesis_b, false).unwrap() {
            InsertResult::Inserted { content_id } => content_id,
            _ => panic!(),
        };

        assert_eq!(dag.heads().len(), 2);

        // Merge: a transaction with both as parents.
        let merge = make_txn("Merge", &[&id_a, &id_b]);
        dag.insert(merge, false).unwrap();

        assert_eq!(dag.heads().len(), 1);
    }

    // ── Accessors ────────────────────────────────────────────────────────

    #[test]
    fn test_get_directive() {
        let mut dag = LedgerDag::new();
        let open = make_open("Assets:Cash");
        let id = compute_content_id(&open);
        dag.insert(open, false).unwrap();
        assert!(dag.get(&id).is_some());
        assert!(dag.get("nonexistent").is_none());
    }

    #[test]
    fn test_directives_returns_all() {
        let mut dag = LedgerDag::new();
        dag.insert(make_open("Assets:Cash"), false).unwrap();
        dag.insert(make_open("Equity:Opening"), false).unwrap();
        dag.insert(make_txn("Genesis", &[]), false).unwrap();

        assert_eq!(dag.directives().len(), 3);
        assert_eq!(dag.transactions().len(), 1);
    }

    #[test]
    fn test_content_ids() {
        let mut dag = LedgerDag::new();
        dag.insert(make_open("Assets:Cash"), false).unwrap();
        dag.insert(make_txn("Genesis", &[]), false).unwrap();

        let ids = dag.content_ids();
        assert_eq!(ids.len(), 2);
    }
}
