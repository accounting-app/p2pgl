//! Deterministic account lifecycle state (M-09).
//!
//! Account open/close state used to be one mutable record per account
//! (`open_date`, `currencies`, `close_date`) updated in ARRIVAL order: the last
//! `open` applied overwrote the account's open date and currency list, and any
//! `close` overwrote the close date regardless of how the two were dated. Two
//! replicas handed the same directives in different orders therefore disagreed
//! permanently, and one allowlisted peer's `close Assets:Cash` dated 1970 shut
//! the account on every node that saw it.
//!
//! This module re-backs the same [`AccountState`] API with an ORDER-INSENSITIVE
//! event model. Per account we keep the *set* of lifecycle directives, each
//! placed in a total order by the tuple
//!
//! ```text
//! (date, §3.3.2 type priority, openledger-lamport, content id)
//! ```
//!
//! Every component is a property of the directive itself, so the position of an
//! event in the order does not depend on when it arrived — inserting the same
//! set in any order yields the same map, and therefore the same answers. The
//! content id is the final tiebreak, which makes the order total: two distinct
//! directives can share a date, a priority and a lamport, but never a content id
//! (that is the DAG's identity).
//!
//! ## Querying
//!
//! "Is account A open at date D" is a FOLD, not a stored flag: take the events
//! of A whose key is below D's position in canonical order and let the last one
//! decide — `open` ⇒ open, `close` ⇒ closed, no event ⇒ not open.
//!
//! D's position uses the §3.3.2 type priority of a `transaction` (4), which is
//! what preserves the pre-existing I3 boundary semantics exactly:
//!
//! * an `open` (priority 0) dated D sorts BEFORE a transaction dated D, so a
//!   same-day open admits the transaction;
//! * a `close` (priority 9) dated D sorts AFTER it, so a same-day close does
//!   not block the transaction — only a `close` dated strictly earlier does.
//!
//! [`AccountState::is_open`] is the same fold with no upper bound: the account's
//! last lifecycle event overall decides. That is the "currently open" question
//! the local write guards ask, and it is what the old `close_date.is_none()`
//! flag computed for every order the old code could actually build.

use std::collections::{BTreeMap, HashMap};

use chrono::NaiveDate;

use crate::hash::compute_content_id;
use crate::model::{Close, Directive, Metadata, Open};
use crate::validate::ValidationError;

/// The §3.3.2 canonical type priority of a `transaction`.
///
/// Lifecycle events sort against this to decide whether they are in force for a
/// transaction on the same date: `open` is 0 (before), `close` is 9 (after).
/// `lifecycle_priorities_bracket_transactions` pins the relationship.
const TRANSACTION_PRIORITY: u8 = 4;

/// The envelope key carrying a directive's Lamport clock (§3.3.1).
const ENVELOPE_KEY_LAMPORT: &str = "openledger-lamport";

/// Deterministic position of one lifecycle event in the canonical total order.
///
/// Field order IS the comparison order (derived `Ord`): date, then §3.3.2 type
/// priority, then Lamport clock, then content id.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct LifecycleKey {
    date: NaiveDate,
    priority: u8,
    lamport: u64,
    content_id: String,
}

impl LifecycleKey {
    /// Exclusive upper bound on the events a transaction dated `date` can see.
    ///
    /// Everything dated earlier is below it; on `date` itself, anything with a
    /// type priority at or below a transaction's (an `open`, priority 0) is
    /// below it and a `close` (priority 9) is above it.
    fn transaction_bound(date: NaiveDate) -> Self {
        LifecycleKey {
            date,
            priority: TRANSACTION_PRIORITY + 1,
            lamport: 0,
            content_id: String::new(),
        }
    }
}

/// What a lifecycle event asserts about the account from its position onward.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LifecycleEvent {
    /// `open` — with the I9 currency constraint list (empty = any currency).
    Open { currencies: Vec<String> },
    /// `close`.
    Close,
}

/// The Lamport clock stamped on a directive's envelope, or 0 when absent.
///
/// Tolerant like [`crate::model::Transaction::lamport_clock`]: a missing or
/// unparsable value is 0, never an error. A hand-written file legitimately
/// carries opens with no envelope at all.
fn envelope_lamport(metadata: &Metadata) -> u64 {
    metadata
        .get(ENVELOPE_KEY_LAMPORT)
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Tracks the open/close state and currency constraints for all accounts.
///
/// See the module docs: this is a per-account SET of lifecycle events folded on
/// demand, not a mutable per-account flag.
#[derive(Debug, Clone, Default)]
pub struct AccountState {
    /// `account → (deterministic key → event)`.
    events: HashMap<String, BTreeMap<LifecycleKey, LifecycleEvent>>,
}

impl AccountState {
    pub fn new() -> Self {
        Self::default()
    }

    // ── Recording events (the ingest paths) ──────────────────────────────

    /// Record the lifecycle event a directive carries, if it is one.
    ///
    /// `content_id` must be the directive's DAG content id — the caller already
    /// has it, and it is what makes the event's position identical on every
    /// replica. Non-lifecycle directives are ignored.
    ///
    /// Recording is pure data entry: it never rejects. Whether a directive is
    /// ALLOWED into the ledger is the caller's decision (the local write guards
    /// in `service.rs`, and M-09's backdated-remote-close guard); once it is in
    /// the DAG, its lifecycle event belongs in this set, because the state must
    /// be a pure function of the stored directive set — a node that boots from
    /// the file and a node that ingested the same directives one by one have to
    /// agree.
    pub fn record_lifecycle(&mut self, directive: &Directive, content_id: &str) {
        match directive {
            Directive::Open(open) => self.record_open(open, content_id),
            Directive::Close(close) => self.record_close(close, content_id),
            _ => {}
        }
    }

    /// Record an `open` directive's event. See [`Self::record_lifecycle`].
    pub fn record_open(&mut self, open: &Open, content_id: &str) {
        self.insert_event(
            &open.account,
            LifecycleKey {
                date: open.date,
                priority: Directive::Open(open.clone()).type_priority(),
                lamport: envelope_lamport(&open.metadata),
                content_id: content_id.to_owned(),
            },
            LifecycleEvent::Open {
                currencies: open.currencies.clone(),
            },
        );
    }

    /// Record a `close` directive's event. See [`Self::record_lifecycle`].
    pub fn record_close(&mut self, close: &Close, content_id: &str) {
        self.insert_event(
            &close.account,
            LifecycleKey {
                date: close.date,
                priority: Directive::Close(close.clone()).type_priority(),
                lamport: envelope_lamport(&close.metadata),
                content_id: content_id.to_owned(),
            },
            LifecycleEvent::Close,
        );
    }

    fn insert_event(&mut self, account: &str, key: LifecycleKey, event: LifecycleEvent) {
        self.events
            .entry(account.to_owned())
            .or_default()
            .insert(key, event);
    }

    // ── Legacy field-wise API (local callers, tests, embedders) ──────────

    /// Register an account opening. Returns an error if it is already open.
    ///
    /// Convenience entry point for callers that hold the lifecycle fields but
    /// not a directive: the event's content id is derived from the canonical
    /// `open` body and its Lamport position is 0. INGEST PATHS MUST NOT USE
    /// THIS — they hold the real directive and must call
    /// [`Self::record_lifecycle`], so that the event lands at the same position
    /// on every replica (and at the same position after a reboot, which reads
    /// the envelope back off disk).
    ///
    /// The already-open rejection, and the fact that a rejected call records
    /// nothing, are preserved from the pre-M-09 implementation.
    pub fn open_account(
        &mut self,
        account: &str,
        date: NaiveDate,
        currencies: &[String],
    ) -> Result<(), ValidationError> {
        if self.is_open(account) {
            return Err(ValidationError::AccountNotOpen {
                account: account.to_owned(),
                date,
            });
        }
        let open = Open {
            date,
            account: account.to_owned(),
            currencies: currencies.to_vec(),
            metadata: Metadata::new(),
        };
        let content_id = compute_content_id(&Directive::Open(open.clone()));
        self.record_open(&open, &content_id);
        Ok(())
    }

    /// Register an account closing. Returns an error if the account is unknown.
    ///
    /// Same contract and same caveat as [`Self::open_account`].
    pub fn close_account(&mut self, account: &str, date: NaiveDate) -> Result<(), ValidationError> {
        if !self.is_known(account) {
            return Err(ValidationError::AccountNotOpen {
                account: account.to_owned(),
                date,
            });
        }
        let close = Close {
            date,
            account: account.to_owned(),
            metadata: Metadata::new(),
        };
        let content_id = compute_content_id(&Directive::Close(close.clone()));
        self.record_close(&close, &content_id);
        Ok(())
    }

    // ── Folds ────────────────────────────────────────────────────────────

    /// The event that decides the account's state for a transaction on `date`.
    fn deciding_for_transaction(
        &self,
        account: &str,
        date: NaiveDate,
    ) -> Option<(&LifecycleKey, &LifecycleEvent)> {
        self.events
            .get(account)?
            .range(..LifecycleKey::transaction_bound(date))
            .next_back()
    }

    /// The account's last lifecycle event overall ("current" state).
    fn deciding_overall(&self, account: &str) -> Option<(&LifecycleKey, &LifecycleEvent)> {
        self.events.get(account)?.iter().next_back()
    }

    // ── Queries ──────────────────────────────────────────────────────────

    /// Check I3: account must be open at the given date.
    ///
    /// An account is valid if the last lifecycle event at or before the
    /// transaction's position in canonical order is an `open`. Equivalently,
    /// for the single-open/single-close shape the old implementation could
    /// represent:
    /// - An `open` directive exists with date ≤ transaction date.
    /// - No `close` directive exists with date **strictly before** the
    ///   transaction date. (Same-day close is allowed because close has sort
    ///   priority 9.)
    pub fn check_account_open(
        &self,
        account: &str,
        date: NaiveDate,
    ) -> Result<(), ValidationError> {
        match self.deciding_for_transaction(account, date) {
            Some((_, LifecycleEvent::Open { .. })) => Ok(()),
            Some((key, LifecycleEvent::Close)) => Err(ValidationError::AccountClosed {
                account: account.to_owned(),
                close_date: key.date,
                transaction_date: date,
            }),
            None => Err(ValidationError::AccountNotOpen {
                account: account.to_owned(),
                date,
            }),
        }
    }

    /// Check I9 against the constraint list in force on `date`.
    ///
    /// The only I9 entry point, deliberately. A date-free variant answering for
    /// the account's *latest* `open` existed alongside this one and was removed
    /// (T41): nothing on any validation path called it, and the constraint that
    /// governs a transaction is the one carried by the `open` in force at the
    /// transaction's date — the same event I3 is checked against (M-09). A
    /// caller with no date in hand would have been asking the wrong question.
    pub fn check_currency_constraint_at(
        &self,
        account: &str,
        currency: &str,
        date: NaiveDate,
    ) -> Result<(), ValidationError> {
        Self::enforce_currencies(
            account,
            currency,
            self.currencies_at(account, date).as_deref(),
        )
    }

    fn enforce_currencies(
        account: &str,
        currency: &str,
        allowed: Option<&[String]>,
    ) -> Result<(), ValidationError> {
        let Some(allowed) = allowed else {
            return Ok(());
        };
        if !allowed.is_empty() && !allowed.iter().any(|c| c == currency) {
            return Err(ValidationError::AccountCurrencyMismatch {
                account: account.to_owned(),
                currency: currency.to_owned(),
                allowed: allowed.to_vec(),
            });
        }
        Ok(())
    }

    /// Returns true if the account is known (carries any lifecycle event).
    pub fn is_known(&self, account: &str) -> bool {
        self.events.contains_key(account)
    }

    /// Returns true if the account has ever been opened.
    ///
    /// Distinct from [`Self::is_known`], which an `open`-less `close` also
    /// satisfies. This is the question the orphan drain asks: "could an `open`
    /// for this account now admit a transaction that was waiting on it?"
    pub fn has_open(&self, account: &str) -> bool {
        self.events.get(account).is_some_and(|events| {
            events
                .values()
                .any(|event| matches!(event, LifecycleEvent::Open { .. }))
        })
    }

    /// The currency constraint a transaction dated after every `open` of the
    /// account faces: the union over all of them (empty = any currency). See
    /// [`Self::currencies_at`]. `None` when the account was never opened.
    pub fn currencies(&self, account: &str) -> Option<Vec<String>> {
        let events = self.events.get(account)?;
        if !events
            .values()
            .any(|event| matches!(event, LifecycleEvent::Open { .. }))
        {
            return None;
        }
        Some(Self::union_of_open_currencies(events.values()))
    }

    /// The currency constraint in force on `date` (empty = any currency): the
    /// UNION of the lists of every `open` of the account dated no later than
    /// the transaction, and no constraint at all once one of them lists none
    /// (T91 / M-63, decision (37)).
    ///
    /// Before T91 it was the list of the latest such `open` alone. An `open` is
    /// data on the wire (M-09), so a peer's second `open` of an account —
    /// back-dated, another currency list, or two partitioned nodes opening
    /// the same account differently — replaced the constraint for every date
    /// after it, and history every replica had admitted under the first list
    /// stopped being admissible: the served-set rule (H-23) then un-served it,
    /// and everything written on top of it, at each node's next restart. With
    /// the union, an `open` can only ever admit more, so a verdict once given
    /// is never retracted by a later arrival and every replica reaches the
    /// same one in every order. A `close` never narrows the list; I3 decides
    /// whether the account is open at all.
    ///
    /// `None` when no `open` is in force then — I3 rejects such a transaction
    /// before I9 is ever consulted.
    pub fn currencies_at(&self, account: &str, date: NaiveDate) -> Option<Vec<String>> {
        let bound = LifecycleKey::transaction_bound(date);
        match self.deciding_for_transaction(account, date) {
            Some((_, LifecycleEvent::Open { .. })) => {}
            _ => return None,
        }
        let events = self.events.get(account)?;
        Some(Self::union_of_open_currencies(
            events.range(..bound).map(|(_, event)| event),
        ))
    }

    fn union_of_open_currencies<'a>(
        events: impl Iterator<Item = &'a LifecycleEvent>,
    ) -> Vec<String> {
        let mut union: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        for event in events {
            if let LifecycleEvent::Open { currencies } = event {
                if currencies.is_empty() {
                    return Vec::new();
                }
                union.extend(currencies.iter().cloned());
            }
        }
        union.into_iter().collect()
    }

    /// The transaction dates an ingested `close` would close (T91 / M-09
    /// remainder, decision (38)): the interval after the close's own date in
    /// which, with the close added to the fold, the close would be the
    /// deciding event — up to (excluding) the next `open` after it, or up to
    /// and including the date of the next `close`, or unbounded. `None` for
    /// an account with no lifecycle event. Where the account is already closed
    /// at the close's position the interval holds no transaction the DAG
    /// holds (I3 refused them), so no separate test is needed for that.
    ///
    /// A transaction held on the account and dated inside the interval is
    /// admitted today and would not be with the close; one dated after a later
    /// re-open is admitted either way, which is what the pre-T91 rule — "any
    /// held transaction dated after the close" — got wrong.
    pub fn dates_a_close_would_close(
        &self,
        close: &Close,
        content_id: &str,
    ) -> Option<(std::ops::Bound<NaiveDate>, std::ops::Bound<NaiveDate>)> {
        use std::ops::Bound;
        let key = LifecycleKey {
            date: close.date,
            priority: Directive::Close(close.clone()).type_priority(),
            lamport: envelope_lamport(&close.metadata),
            content_id: content_id.to_owned(),
        };
        let events = self.events.get(&close.account)?;
        let until = match events
            .range((Bound::Excluded(key), Bound::Unbounded))
            .next()
        {
            Some((next, LifecycleEvent::Open { .. })) => Bound::Excluded(next.date),
            Some((next, LifecycleEvent::Close)) => Bound::Included(next.date),
            None => Bound::Unbounded,
        };
        Some((Bound::Excluded(close.date), until))
    }

    /// Returns true if the account is currently open (its last lifecycle event
    /// overall is an `open`).
    pub fn is_open(&self, account: &str) -> bool {
        matches!(
            self.deciding_overall(account),
            Some((_, LifecycleEvent::Open { .. }))
        )
    }

    /// Whether the account is currently open counting only the lifecycle
    /// events whose content id is not in `exclude` (T92 / L-121): "is it open
    /// without these pending hand-typed `open`s", the question L-77 asks of
    /// operator input once the signature pass has settled what is served.
    pub fn is_open_excluding(
        &self,
        account: &str,
        exclude: &std::collections::HashSet<String>,
    ) -> bool {
        self.events.get(account).is_some_and(|events| {
            matches!(
                events
                    .iter()
                    .rev()
                    .find(|(key, _)| !exclude.contains(&key.content_id)),
                Some((_, LifecycleEvent::Open { .. }))
            )
        })
    }

    /// Returns true if the account is open for a transaction dated `date`.
    pub fn is_open_at(&self, account: &str, date: NaiveDate) -> bool {
        self.check_account_open(account, date).is_ok()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Flag, Transaction};
    use std::collections::BTreeMap;

    fn date(year: i32, month: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(year, month, day).expect("valid date")
    }

    fn open_directive(account: &str, on: NaiveDate, lamport: u64) -> Directive {
        let mut metadata = Metadata::new();
        metadata.insert(ENVELOPE_KEY_LAMPORT.to_owned(), lamport.to_string());
        Directive::Open(Open {
            date: on,
            account: account.to_owned(),
            currencies: Vec::new(),
            metadata,
        })
    }

    fn close_directive(account: &str, on: NaiveDate, lamport: u64) -> Directive {
        let mut metadata = Metadata::new();
        metadata.insert(ENVELOPE_KEY_LAMPORT.to_owned(), lamport.to_string());
        Directive::Close(Close {
            date: on,
            account: account.to_owned(),
            metadata,
        })
    }

    fn apply(state: &mut AccountState, directives: &[Directive]) {
        for directive in directives {
            let content_id = compute_content_id(directive);
            state.record_lifecycle(directive, &content_id);
        }
    }

    /// Every permutation of a directive set yields the same answers.
    fn assert_permutation_invariant(directives: &[Directive], account: &str, probes: &[NaiveDate]) {
        let mut reference = AccountState::new();
        apply(&mut reference, directives);

        let mut indices: Vec<usize> = (0..directives.len()).collect();
        let mut permutations = 0usize;
        loop {
            let ordered: Vec<Directive> = indices.iter().map(|&i| directives[i].clone()).collect();
            let mut state = AccountState::new();
            apply(&mut state, &ordered);
            assert_eq!(
                state.is_open(account),
                reference.is_open(account),
                "is_open diverged for order {indices:?}"
            );
            for probe in probes {
                assert_eq!(
                    state.check_account_open(account, *probe).is_ok(),
                    reference.check_account_open(account, *probe).is_ok(),
                    "open-at-{probe} diverged for order {indices:?}"
                );
            }
            assert_eq!(
                state.currencies(account),
                reference.currencies(account),
                "currencies diverged for order {indices:?}"
            );
            permutations += 1;
            if !next_permutation(&mut indices) {
                break;
            }
        }
        assert!(permutations > 1, "the set must have several orders");
    }

    /// In-place next lexicographic permutation; false when the last is reached.
    fn next_permutation(items: &mut [usize]) -> bool {
        if items.len() < 2 {
            return false;
        }
        let mut i = items.len() - 1;
        while i > 0 && items[i - 1] >= items[i] {
            i -= 1;
        }
        if i == 0 {
            return false;
        }
        let mut j = items.len() - 1;
        while items[j] <= items[i - 1] {
            j -= 1;
        }
        items.swap(i - 1, j);
        items[i..].reverse();
        true
    }

    #[test]
    fn lifecycle_priorities_bracket_transactions() {
        // The whole same-day boundary rule rests on this ordering.
        let open = open_directive("Assets:Cash", date(2024, 1, 1), 1);
        let close = close_directive("Assets:Cash", date(2024, 1, 1), 2);
        let transaction = Directive::Transaction(Transaction {
            date: date(2024, 1, 1),
            flag: Flag::Complete,
            payee: None,
            narration: None,
            tags: Vec::new(),
            links: Vec::new(),
            postings: Vec::new(),
            metadata: BTreeMap::new(),
        });
        assert!(open.type_priority() < TRANSACTION_PRIORITY);
        assert_eq!(transaction.type_priority(), TRANSACTION_PRIORITY);
        assert!(close.type_priority() > TRANSACTION_PRIORITY);
    }

    #[test]
    fn open_then_close_is_order_insensitive() {
        let directives = vec![
            open_directive("Assets:Cash", date(2024, 1, 1), 1),
            close_directive("Assets:Cash", date(2024, 6, 1), 2),
        ];
        assert_permutation_invariant(
            &directives,
            "Assets:Cash",
            &[
                date(2023, 12, 31),
                date(2024, 1, 1),
                date(2024, 3, 1),
                date(2024, 6, 1),
                date(2024, 6, 2),
            ],
        );

        let mut state = AccountState::new();
        apply(&mut state, &directives);
        assert!(!state.is_open("Assets:Cash"));
        assert!(state.is_open_at("Assets:Cash", date(2024, 3, 1)));
        // Same-day close still admits the transaction (close priority 9).
        assert!(state.is_open_at("Assets:Cash", date(2024, 6, 1)));
        assert!(!state.is_open_at("Assets:Cash", date(2024, 6, 2)));
    }

    #[test]
    fn conflicting_open_close_pairs_are_order_insensitive() {
        let directives = vec![
            open_directive("Assets:Cash", date(2024, 1, 1), 4),
            close_directive("Assets:Cash", date(2024, 2, 1), 2),
            open_directive("Assets:Cash", date(2024, 3, 1), 7),
            close_directive("Assets:Cash", date(2024, 4, 1), 1),
        ];
        assert_permutation_invariant(
            &directives,
            "Assets:Cash",
            &[
                date(2024, 1, 15),
                date(2024, 2, 15),
                date(2024, 3, 15),
                date(2024, 4, 15),
            ],
        );

        let mut state = AccountState::new();
        apply(&mut state, &directives);
        assert!(state.is_open_at("Assets:Cash", date(2024, 1, 15)));
        assert!(!state.is_open_at("Assets:Cash", date(2024, 2, 15)));
        assert!(state.is_open_at("Assets:Cash", date(2024, 3, 15)));
        assert!(!state.is_open_at("Assets:Cash", date(2024, 4, 15)));
        assert!(!state.is_open("Assets:Cash"));
    }

    #[test]
    fn backdated_close_does_not_close_a_later_open() {
        // The M-09 write-DoS shape at the state level: a 1970 close cannot
        // retroactively shut an account opened in 2024.
        let directives = vec![
            open_directive("Assets:Cash", date(2024, 1, 1), 9),
            close_directive("Assets:Cash", date(1970, 1, 1), 1),
        ];
        assert_permutation_invariant(
            &directives,
            "Assets:Cash",
            &[date(1970, 6, 1), date(2024, 6, 1)],
        );

        let mut state = AccountState::new();
        apply(&mut state, &directives);
        assert!(
            state.is_open("Assets:Cash"),
            "a backdated close must not close a later open"
        );
        assert!(state.is_open_at("Assets:Cash", date(2024, 6, 1)));
    }

    #[test]
    fn close_before_any_open_is_recorded_not_dropped() {
        // A close that arrives first must still land in the set — dropping it
        // would make the state depend on arrival order again.
        let close = close_directive("Assets:Cash", date(2024, 6, 1), 1);
        let open = open_directive("Assets:Cash", date(2024, 1, 1), 2);

        let mut close_first = AccountState::new();
        apply(&mut close_first, &[close.clone(), open.clone()]);
        let mut open_first = AccountState::new();
        apply(&mut open_first, &[open, close]);

        assert!(!close_first.is_open("Assets:Cash"));
        assert_eq!(
            close_first.is_open("Assets:Cash"),
            open_first.is_open("Assets:Cash")
        );
        assert!(close_first.is_open_at("Assets:Cash", date(2024, 3, 1)));
        assert!(!close_first.is_open_at("Assets:Cash", date(2024, 6, 2)));
    }

    #[test]
    fn currencies_follow_the_open_in_force() {
        let mut state = AccountState::new();
        let early = Directive::Open(Open {
            date: date(2024, 1, 1),
            account: "Assets:Cash".to_owned(),
            currencies: vec!["USD".to_owned()],
            metadata: Metadata::new(),
        });
        let late = Directive::Open(Open {
            date: date(2024, 6, 1),
            account: "Assets:Cash".to_owned(),
            currencies: vec!["EUR".to_owned()],
            metadata: Metadata::new(),
        });
        apply(&mut state, &[late, early]);

        assert_eq!(
            state.currencies_at("Assets:Cash", date(2024, 3, 1)),
            Some(vec!["USD".to_owned()])
        );
        // T91 / M-63, decision (37): from the second `open` on, the union —
        // a later `open` admits more, it never takes USD away.
        assert_eq!(
            state.currencies_at("Assets:Cash", date(2024, 9, 1)),
            Some(vec!["EUR".to_owned(), "USD".to_owned()])
        );
        assert!(state
            .check_currency_constraint_at("Assets:Cash", "USD", date(2024, 3, 1))
            .is_ok());
        assert!(state
            .check_currency_constraint_at("Assets:Cash", "EUR", date(2024, 3, 1))
            .is_err());
        assert!(state
            .check_currency_constraint_at("Assets:Cash", "USD", date(2024, 9, 1))
            .is_ok());
        // The date-free form answers for a transaction after every open.
        assert_eq!(
            state.currencies("Assets:Cash"),
            Some(vec!["EUR".to_owned(), "USD".to_owned()])
        );
    }

    #[test]
    fn unknown_account_is_not_open() {
        let state = AccountState::new();
        assert!(!state.is_known("Assets:Cash"));
        assert!(!state.has_open("Assets:Cash"));
        assert_eq!(
            state
                .check_account_open("Assets:Cash", date(2024, 1, 1))
                .unwrap_err()
                .error_code(),
            "ACCOUNT_NOT_OPEN"
        );
    }

    #[test]
    fn has_open_distinguishes_a_bare_close() {
        let mut state = AccountState::new();
        apply(
            &mut state,
            &[close_directive("Assets:Cash", date(2024, 1, 1), 1)],
        );
        assert!(state.is_known("Assets:Cash"));
        assert!(!state.has_open("Assets:Cash"));
    }

    #[test]
    fn same_directive_recorded_twice_is_one_event() {
        let open = open_directive("Assets:Cash", date(2024, 1, 1), 1);
        let mut once = AccountState::new();
        apply(&mut once, std::slice::from_ref(&open));
        let mut twice = AccountState::new();
        apply(&mut twice, &[open.clone(), open]);
        assert_eq!(
            once.is_open("Assets:Cash"),
            twice.is_open("Assets:Cash"),
            "recording is idempotent"
        );
        assert_eq!(
            twice.events.get("Assets:Cash").map(BTreeMap::len),
            Some(1),
            "the same directive occupies one position"
        );
    }

    #[test]
    fn lamport_breaks_same_date_ties_deterministically() {
        // Two closes and one open on the same date: the open's priority 0 puts
        // it first whatever its lamport, and the account ends closed.
        let directives = vec![
            open_directive("Assets:Cash", date(2024, 1, 1), 99),
            close_directive("Assets:Cash", date(2024, 1, 1), 1),
            close_directive("Assets:Cash", date(2024, 1, 2), 2),
        ];
        assert_permutation_invariant(
            &directives,
            "Assets:Cash",
            &[date(2024, 1, 1), date(2024, 1, 2), date(2024, 1, 3)],
        );
        let mut state = AccountState::new();
        apply(&mut state, &directives);
        assert!(!state.is_open("Assets:Cash"));
        // Same-day close does not block a same-day transaction.
        assert!(state.is_open_at("Assets:Cash", date(2024, 1, 1)));
    }

    #[test]
    fn legacy_helpers_preserve_their_rejections() {
        let mut state = AccountState::new();
        assert!(state
            .close_account("Assets:Cash", date(2024, 1, 1))
            .is_err());
        state
            .open_account("Assets:Cash", date(2024, 1, 1), &["USD".to_owned()])
            .expect("first open");
        assert!(
            state
                .open_account("Assets:Cash", date(2024, 2, 1), &[])
                .is_err(),
            "opening an already-open account still errors"
        );
        assert_eq!(
            state.currencies("Assets:Cash"),
            Some(vec!["USD".to_owned()]),
            "the rejected open recorded nothing"
        );
        state
            .close_account("Assets:Cash", date(2024, 12, 31))
            .expect("close");
        assert!(!state.is_open("Assets:Cash"));
    }
}
