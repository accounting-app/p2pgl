use async_graphql::{Context, Object};
use rust_decimal::Decimal;

use super::scalars::{DateScalar, DecimalScalar, TransactionId};
use super::types::{
    AccountBalance, Amount, BalanceAssertionFailure, BalanceAssertionReport, BalanceSheet,
    HealthStatus, IncomeStatement, Peer, Posting, Transaction, TrialBalance, TrialBalanceRow,
    VerifyResult,
};
use super::SharedLedger;

/// Maximum `journal` page size accepted from GraphQL (H-2).
const MAX_JOURNAL_LIMIT: i32 = 10_000;

use super::{GRAPHQL_MAX_COMPLEXITY, HEAVY_RESOLVER_COMPLEXITY};

/// Ledger passes a single request may buy through `verify` (M-23).
///
/// `verify` is the most expensive field in the schema by a wide margin, so it
/// is rationed directly rather than sharing the flat heavy-resolver weight.
pub(crate) const MAX_VERIFY_PER_REQUEST: usize = 2;

/// The most quarantined ids one `verify` lists (T88 / L-103); the field
/// `quarantinedTotal` carries the full count. The list is set by the file,
/// not by the caller, and a 20,000-record quarantine was 1.3 MB per `verify`.
pub(crate) const MAX_LISTED_QUARANTINED: usize = 1_000;

/// Complexity weight for `verify` (M-23).
///
/// # Why this is not `HEAVY_RESOLVER_COMPLEXITY`
///
/// `HEAVY_RESOLVER_COMPLEXITY` is denominated in *one whole-ledger scan* — its
/// comment says so, and that was true of `verify` when the weight was chosen.
/// T32 then wired balance assertions into `verify` (M-08) as one whole-ledger
/// balance rebuild **per `balance` directive**, and the weight's model broke in
/// silence: 512 against a 4096 budget kept admitting 8 `verify` calls per
/// request, except each one was now O(assertions × transactions × postings)
/// with the assertion count supplied by any peer that can plant a 250-byte
/// `balance` directive. A comment was the only thing asserting the invariant,
/// and a comment does not fail a build.
///
/// # The measurement this is sized on
///
/// With M-23's batched sweep in place `verify` is linear in the directive
/// count again, but it is *not* one scan: the per-directive content-hash
/// recomputation dominates. Measured in release against
/// `ReadModel::trial_balance` (the one-scan unit) — see
/// [`ledger::verify::verify_dag`] for the full table:
///
/// ```text
/// 20k txns +  20k balances   verify 139ms  vs one scan 4.1ms   (~34x)
/// 20k txns + 100k balances   verify 396ms  vs one scan 3.4ms   (~116x)
/// ```
///
/// So `verify` is worth tens of heavy resolvers, not one — but the budget must
/// still admit at least one of them, and a request that asks for `verify`
/// alongside a dashboard's reports is legitimate. The weight is therefore set
/// by rationing the budget rather than by the raw ratio: at
/// [`MAX_VERIFY_PER_REQUEST`] the worst case a single request can buy is two
/// linear passes (~0.8 s at the 120k-directive shape above), instead of eight
/// quadratic ones with no bound at all.
///
/// The premise underneath — that the pass is linear and cannot be multiplied
/// by a planted assertion count — is pinned by
/// [`tests::test_verify_complexity_matches_measured_cost_model`], not by this
/// comment.
pub(crate) const VERIFY_COMPLEXITY: usize = GRAPHQL_MAX_COMPLEXITY / MAX_VERIFY_PER_REQUEST;

/// GraphQL query root. Resolvers pull from `SharedLedger` when available,
/// fall back to empty defaults for introspection-only schemas.
pub struct QueryRoot;

#[Object]
impl QueryRoot {
    /// Trial balance at a given date (FR-2 AC1).
    #[graphql(complexity = "HEAVY_RESOLVER_COMPLEXITY")]
    async fn trial_balance(
        &self,
        ctx: &Context<'_>,
        at: DateScalar,
    ) -> async_graphql::Result<TrialBalance> {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            let svc = ledger.read().await;
            let report = svc
                .read_model()
                .try_trial_balance(at.0)
                .map_err(|error| out_of_range_error("trialBalance", error))?;
            Ok(TrialBalance {
                at,
                rows: report
                    .rows
                    .iter()
                    .map(|r| TrialBalanceRow {
                        account: r.account.clone(),
                        debit: DecimalScalar(r.debit),
                        credit: DecimalScalar(r.credit),
                        exact: r.exact,
                    })
                    .collect(),
                total_debit: DecimalScalar(report.total_debit),
                total_credit: DecimalScalar(report.total_credit),
                exact: report.exact,
            })
        } else {
            Ok(TrialBalance {
                at,
                rows: Vec::new(),
                total_debit: DecimalScalar(Decimal::ZERO),
                total_credit: DecimalScalar(Decimal::ZERO),
                exact: true,
            })
        }
    }

    /// Balance sheet at a given date (FR-2 AC2).
    #[graphql(complexity = "HEAVY_RESOLVER_COMPLEXITY")]
    async fn balance_sheet(
        &self,
        ctx: &Context<'_>,
        at: DateScalar,
    ) -> async_graphql::Result<BalanceSheet> {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            let svc = ledger.read().await;
            let report = svc
                .read_model()
                .try_balance_sheet(at.0)
                .map_err(|error| out_of_range_error("balanceSheet", error))?;
            Ok(BalanceSheet {
                at,
                assets: account_balances_to_graphql(&report.assets),
                liabilities: account_balances_to_graphql(&report.liabilities),
                equity: account_balances_to_graphql(&report.equity),
                exact: report.exact,
            })
        } else {
            Ok(BalanceSheet {
                at,
                assets: Vec::new(),
                liabilities: Vec::new(),
                equity: Vec::new(),
                exact: true,
            })
        }
    }

    /// Income statement for a date range (FR-2 AC3).
    #[graphql(complexity = "HEAVY_RESOLVER_COMPLEXITY")]
    async fn income_statement(
        &self,
        ctx: &Context<'_>,
        from: DateScalar,
        to: DateScalar,
    ) -> async_graphql::Result<IncomeStatement> {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            let svc = ledger.read().await;
            let report = svc
                .read_model()
                .try_income_statement(from.0, to.0)
                .map_err(|error| out_of_range_error("incomeStatement", error))?;
            Ok(IncomeStatement {
                from,
                to,
                income: account_balances_to_graphql(&report.income),
                expenses: account_balances_to_graphql(&report.expenses),
                net: amounts_to_graphql(&report.net),
                exact: report.exact,
            })
        } else {
            Ok(IncomeStatement {
                from,
                to,
                income: Vec::new(),
                expenses: Vec::new(),
                net: Vec::new(),
                exact: true,
            })
        }
    }

    /// Journal of transactions, optionally filtered (FR-2 AC4).
    ///
    /// Weighted by the page it returns, not as one flat scan (M-45); see
    /// [`journal_complexity`].
    #[graphql(complexity = "journal_complexity(limit, child_complexity)")]
    async fn journal(
        &self,
        ctx: &Context<'_>,
        account: Option<String>,
        from: Option<DateScalar>,
        to: Option<DateScalar>,
        #[graphql(default = 100)] limit: i32,
        #[graphql(default = 0)] offset: i32,
    ) -> Vec<Transaction> {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            // M-45: postings are the bulk of a row (up to 1,000 each), so they
            // are materialized only when the query selects them. The weight
            // charges them only when selected, and this keeps the two in step.
            let with_postings = ctx.look_ahead().field("postings").exists();
            let svc = ledger.read().await;
            let entries = svc.read_model().journal(
                account.as_deref(),
                from.map(|d| d.0),
                to.map(|d| d.0),
                clamp_journal_limit(limit),
                clamp_journal_offset(offset),
            );
            // M-45: the read model already holds each row's content id; the
            // old path cloned the whole transaction and re-hashed it per row.
            entries
                .into_iter()
                .map(|entry| txn_to_graphql(&entry.transaction, entry.txid.clone(), with_postings))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Look up a single transaction by its content hash.
    async fn transaction(&self, ctx: &Context<'_>, txid: TransactionId) -> Option<Transaction> {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            let svc = ledger.read().await;
            // The DAG is keyed by content id, so the id that found the
            // directive IS its content id — no need to re-hash it (M-45).
            if let Some(ledger::model::Directive::Transaction(txn)) = svc.get_directive(&txid.0) {
                return Some(txn_to_graphql(txn, txid.0, true));
            }
        }
        None
    }

    /// Look up an account's balances.
    ///
    /// With `at` set this replays every transaction (`balances_at`) — a full
    /// ledger scan — so it carries the heavy weight in that form only; the
    /// current-balance lookup stays cheap for legitimate multi-account batches.
    #[graphql(
        complexity = "if at.is_some() { HEAVY_RESOLVER_COMPLEXITY } else { 1 + child_complexity }"
    )]
    async fn account(
        &self,
        ctx: &Context<'_>,
        name: String,
        at: Option<DateScalar>,
    ) -> async_graphql::Result<Option<AccountBalance>> {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            let svc = ledger.read().await;
            let entry = svc
                .read_model()
                .try_account_balance(&name, at.map(|d| d.0))
                .map_err(|error| out_of_range_error("account", error))?;
            return Ok(entry.as_ref().map(account_balance_to_graphql));
        }
        Ok(None)
    }

    /// Everyone who has access to this mesh's API, by user id: name, role and
    /// expiry (`docs/build-log/002-users-and-roles`) — never a key or its hash.
    /// Admin only.
    async fn access_list(
        &self,
        ctx: &Context<'_>,
    ) -> async_graphql::Result<Vec<super::access::PersonAccess>> {
        super::access::access_list(ctx).await
    }

    /// Verify DAG integrity and balance assertions (FR-5 AC1, §3.6).
    ///
    /// `ok`/`errors` cover the structural checks — content hashes (I5), parent
    /// links (I8), acyclicity. `balanceAssertions` reports every `balance`
    /// directive in the ledger evaluated against the read model (M-08): before
    /// this wiring those directives were stored and never checked, so a false
    /// claim — hand-edited or gossiped in by an allowlisted peer — read as
    /// verified. Evaluation is read-only: a failing assertion is surfaced, not
    /// used to reject or adjust anything, and it does not clear `ok`.
    ///
    /// Carries [`VERIFY_COMPLEXITY`] rather than the flat heavy-resolver weight
    /// (M-23): it hashes every directive and sweeps every posting, which is
    /// tens of ordinary ledger scans even now that it is linear again.
    #[graphql(complexity = "VERIFY_COMPLEXITY")]
    async fn verify(&self, ctx: &Context<'_>) -> VerifyResult {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            // Still computed under the read guard, deliberately (M-23, residual).
            //
            // `tokio::sync::RwLock` is write-preferring, so a long read here
            // makes writers wait. The stall is what M-23 fixed — the pass is
            // linear now, hundreds of milliseconds rather than tens of minutes
            // — but the work is still *on* the lock, and the 408 timeout drops
            // the response, not the work.
            //
            // Getting it off the lock needs a snapshot the guard can outlive,
            // and `LedgerService` hands out `&LedgerDag` / `&ReadModel` only.
            // The two ways to do it from here are both worse than the stall:
            // cloning the DAG and read model is O(ledger) allocation per call,
            // and `MAX_VERIFY_PER_REQUEST` of those concurrently is a fresh
            // memory DoS; `block_in_place` frees the worker thread but keeps
            // the lock, so writers are no better off, and it panics outright on
            // a current-thread runtime. The real fix is `LedgerService` holding
            // its DAG and read model behind `Arc` so a reader can clone the
            // handle and drop the guard — a `ledger::service` change, out of scope
            // for this task and left for the pass that owns that file.
            let svc = ledger.read().await;
            let report = ledger::verify::verify_dag(svc.dag(), svc.read_model());
            // T88 / L-103: capped like `errors`, with the full count beside it.
            let (quarantined, quarantined_total) =
                svc.quarantined_ids_capped(MAX_LISTED_QUARANTINED);
            VerifyResult {
                ok: report.ok,
                nodes_checked: report.nodes_checked as i32,
                errors: report.errors.iter().map(|e| e.to_string()).collect(),
                truncated: i32::try_from(report.truncated).unwrap_or(i32::MAX),
                balance_assertions: assertion_report(&report.assertions),
                quarantined,
                quarantined_total: i32::try_from(quarantined_total).unwrap_or(i32::MAX),
                unparsable_blocks: i32::try_from(svc.unparsable_block_count()).unwrap_or(i32::MAX),
            }
        } else {
            VerifyResult {
                ok: true,
                nodes_checked: 0,
                errors: Vec::new(),
                truncated: 0,
                balance_assertions: assertion_report(&Default::default()),
                quarantined: Vec::new(),
                quarantined_total: 0,
                unparsable_blocks: 0,
            }
        }
    }

    /// Node health status (§2.9 / FR-6 AC1).
    async fn health(&self, ctx: &Context<'_>) -> HealthStatus {
        let heads = if let Ok(ledger) = ctx.data::<SharedLedger>() {
            let svc = ledger.read().await;
            svc.head_count() as i32
        } else {
            0
        };
        let peer_count = if let Ok(registry) = ctx.data::<p2p::node::PeerRegistry>() {
            registry.count() as i32
        } else {
            0
        };
        HealthStatus {
            status: "ok".to_owned(),
            heads,
            peers: peer_count,
            version: env!("CARGO_PKG_VERSION").to_owned(),
        }
    }

    /// Currently-connected peers (FR-6 AC2).
    ///
    /// Membership only: the per-peer `heads` list this used to return was
    /// always empty (see [`Peer`]).
    async fn peers(&self, ctx: &Context<'_>) -> Vec<Peer> {
        if let Ok(registry) = ctx.data::<p2p::node::PeerRegistry>() {
            registry
                .list()
                .into_iter()
                .map(|peer| Peer { id: peer.id })
                .collect()
        } else {
            Vec::new()
        }
    }
}

/// The error a report resolver returns for a figure no `Decimal` can hold
/// (T76). Unreachable while every summed amount is inside the amount cap —
/// every total then fits at scale 0 — so it is logged loudly and surfaced as
/// a generic internal error rather than a client-facing code.
fn out_of_range_error(
    resolver: &'static str,
    error: ledger::read_model::OutOfRange,
) -> async_graphql::Error {
    tracing::error!(
        resolver,
        %error,
        "a report figure is out of range for any Decimal; this should be unreachable \
         inside the amount cap (T76)"
    );
    async_graphql::Error::new("internal error")
}

/// A currency → figure map as GraphQL amounts.
fn amounts_to_graphql(balances: &ledger::read_model::CurrencyBalances) -> Vec<Amount> {
    balances
        .iter()
        .map(|(currency, amount)| Amount {
            number: DecimalScalar(*amount),
            currency: currency.clone(),
        })
        .collect()
}

/// One account's balances as their GraphQL shape.
fn account_balance_to_graphql(entry: &ledger::read_model::AccountBalanceEntry) -> AccountBalance {
    AccountBalance {
        account: entry.account.clone(),
        balances: amounts_to_graphql(&entry.balances),
        exact: entry.exact,
    }
}

fn account_balances_to_graphql(
    entries: &[ledger::read_model::AccountBalanceEntry],
) -> Vec<AccountBalance> {
    entries.iter().map(account_balance_to_graphql).collect()
}

/// Convert the ledger's balance-assertion summary to its GraphQL shape (M-08).
///
/// Only the failures carry per-assertion detail; the counts cover the rest, so
/// a client can alert on `failed` without pulling the whole list.
fn assertion_report(summary: &ledger::verify::BalanceAssertionSummary) -> BalanceAssertionReport {
    BalanceAssertionReport {
        evaluated: summary.evaluated as i32,
        passed: summary.passed() as i32,
        failed: summary.failures.len() as i32,
        ok: summary.ok(),
        failures: summary
            .failures
            .iter()
            .map(|failure| BalanceAssertionFailure {
                account: failure.account.clone(),
                date: DateScalar(failure.date),
                expected: DecimalScalar(failure.expected),
                actual: DecimalScalar(failure.actual),
                actual_exact: failure.actual_exact,
                currency: failure.currency.clone(),
            })
            .collect(),
    }
}

/// Convert a domain Transaction whose content id the caller already holds
/// (M-45).
///
/// `txid` must be `txn`'s content id — the read model's `IndexedTransaction`
/// and the DAG's key both are. With `with_postings` false the `postings` list
/// is left empty: pass it only when the query does not select the field.
pub fn txn_to_graphql(
    txn: &ledger::model::Transaction,
    txid: String,
    with_postings: bool,
) -> Transaction {
    Transaction {
        txid: TransactionId(txid),
        date: DateScalar(txn.date),
        flag: match txn.flag {
            ledger::model::Flag::Complete => "*".to_owned(),
            ledger::model::Flag::Incomplete => "!".to_owned(),
        },
        payee: txn.payee.clone(),
        narration: txn.narration.clone(),
        tags: txn.tags.clone(),
        links: txn.links.clone(),
        postings: if with_postings {
            txn.postings.iter().map(posting_to_graphql).collect()
        } else {
            Vec::new()
        },
        author: txn
            .metadata
            .get("openledger-author")
            .cloned()
            .unwrap_or_default(),
        signature: txn.metadata.get("openledger-signature").cloned(),
        parents: txn
            .metadata
            .get("openledger-parents")
            .map(|p| {
                if p.is_empty() {
                    vec![]
                } else {
                    p.split(',')
                        .map(|s| TransactionId(s.trim().to_owned()))
                        .collect()
                }
            })
            .unwrap_or_default(),
    }
}

/// Convert one domain posting to its GraphQL shape.
fn posting_to_graphql(p: &ledger::model::Posting) -> Posting {
    let amt = p.amount.as_ref().map(|a| Amount {
        number: DecimalScalar(a.number),
        currency: a.currency.clone(),
    });
    Posting {
        account: p.account.clone(),
        amount: amt.unwrap_or(Amount {
            number: DecimalScalar(Decimal::ZERO),
            currency: String::new(),
        }),
        cost: p.cost.as_ref().and_then(|c| {
            c.amount.as_ref().map(|a| Amount {
                number: DecimalScalar(a.number),
                currency: a.currency.clone(),
            })
        }),
        price: p.price.as_ref().map(|pr| match pr {
            ledger::model::PriceSpec::Unit(a) | ledger::model::PriceSpec::Total(a) => Amount {
                number: DecimalScalar(a.number),
                currency: a.currency.clone(),
            },
        }),
    }
}

/// Rows per unit of `journal` weight (M-45).
const JOURNAL_ROWS_PER_WEIGHT_UNIT: usize = 100;

/// The `journal` field's complexity weight (M-45).
///
/// It used to be a flat [`HEAVY_RESOLVER_COMPLEXITY`], whatever the `limit`
/// and whatever the selection — so eight aliased `journal(limit: 10000)
/// { postings { … } }` cost exactly the 4096 budget and were admitted, every
/// alias resolving concurrently: against ~3,600 planted 1,000-posting
/// transactions, ~3.6M posting objects (~1.8 GB) per alias. Now it is
///
/// ```text
/// max(HEAVY_RESOLVER_COMPLEXITY, (limit / 100).max(1) × (1 + child_complexity))
/// ```
///
/// * The product charges the page: each hundred rows costs what one row's
///   selection costs. With the finding's selection (`postings { account
///   amount { number currency } }`, child complexity 5) a 10,000-row page
///   weighs 600 as measured on the real schema, so at most six such aliases
///   fit — seven or eight are refused. A whole-row selection (every scalar
///   plus postings with cost and price) weighs 2,200: one full page per
///   request.
/// * The [`HEAVY_RESOLVER_COMPLEXITY`] floor is the scan: the read model
///   filters EVERY transaction before it applies `limit`/`offset`, so even a
///   one-row page is one whole-ledger pass, and a small selection must never
///   make `journal` cheaper than it was — without the floor, twenty
///   `journal(limit: 10000) { txid }` would have fit where eight did before.
///
/// A dashboard page (`limit` ≤ a few hundred, any selection) stays at the
/// floor, so the documented "one of every report in a dashboard call" still
/// fits; pinned by the tests below against the real schema.
fn journal_complexity(limit: i32, child_complexity: usize) -> usize {
    let hundreds = (clamp_journal_limit(limit) / JOURNAL_ROWS_PER_WEIGHT_UNIT).max(1);
    HEAVY_RESOLVER_COMPLEXITY.max(hundreds.saturating_mul(child_complexity.saturating_add(1)))
}

/// Clamp GraphQL `limit` to `[0, MAX_JOURNAL_LIMIT]` before the `i32 as usize` cast.
fn clamp_journal_limit(limit: i32) -> usize {
    limit.clamp(0, MAX_JOURNAL_LIMIT) as usize
}

/// Clamp GraphQL `offset` to a non-negative `usize`.
fn clamp_journal_offset(offset: i32) -> usize {
    offset.max(0) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graphql::ExecuteAsOperator;

    #[test]
    fn test_clamp_journal_limit_default_range() {
        assert_eq!(clamp_journal_limit(100), 100);
        assert_eq!(clamp_journal_limit(0), 0);
        assert_eq!(clamp_journal_limit(MAX_JOURNAL_LIMIT), 10_000);
    }

    #[test]
    fn test_clamp_journal_limit_rejects_negative_and_huge() {
        assert_eq!(clamp_journal_limit(-1), 0);
        assert_eq!(clamp_journal_limit(i32::MIN), 0);
        assert_eq!(clamp_journal_limit(50_000), 10_000);
    }

    #[test]
    fn test_clamp_journal_offset_rejects_negative() {
        assert_eq!(clamp_journal_offset(0), 0);
        assert_eq!(clamp_journal_offset(25), 25);
        assert_eq!(clamp_journal_offset(-1), 0);
        assert_eq!(clamp_journal_offset(i32::MIN), 0);
    }

    // ── M-23: the `verify` complexity weight ─────────────────────────────

    /// M-23: the weight is pinned to the cost model it was derived from, so
    /// re-breaking the model fails a test rather than a comment.
    ///
    /// This is the whole point of the finding. The previous weight was
    /// justified by prose ("scan the ledger once") that T32 silently
    /// invalidated; nothing failed, and `verify` kept its one-scan weight while
    /// running O(assertions × transactions × postings). So the three things the
    /// weight rests on are asserted here:
    ///
    /// 1. the arithmetic — the weight *is* the budget divided by the rationed
    ///    call count, not an independently chosen number that can drift from
    ///    [`GRAPHQL_MAX_COMPLEXITY`];
    /// 2. the ordering — `verify` is weighted strictly above a one-scan
    ///    resolver, which is what the 34x–116x measurement says;
    /// 3. the **premise** — that the assertion pass is one ledger walk whose
    ///    cost a planted assertion count cannot multiply. If that regresses,
    ///    the pass is quadratic again and every number above is wrong.
    #[test]
    fn test_verify_complexity_matches_measured_cost_model() {
        // (1) The weight is the ration, not a magic number, and (2) `verify`
        // outweighs a one-scan resolver — it hashes every directive on top of
        // sweeping every posting. Both are `const`, so re-breaking them fails
        // the build and not merely this test.
        const {
            assert!(
                VERIFY_COMPLEXITY == GRAPHQL_MAX_COMPLEXITY / MAX_VERIFY_PER_REQUEST,
                "VERIFY_COMPLEXITY must stay derived from the budget it rations"
            );
            assert!(
                VERIFY_COMPLEXITY * MAX_VERIFY_PER_REQUEST <= GRAPHQL_MAX_COMPLEXITY,
                "the budget must actually admit MAX_VERIFY_PER_REQUEST verify calls"
            );
            assert!(
                VERIFY_COMPLEXITY * (MAX_VERIFY_PER_REQUEST + 1) > GRAPHQL_MAX_COMPLEXITY,
                "the budget must not admit more than MAX_VERIFY_PER_REQUEST verify calls"
            );
            assert!(
                VERIFY_COMPLEXITY >= 4 * HEAVY_RESOLVER_COMPLEXITY,
                "verify measured at ~34x-116x one ledger scan; it must not share \
                 the flat one-scan weight again (M-23)"
            );
        }

        // (3) The premise: one ledger walk, not one per assertion.
        //
        // A peer plants `balance` directives to supply the multiplier, so the
        // check holds the ledger fixed and varies only the number of
        // (account, date) pairs asked about — including 50,000 on an account
        // that does not exist, which is the cheapest thing to plant.
        let mut bean = String::from("2024-01-01 open Assets:Cash USD\n");
        bean.push_str("2024-01-01 open Equity:Opening USD\n");
        for i in 0..500 {
            bean.push_str(&format!(
                "2024-01-{:02} * \"txn {i}\"\n  Assets:Cash 1 USD\n  Equity:Opening -1 USD\n",
                i % 28 + 1
            ));
        }
        let directives = ledger::parse::parse_file(&bean).expect("fixture parses");
        let model = ledger::read_model::ReadModel::build(&directives);
        let at = chrono::NaiveDate::from_ymd_opt(2024, 1, 28).unwrap();

        let honest = [("Assets:Cash", at)];
        let planted: Vec<(&str, chrono::NaiveDate)> =
            std::iter::repeat_n(("Assets:Planted", at), 50_000).collect();

        let honest_cost = model.balances_at_dates(&honest).postings_visited;
        let planted_cost = model.balances_at_dates(&planted).postings_visited;

        assert_eq!(honest_cost, 1000, "500 transactions x 2 postings, one walk");
        assert_eq!(
            planted_cost, honest_cost,
            "50,000 planted assertions multiplied the ledger walk — `verify` is \
             quadratic again and VERIFY_COMPLEXITY no longer describes it (M-23)"
        );
    }

    /// M-23: the budget admits exactly [`MAX_VERIFY_PER_REQUEST`] `verify`
    /// calls, enforced before execution.
    ///
    /// The arithmetic above is necessary but not sufficient — async-graphql has
    /// to agree, and a future field-level change (children counted, a different
    /// attribute form) could quietly re-open alias batching without changing
    /// any constant.
    #[tokio::test]
    async fn test_verify_complexity_rations_calls_per_request() {
        async fn aliased_verify_count(n: usize) -> Vec<async_graphql::ServerError> {
            let schema = crate::graphql::build_schema();
            let mut query = String::from("{");
            for i in 0..n {
                query.push_str(&format!(" a{i}: verify {{ ok }}"));
            }
            query.push('}');
            schema.execute_as_operator(query).await.errors
        }

        let admitted = aliased_verify_count(MAX_VERIFY_PER_REQUEST).await;
        assert!(
            admitted.is_empty(),
            "{MAX_VERIFY_PER_REQUEST} verify calls must be admitted, got: {admitted:?}"
        );

        let rejected = aliased_verify_count(MAX_VERIFY_PER_REQUEST + 1).await;
        assert!(
            rejected
                .iter()
                .any(|e| e.message.to_lowercase().contains("complex")),
            "{} verify calls must be rejected on complexity, got: {rejected:?}",
            MAX_VERIFY_PER_REQUEST + 1
        );
    }

    /// M-23: re-weighting `verify` must not lock out a legitimate dashboard.
    ///
    /// `HEAVY_RESOLVER_COMPLEXITY`'s stated intent is that the budget leaves
    /// "room for one of every report in a dashboard call". Raising `verify`
    /// from 512 to `VERIFY_COMPLEXITY` spends that room, so the claim is
    /// checked rather than assumed: one `verify` plus one of each report is
    /// exactly the budget, and still passes.
    #[tokio::test]
    async fn test_verify_weight_still_admits_a_full_dashboard_call() {
        let schema = crate::graphql::build_schema();
        let result = schema
            .execute_as_operator(
                r#"{
                    verify { ok }
                    trialBalance(at: "2024-12-31") { totalDebit }
                    balanceSheet(at: "2024-12-31") { assets { account } }
                    incomeStatement(from: "2024-01-01", to: "2024-12-31") { net { currency } }
                    journal(limit: 10) { txid }
                }"#,
            )
            .await;
        assert!(
            result.errors.is_empty(),
            "a dashboard call (verify + one of each report) must stay within the \
             {GRAPHQL_MAX_COMPLEXITY} budget: {:?}",
            result.errors
        );
    }

    // ── M-45: `journal` is weighted by its page and selection ────────────

    /// The finding's selection: every posting with its amount.
    const POSTINGS_SELECTION: &str = "postings { account amount { number currency } }";

    /// The complexity async-graphql computes for `query` against the real
    /// schema (its `Analyzer` extension), or `None` if the query was refused.
    async fn measured_complexity(query: &str) -> Option<u64> {
        let schema = super::super::schema_builder(true)
            .extension(async_graphql::extensions::Analyzer)
            .finish();
        let response = schema.execute_as_operator(query).await;
        if !response.errors.is_empty() {
            return None;
        }
        let analyzer = response.extensions.get("analyzer")?;
        match analyzer.clone().into_json().ok()?.get("complexity")? {
            serde_json::Value::Number(number) => number.as_u64(),
            _ => None,
        }
    }

    async fn aliased(count: usize, field: &str) -> Vec<async_graphql::ServerError> {
        let mut query = String::from("{");
        for index in 0..count {
            query.push_str(&format!(" a{index}: {field}"));
        }
        query.push('}');
        crate::graphql::build_schema()
            .execute_as_operator(query)
            .await
            .errors
    }

    fn refused_on_complexity(errors: &[async_graphql::ServerError]) -> bool {
        errors
            .iter()
            .any(|error| error.message.to_lowercase().contains("complex"))
    }

    /// M-45 regression: eight aliased 10,000-row pages WITH postings were
    /// exactly the 4096 budget and admitted — ~14 GB of posting values per
    /// request against planted 1,000-posting transactions. Refused now, with
    /// the weights pinned as measured by the real schema.
    #[tokio::test]
    async fn m45_eight_aliased_full_journal_pages_with_postings_are_refused() {
        let page = format!("journal(limit: 10000) {{ {POSTINGS_SELECTION} }}");
        let weight = measured_complexity(&format!("{{ {page} }}"))
            .await
            .expect("one full page with postings is admitted");
        assert_eq!(
            weight,
            (MAX_JOURNAL_LIMIT as u64 / 100) * (1 + 5),
            "10,000 rows × (1 + postings {{ account amount {{ number currency }} }} = 5)"
        );
        assert!(8 * weight > GRAPHQL_MAX_COMPLEXITY as u64);

        let refused = aliased(8, &page).await;
        assert!(
            refused_on_complexity(&refused),
            "eight aliased journal(limit: 10000) with postings must be refused \
             on complexity (M-45), got: {refused:?}"
        );
    }

    /// M-45: the page weight must not undercut the scan it replaced. The read
    /// model filters every transaction before `limit`, so each `journal` is at
    /// least one whole-ledger pass — a tiny selection keeps the old weight
    /// and the old cap of eight per request.
    #[tokio::test]
    async fn m45_small_selection_keeps_the_heavy_scan_floor() {
        let tiny = "journal(limit: 10000) { txid }";
        assert_eq!(
            measured_complexity(&format!("{{ {tiny} }}")).await,
            Some(HEAVY_RESOLVER_COMPLEXITY as u64),
            "100 × (1 + 1) = 200 is under the floor; the floor applies"
        );
        assert!(
            aliased(8, tiny).await.is_empty(),
            "eight admitted, as before"
        );
        assert!(
            refused_on_complexity(&aliased(9, tiny).await),
            "a ninth is refused, as before — the fix must not raise the cap"
        );
    }

    /// M-45: a dashboard — `verify` plus one of every report plus a normal
    /// 100-row journal page with its postings — still fits the budget.
    #[tokio::test]
    async fn m45_dashboard_journal_page_with_postings_still_fits() {
        let query = format!(
            r#"{{
                verify {{ ok }}
                trialBalance(at: "2024-12-31") {{ totalDebit }}
                balanceSheet(at: "2024-12-31") {{ assets {{ account }} }}
                incomeStatement(from: "2024-01-01", to: "2024-12-31") {{ net {{ currency }} }}
                journal(limit: 100) {{ txid date narration {POSTINGS_SELECTION} }}
            }}"#
        );
        let errors = crate::graphql::build_schema()
            .execute_as_operator(query)
            .await
            .errors;
        assert!(
            errors.is_empty(),
            "a dashboard with a 100-row journal page must fit the \
             {GRAPHQL_MAX_COMPLEXITY} budget: {errors:?}"
        );
    }

    /// M-45: the resolvers hand out the content id the read model / DAG
    /// already hold instead of re-hashing — and it IS the content id — and
    /// `journal` materializes postings only when they are selected.
    #[tokio::test]
    async fn m45_journal_and_transaction_use_the_stored_txid() {
        let dir = tempfile::tempdir().unwrap();
        let bean_path = dir.path().join("test.bean");
        std::fs::write(
            &bean_path,
            "2024-01-01 open Assets:Cash USD\n2024-01-01 open Equity:Opening USD\n\
             2024-01-02 * \"seed\"\n  Assets:Cash 10 USD\n  Equity:Opening -10 USD\n",
        )
        .unwrap();
        let service =
            ledger::service::LedgerService::boot(&bean_path, "test-node".to_owned()).unwrap();
        let expected = service
            .read_model()
            .journal(None, None, None, 10, 0)
            .first()
            .map(|entry| {
                ledger::hash::compute_content_id(&ledger::model::Directive::Transaction(
                    entry.transaction.clone(),
                ))
            })
            .expect("one transaction");
        let ledger: SharedLedger = std::sync::Arc::new(tokio::sync::RwLock::new(service));
        let schema = crate::graphql::build_schema_with_service(
            ledger,
            crate::graphql::broadcast::TransactionBroadcast::new(),
            p2p::node::PeerRegistry::new(),
            std::sync::Arc::new(security::signing::NoopSignatureProvider),
            true,
            None,
        );

        let response = schema
            .execute_as_operator(format!(
                r#"{{
                    bare: journal {{ txid }}
                    full: journal {{ txid {POSTINGS_SELECTION} }}
                    one: transaction(txid: "{expected}") {{ txid {POSTINGS_SELECTION} }}
                }}"#
            ))
            .await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        let data = response.data.into_json().unwrap();
        assert_eq!(data["bare"][0]["txid"], expected.as_str());
        assert_eq!(data["full"][0]["txid"], expected.as_str());
        assert_eq!(data["one"]["txid"], expected.as_str());
        assert_eq!(data["full"][0]["postings"].as_array().unwrap().len(), 2);
        assert_eq!(data["one"]["postings"].as_array().unwrap().len(), 2);
        assert_eq!(data["full"][0]["postings"][0]["account"], "Assets:Cash");
    }

    // ── T76: the `exact` flags ────────────────────────────────────────────

    /// T76 (L-79): `exact` is exposed on every balance-carrying type and is
    /// `false` for mixed-scale dust — `1000 + 10^-28` does not fit a
    /// `Decimal` at scale 28, so it is reported rounded once — and `true`
    /// beside it for an ordinary balance; a `balance` claim of the rounded
    /// figure fails, with `actualExact: false`.
    #[tokio::test]
    async fn t76_exact_is_exposed_and_false_for_mixed_scale_dust() {
        let dir = tempfile::tempdir().unwrap();
        let bean_path = dir.path().join("test.bean");
        std::fs::write(
            &bean_path,
            "2024-01-01 open Assets:Cash\n2024-01-01 open Assets:Bank\n\
             2024-01-01 open Income:Salary\n2024-01-01 open Equity:Opening\n\
             2024-01-02 * \"pay\"\n  Assets:Cash 1000 USD\n  Income:Salary -1000 USD\n\
             2024-01-03 * \"dust\"\n  Assets:Cash 0.0000000000000000000000000001 USD\n  \
             Income:Salary -0.0000000000000000000000000001 USD\n\
             2024-01-04 * \"plain\"\n  Assets:Bank 5.00 USD\n  Equity:Opening -5.00 USD\n\
             2024-01-05 balance Assets:Cash 1000.0000000000000000000000000 USD\n",
        )
        .unwrap();
        let service =
            ledger::service::LedgerService::boot(&bean_path, "test-node".to_owned()).unwrap();
        let ledger: SharedLedger = std::sync::Arc::new(tokio::sync::RwLock::new(service));
        let schema = crate::graphql::build_schema_with_service(
            ledger,
            crate::graphql::broadcast::TransactionBroadcast::new(),
            p2p::node::PeerRegistry::new(),
            std::sync::Arc::new(security::signing::NoopSignatureProvider),
            true,
            None,
        );
        let response = schema
            .execute_as_operator(
                r#"{
                    cash: account(name: "Assets:Cash") { balances { number } exact }
                    bank: account(name: "Assets:Bank") { balances { number } exact }
                    trialBalance(at: "2024-12-31") { exact rows { account exact } }
                    balanceSheet(at: "2024-12-31") { exact assets { account exact } }
                    incomeStatement(from: "2024-01-01", to: "2024-12-31") {
                        exact net { number }
                    }
                    verify { balanceAssertions { failed failures { actual actualExact } } }
                }"#,
            )
            .await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        let data = response.data.into_json().unwrap();
        assert_eq!(
            data["cash"]["balances"][0]["number"],
            "1000.0000000000000000000000000"
        );
        assert_eq!(data["cash"]["exact"], false);
        assert_eq!(data["bank"]["balances"][0]["number"], "5.00");
        assert_eq!(data["bank"]["exact"], true);
        assert_eq!(data["trialBalance"]["exact"], false);
        let rows = data["trialBalance"]["rows"].as_array().unwrap();
        let row = |account: &str| {
            rows.iter()
                .find(|row| row["account"] == account)
                .unwrap_or_else(|| panic!("{account} row"))["exact"]
                .clone()
        };
        assert_eq!(row("Assets:Cash"), false);
        assert_eq!(row("Assets:Bank"), true);
        assert_eq!(data["balanceSheet"]["exact"], false);
        assert_eq!(data["incomeStatement"]["exact"], false);
        assert_eq!(
            data["incomeStatement"]["net"][0]["number"],
            "1000.0000000000000000000000000"
        );
        let assertions = &data["verify"]["balanceAssertions"];
        assert_eq!(
            assertions["failed"], 1,
            "the rounded figure is not the balance"
        );
        assert_eq!(
            assertions["failures"][0]["actual"],
            "1000.0000000000000000000000000"
        );
        assert_eq!(assertions["failures"][0]["actualExact"], false);
    }
}
