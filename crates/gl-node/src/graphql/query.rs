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
    async fn trial_balance(&self, ctx: &Context<'_>, at: DateScalar) -> TrialBalance {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            let svc = ledger.read().await;
            let report = svc.read_model().trial_balance(at.0);
            TrialBalance {
                at,
                rows: report
                    .rows
                    .iter()
                    .map(|r| TrialBalanceRow {
                        account: r.account.clone(),
                        debit: DecimalScalar(r.debit),
                        credit: DecimalScalar(r.credit),
                    })
                    .collect(),
                total_debit: DecimalScalar(report.total_debit),
                total_credit: DecimalScalar(report.total_credit),
            }
        } else {
            TrialBalance {
                at,
                rows: Vec::new(),
                total_debit: DecimalScalar(Decimal::ZERO),
                total_credit: DecimalScalar(Decimal::ZERO),
            }
        }
    }

    /// Balance sheet at a given date (FR-2 AC2).
    #[graphql(complexity = "HEAVY_RESOLVER_COMPLEXITY")]
    async fn balance_sheet(&self, ctx: &Context<'_>, at: DateScalar) -> BalanceSheet {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            let svc = ledger.read().await;
            let report = svc.read_model().balance_sheet(at.0);
            fn convert_balances(
                entries: &[ledger::read_model::AccountBalanceEntry],
            ) -> Vec<AccountBalance> {
                entries
                    .iter()
                    .map(|entry| AccountBalance {
                        account: entry.account.clone(),
                        balances: entry
                            .balances
                            .iter()
                            .map(|(currency, amount)| Amount {
                                number: DecimalScalar(*amount),
                                currency: currency.clone(),
                            })
                            .collect(),
                    })
                    .collect()
            }
            BalanceSheet {
                at,
                assets: convert_balances(&report.assets),
                liabilities: convert_balances(&report.liabilities),
                equity: convert_balances(&report.equity),
            }
        } else {
            BalanceSheet {
                at,
                assets: Vec::new(),
                liabilities: Vec::new(),
                equity: Vec::new(),
            }
        }
    }

    /// Income statement for a date range (FR-2 AC3).
    #[graphql(complexity = "HEAVY_RESOLVER_COMPLEXITY")]
    async fn income_statement(
        &self,
        ctx: &Context<'_>,
        from: DateScalar,
        to: DateScalar,
    ) -> IncomeStatement {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            let svc = ledger.read().await;
            let report = svc.read_model().income_statement(from.0, to.0);
            fn convert_entries(
                entries: &[ledger::read_model::AccountBalanceEntry],
            ) -> Vec<AccountBalance> {
                entries
                    .iter()
                    .map(|entry| AccountBalance {
                        account: entry.account.clone(),
                        balances: entry
                            .balances
                            .iter()
                            .map(|(currency, amount)| Amount {
                                number: DecimalScalar(*amount),
                                currency: currency.clone(),
                            })
                            .collect(),
                    })
                    .collect()
            }
            IncomeStatement {
                from,
                to,
                income: convert_entries(&report.income),
                expenses: convert_entries(&report.expenses),
                net: report
                    .net
                    .iter()
                    .map(|(currency, amount)| Amount {
                        number: DecimalScalar(*amount),
                        currency: currency.clone(),
                    })
                    .collect(),
            }
        } else {
            IncomeStatement {
                from,
                to,
                income: Vec::new(),
                expenses: Vec::new(),
                net: Vec::new(),
            }
        }
    }

    /// Journal of transactions, optionally filtered (FR-2 AC4).
    #[graphql(complexity = "HEAVY_RESOLVER_COMPLEXITY")]
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
            let svc = ledger.read().await;
            let entries = svc.read_model().journal(
                account.as_deref(),
                from.map(|d| d.0),
                to.map(|d| d.0),
                clamp_journal_limit(limit),
                clamp_journal_offset(offset),
            );
            entries
                .into_iter()
                .map(|e| domain_txn_to_graphql(&e.transaction, &svc))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Look up a single transaction by its content hash.
    async fn transaction(&self, ctx: &Context<'_>, txid: TransactionId) -> Option<Transaction> {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            let svc = ledger.read().await;
            if let Some(ledger::model::Directive::Transaction(txn)) = svc.get_directive(&txid.0) {
                return Some(domain_txn_to_graphql(txn, &svc));
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
    ) -> Option<AccountBalance> {
        if let Ok(ledger) = ctx.data::<SharedLedger>() {
            let svc = ledger.read().await;
            if let Some(entry) = svc.read_model().account_balance(&name, at.map(|d| d.0)) {
                return Some(AccountBalance {
                    account: name,
                    balances: entry
                        .balances
                        .iter()
                        .map(|(currency, amount)| Amount {
                            number: DecimalScalar(*amount),
                            currency: currency.clone(),
                        })
                        .collect(),
                });
            }
        }
        None
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
            // handle and drop the guard — a `service.rs` change, out of scope
            // for this task and left for the pass that owns that file.
            let svc = ledger.read().await;
            let report = ledger::verify::verify_dag(svc.dag(), svc.read_model());
            VerifyResult {
                ok: report.ok,
                nodes_checked: report.nodes_checked as i32,
                errors: report.errors.iter().map(|e| e.to_string()).collect(),
                balance_assertions: assertion_report(&report.assertions),
            }
        } else {
            VerifyResult {
                ok: true,
                nodes_checked: 0,
                errors: Vec::new(),
                balance_assertions: assertion_report(&Default::default()),
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
                currency: failure.currency.clone(),
            })
            .collect(),
    }
}

/// Convert a domain Transaction to the GraphQL Transaction type.
pub fn domain_txn_to_graphql(
    txn: &ledger::model::Transaction,
    _svc: &ledger::service::LedgerService,
) -> Transaction {
    let content_id =
        ledger::hash::compute_content_id(&ledger::model::Directive::Transaction(txn.clone()));
    Transaction {
        txid: TransactionId(content_id),
        date: DateScalar(txn.date),
        flag: match txn.flag {
            ledger::model::Flag::Complete => "*".to_owned(),
            ledger::model::Flag::Incomplete => "!".to_owned(),
        },
        payee: txn.payee.clone(),
        narration: txn.narration.clone(),
        tags: txn.tags.clone(),
        links: txn.links.clone(),
        postings: txn
            .postings
            .iter()
            .map(|p| {
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
                        ledger::model::PriceSpec::Unit(a) | ledger::model::PriceSpec::Total(a) => {
                            Amount {
                                number: DecimalScalar(a.number),
                                currency: a.currency.clone(),
                            }
                        }
                    }),
                }
            })
            .collect(),
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
            schema.execute(query).await.errors
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
            .execute(
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
}
