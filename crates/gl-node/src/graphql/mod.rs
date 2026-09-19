pub mod broadcast;
pub mod inputs;
pub mod mutation;
pub mod query;
pub mod scalars;
pub mod subscription;
pub mod types;

use std::sync::Arc;

use async_graphql::http::GraphiQLSource;
use async_graphql::Schema;
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::extract::State;
use axum::response::{Html, IntoResponse};
use tokio::sync::RwLock;

use broadcast::TransactionBroadcast;
use ledger::service::LedgerService;
use mutation::MutationRoot;
use query::QueryRoot;
use subscription::SubscriptionRoot;

/// Shared ledger state — `Arc<RwLock<LedgerService>>` for concurrent access.
///
/// Per §3.5: writes serialize through the write lock; reads use the read lock
/// and proceed concurrently.
pub type SharedLedger = Arc<RwLock<LedgerService>>;

/// The complete GraphQL schema type.
pub type AppSchema = Schema<QueryRoot, MutationRoot, SubscriptionRoot>;

/// Maximum selection-set depth (M-7).
pub const GRAPHQL_MAX_DEPTH: usize = 16;

/// Maximum query complexity (M-7).
pub const GRAPHQL_MAX_COMPLEXITY: usize = 4096;

/// Complexity weight for fields that scan the whole ledger/DAG under a lock, or
/// rewrite and fsync the whole ledger file (M-1). Every GraphQL field defaults
/// to a weight of 1, so without this a single request could alias a heavyweight
/// field thousands of times within the depth limit (e.g. `{ a: verify{ok}
/// b: verify{ok} … }`) and pin CPU — or batch thousands of mutations. At this
/// weight the 4096 budget admits at most 8 such fields per request, while still
/// leaving room for one of every report in a dashboard call.
pub(crate) const HEAVY_RESOLVER_COMPLEXITY: usize = 512;

fn schema_builder(
    enable_introspection: bool,
) -> async_graphql::SchemaBuilder<QueryRoot, MutationRoot, SubscriptionRoot> {
    let mut builder = Schema::build(QueryRoot, MutationRoot, SubscriptionRoot)
        .limit_depth(GRAPHQL_MAX_DEPTH)
        .limit_complexity(GRAPHQL_MAX_COMPLEXITY);
    if !enable_introspection {
        builder = builder.disable_introspection();
    }
    builder
}

/// Channel used to announce locally inserted directives on the gossip topic (R1).
pub type GossipSender = tokio::sync::mpsc::Sender<ledger::model::Directive>;

/// Build the async-graphql schema with the live ledger service.
///
/// Injects `SharedLedger`, `TransactionBroadcast`, `PeerRegistry`, and
/// `SignatureProvider` into the schema data so resolvers can access them
/// via `ctx.data_unchecked::<T>()`.
///
/// Introspection is enabled only when GraphiQL is on (loopback playground).
pub fn build_schema_with_service(
    ledger: SharedLedger,
    broadcast: TransactionBroadcast,
    peer_registry: p2p::node::PeerRegistry,
    signer: std::sync::Arc<dyn security::signing::SignatureProvider>,
    enable_introspection: bool,
    gossip_sender: Option<GossipSender>,
) -> AppSchema {
    let mut builder = schema_builder(enable_introspection)
        .data(ledger)
        .data(broadcast)
        .data(peer_registry)
        .data(signer);
    if let Some(sender) = gossip_sender {
        builder = builder.data(sender);
    }
    builder.finish()
}

/// Build the schema without a ledger service (for tests / introspection only).
///
/// Queries and mutations that need the ledger will return INTERNAL errors.
#[cfg(test)]
pub fn build_schema() -> AppSchema {
    schema_builder(true).finish()
}

/// Handler for `POST /graphql` — execute a GraphQL request.
pub async fn graphql_handler(
    State(schema): State<AppSchema>,
    request: GraphQLRequest,
) -> GraphQLResponse {
    schema.execute(request.into_inner()).await.into()
}

/// Handler for `GET /graphql` — serve the GraphiQL interactive explorer.
pub async fn graphiql_handler() -> impl IntoResponse {
    Html(GraphiQLSource::build().endpoint("/graphql").finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_schema_introspection() {
        let schema = build_schema();
        let result = schema.execute("{ __schema { queryType { name } } }").await;
        assert!(
            result.errors.is_empty(),
            "introspection errors: {:?}",
            result.errors
        );
        let data = result.data.into_json().unwrap();
        assert_eq!(data["__schema"]["queryType"]["name"], "QueryRoot");
    }

    #[tokio::test]
    async fn test_complexity_limits_heavy_resolver_aliasing() {
        // M-1 regression: aliasing an expensive resolver many times must be
        // rejected by the complexity budget (before execution) rather than
        // running thousands of full-ledger scans.
        let schema = build_schema();
        let mut query = String::from("{");
        for i in 0..64 {
            query.push_str(&format!(" a{i}: verify {{ ok }}"));
        }
        query.push('}');
        let result = schema.execute(query).await;
        assert!(
            !result.errors.is_empty(),
            "64 aliased verify calls should exceed the complexity budget"
        );
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.to_lowercase().contains("complex")),
            "expected a complexity error, got: {:?}",
            result.errors
        );
    }

    #[tokio::test]
    async fn test_complexity_limits_mutation_alias_batching() {
        // 0820-M1 completion (M-03): mutations rewrite + fsync the whole ledger
        // file, so alias batching must be budget-limited too.
        let schema = build_schema();
        let mut query = String::from("mutation {");
        for i in 0..16 {
            query.push_str(&format!(
                " a{i}: openAccount(name: \"Assets:X\", date: \"2024-01-01\")"
            ));
        }
        query.push('}');
        let result = schema.execute(query).await;
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.to_lowercase().contains("complex")),
            "16 aliased mutations should exceed the complexity budget, got: {:?}",
            result.errors
        );
    }

    #[tokio::test]
    async fn test_complexity_limits_account_at_aliasing() {
        // 0820-M1 completion (M-02): `account(at:)` replays the whole ledger, so
        // aliasing it must be budget-limited like the other heavy resolvers.
        let schema = build_schema();
        let mut query = String::from("{");
        for i in 0..16 {
            query.push_str(&format!(
                " a{i}: account(name: \"Assets:X\", at: \"2024-01-01\") {{ account }}"
            ));
        }
        query.push('}');
        let result = schema.execute(query).await;
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.to_lowercase().contains("complex")),
            "16 aliased account(at:) calls should exceed the complexity budget, got: {:?}",
            result.errors
        );
    }

    #[tokio::test]
    async fn test_complexity_allows_account_lookups_without_at() {
        // Current-balance lookups stay cheap: batching accounts WITHOUT `at`
        // must not trip the budget.
        let schema = build_schema();
        let mut query = String::from("{");
        for i in 0..16 {
            query.push_str(&format!(" a{i}: account(name: \"Assets:X\") {{ account }}"));
        }
        query.push('}');
        let result = schema.execute(query).await;
        assert!(
            !result
                .errors
                .iter()
                .any(|e| e.message.to_lowercase().contains("complex")),
            "account lookups without `at` should stay under the budget: {:?}",
            result.errors
        );
    }

    #[tokio::test]
    async fn test_complexity_allows_single_heavy_resolver() {
        // A single heavy resolver stays well within the budget.
        let schema = build_schema();
        let result = schema.execute("{ verify { ok } }").await;
        assert!(
            result.errors.is_empty(),
            "single verify should be allowed: {:?}",
            result.errors
        );
    }

    #[tokio::test]
    async fn test_health_query() {
        let schema = build_schema();
        let result = schema
            .execute("{ health { status heads peers version } }")
            .await;
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let data = result.data.into_json().unwrap();
        assert_eq!(data["health"]["status"], "ok");
        assert!(data["health"]["version"].is_string());
    }

    #[tokio::test]
    async fn test_all_query_fields_present() {
        let schema = build_schema();
        let result = schema
            .execute(r#"{ __type(name: "QueryRoot") { fields { name } } }"#)
            .await;
        assert!(result.errors.is_empty());
        let data = result.data.into_json().unwrap();
        let field_names: Vec<&str> = data["__type"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|field| field["name"].as_str().unwrap())
            .collect();
        let expected = [
            "trialBalance",
            "balanceSheet",
            "incomeStatement",
            "journal",
            "transaction",
            "account",
            "verify",
            "health",
            "peers",
        ];
        for name in &expected {
            assert!(field_names.contains(name), "missing query field: {name}");
        }
    }

    #[tokio::test]
    async fn test_all_mutation_fields_present() {
        let schema = build_schema();
        let result = schema
            .execute(r#"{ __type(name: "MutationRoot") { fields { name } } }"#)
            .await;
        assert!(result.errors.is_empty());
        let data = result.data.into_json().unwrap();
        let field_names: Vec<&str> = data["__type"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .map(|field| field["name"].as_str().unwrap())
            .collect();
        let expected = ["appendTransaction", "openAccount", "closeAccount"];
        for name in &expected {
            assert!(field_names.contains(name), "missing mutation field: {name}");
        }
    }

    #[tokio::test]
    async fn test_scalars_registered() {
        let schema = build_schema();
        for scalar_name in ["Date", "Decimal", "TxId"] {
            let query = format!(r#"{{ __type(name: "{scalar_name}") {{ name kind }} }}"#);
            let result = schema.execute(&query).await;
            assert!(result.errors.is_empty());
            let data = result.data.into_json().unwrap();
            assert_eq!(
                data["__type"]["kind"], "SCALAR",
                "expected {scalar_name} to be a SCALAR"
            );
        }
    }

    /// The `Peer` type exposes membership only (0902 informational).
    ///
    /// `Peer.heads` was fed by a registry field that nothing ever wrote a head
    /// into, so it answered `[]` for every peer on every healthy mesh. Asserting
    /// the exact field set — rather than just that `heads` is gone — is what
    /// stops it being reintroduced as another always-empty list.
    #[tokio::test]
    async fn test_peer_type_exposes_membership_only() {
        let schema = build_schema();
        let result = schema
            .execute(r#"{ __type(name: "Peer") { fields { name } } }"#)
            .await;
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let data = result.data.into_json().unwrap();
        let field_names: Vec<&str> = data["__type"]["fields"]
            .as_array()
            .expect("Peer must still be in the schema")
            .iter()
            .map(|field| field["name"].as_str().unwrap())
            .collect();
        assert_eq!(field_names, vec!["id"]);

        // And querying the removed field is now a schema error, not an empty list.
        let removed = schema.execute("{ peers { id heads } }").await;
        assert!(
            !removed.errors.is_empty(),
            "peers.heads must no longer resolve"
        );

        let live = schema.execute("{ peers { id } }").await;
        assert!(live.errors.is_empty(), "errors: {:?}", live.errors);
    }

    #[tokio::test]
    async fn test_wired_schema_with_service() {
        let dir = tempfile::tempdir().unwrap();
        let bean_path = dir.path().join("test.bean");
        std::fs::write(&bean_path, "").unwrap();

        let service = LedgerService::boot(&bean_path, "test-node".to_owned()).unwrap();
        let ledger = Arc::new(RwLock::new(service));
        let broadcast = TransactionBroadcast::new();
        let schema = build_schema_with_service(
            ledger,
            broadcast,
            p2p::node::PeerRegistry::new(),
            std::sync::Arc::new(security::signing::NoopSignatureProvider),
            true,
            None,
        );

        // Health should show 0 heads.
        let result = schema.execute("{ health { status heads } }").await;
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let data = result.data.into_json().unwrap();
        assert_eq!(data["health"]["status"], "ok");
        assert_eq!(data["health"]["heads"], 0);
    }

    /// Boot a schema over a temp ledger holding exactly `bean` (M-08 tests).
    fn schema_over_ledger(bean: &str) -> (tempfile::TempDir, AppSchema) {
        let (dir, _ledger, schema) = schema_and_ledger_over(bean);
        (dir, schema)
    }

    /// As [`schema_over_ledger`], but also hands back the `SharedLedger` so a
    /// test can drive the P2P receive path behind the schema's back (M-10).
    fn schema_and_ledger_over(bean: &str) -> (tempfile::TempDir, SharedLedger, AppSchema) {
        let dir = tempfile::tempdir().unwrap();
        let bean_path = dir.path().join("test.bean");
        std::fs::write(&bean_path, bean).unwrap();
        let service = LedgerService::boot(&bean_path, "test-node".to_owned()).unwrap();
        let ledger: SharedLedger = Arc::new(RwLock::new(service));
        let schema = build_schema_with_service(
            Arc::clone(&ledger),
            TransactionBroadcast::new(),
            p2p::node::PeerRegistry::new(),
            std::sync::Arc::new(security::signing::NoopSignatureProvider),
            true,
            None,
        );
        (dir, ledger, schema)
    }

    /// A ledger whose single `balance` directive claims `asserted` for
    /// `Assets:Cash` on 2024-02-01, where the real balance is 1000.00 USD.
    fn ledger_asserting(asserted: &str) -> String {
        format!(
            "2024-01-01 open Assets:Cash USD\n\
             2024-01-01 open Equity:Opening USD\n\
             \n\
             2024-01-15 * \"Deposit\"\n  \
               openledger-author: \"test\"\n  \
               openledger-lamport: \"1\"\n  \
               openledger-parents: \"\"\n  \
               Assets:Cash                                      1000.00 USD\n  \
               Equity:Opening                                  -1000.00 USD\n\
             \n\
             2024-02-01 balance Assets:Cash {asserted} USD\n"
        )
    }

    const VERIFY_QUERY: &str = r"
        { verify {
            ok
            nodesChecked
            errors
            balanceAssertions {
                evaluated passed failed ok
                failures { account date expected actual currency }
            }
        } }
    ";

    #[tokio::test]
    async fn test_verify_surfaces_failing_balance_assertion() {
        // M-08 regression: `balance` directives reach the file through the
        // unvalidated catch-all — from a local edit or from an allowlisted peer
        // over gossip — and used to be stored and never evaluated, so a false
        // claim read as verified. `verify` must now report it, with the figures
        // that expose the lie.
        let (_dir, schema) = schema_over_ledger(&ledger_asserting("999.00"));

        let result = schema.execute(VERIFY_QUERY).await;
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let data = result.data.into_json().unwrap();
        let assertions = &data["verify"]["balanceAssertions"];

        assert_eq!(assertions["evaluated"], 1);
        assert_eq!(assertions["passed"], 0);
        assert_eq!(assertions["failed"], 1);
        assert_eq!(assertions["ok"], false);

        let failures = assertions["failures"].as_array().unwrap();
        assert_eq!(failures.len(), 1, "expected one failure: {failures:?}");
        let failure = &failures[0];
        assert_eq!(failure["account"], "Assets:Cash");
        assert_eq!(failure["date"], "2024-02-01");
        assert_eq!(failure["currency"], "USD");
        assert_eq!(
            decimal(&failure["expected"]),
            rust_decimal_macros::dec!(999),
            "the claim in the file"
        );
        assert_eq!(
            decimal(&failure["actual"]),
            rust_decimal_macros::dec!(1000),
            "what the ledger actually holds"
        );

        // The structural verdict is untouched: a false claim is not DAG
        // corruption, so a peer cannot redden every node by gossiping one.
        assert_eq!(data["verify"]["ok"], true, "structural checks: {data:?}");
        assert_eq!(data["verify"]["errors"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_verify_reports_passing_balance_assertion() {
        let (_dir, schema) = schema_over_ledger(&ledger_asserting("1000.00"));

        let result = schema.execute(VERIFY_QUERY).await;
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let data = result.data.into_json().unwrap();
        let assertions = &data["verify"]["balanceAssertions"];

        assert_eq!(assertions["evaluated"], 1);
        assert_eq!(assertions["passed"], 1);
        assert_eq!(assertions["failed"], 0);
        assert_eq!(assertions["ok"], true);
        assert!(assertions["failures"].as_array().unwrap().is_empty());
        assert_eq!(data["verify"]["ok"], true);
    }

    #[tokio::test]
    async fn test_verify_reports_no_assertions_for_a_ledger_without_any() {
        // An empty summary means "nothing claimed", not "nothing checked".
        let (_dir, schema) = schema_over_ledger("2024-01-01 open Assets:Cash USD\n");

        let result = schema.execute(VERIFY_QUERY).await;
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let data = result.data.into_json().unwrap();
        let assertions = &data["verify"]["balanceAssertions"];
        assert_eq!(assertions["evaluated"], 0);
        assert_eq!(assertions["ok"], true);
        assert!(assertions["failures"].as_array().unwrap().is_empty());
    }

    /// Read a `Decimal` GraphQL scalar (a string on the wire, I4) from JSON.
    fn decimal(value: &serde_json::Value) -> rust_decimal::Decimal {
        value
            .as_str()
            .unwrap_or_else(|| panic!("Decimal must be a string on the wire: {value:?}"))
            .parse()
            .expect("valid decimal")
    }

    #[tokio::test]
    async fn test_introspection_disabled_when_graphiql_off() {
        let dir = tempfile::tempdir().unwrap();
        let bean_path = dir.path().join("test.bean");
        std::fs::write(&bean_path, "").unwrap();
        let service = LedgerService::boot(&bean_path, "test-node".to_owned()).unwrap();
        let schema = build_schema_with_service(
            Arc::new(RwLock::new(service)),
            TransactionBroadcast::new(),
            p2p::node::PeerRegistry::new(),
            std::sync::Arc::new(security::signing::NoopSignatureProvider),
            false,
            None,
        );
        let result = schema.execute("{ __schema { queryType { name } } }").await;
        let data = result.data.into_json().unwrap();
        assert!(
            data["__schema"].is_null(),
            "introspection should be disabled; data={data:?}"
        );
    }

    #[tokio::test]
    async fn test_append_transaction_rejects_invalid_flag() {
        let dir = tempfile::tempdir().unwrap();
        let bean_path = dir.path().join("test.bean");
        std::fs::write(&bean_path, "").unwrap();

        let service = LedgerService::boot(&bean_path, "test-node".to_owned()).unwrap();
        let ledger = Arc::new(RwLock::new(service));
        let schema = build_schema_with_service(
            ledger,
            TransactionBroadcast::new(),
            p2p::node::PeerRegistry::new(),
            std::sync::Arc::new(security::signing::NoopSignatureProvider),
            true,
            None,
        );

        let result = schema
            .execute(
                r#"
                mutation {
                    appendTransaction(input: {
                        date: "2024-01-15"
                        flag: "nope"
                        postings: [
                            { account: "Assets:Cash", amount: { number: "1", currency: "USD" } }
                        ]
                    }) { txid }
                }
                "#,
            )
            .await;
        assert!(!result.errors.is_empty());
        assert!(
            result.errors[0].message.contains("flag"),
            "unexpected error: {:?}",
            result.errors
        );
    }

    #[tokio::test]
    async fn test_append_transaction_rejects_out_of_range_year() {
        // H-04 regression: chrono's `%Y` accepts `+10000-01-01` and re-emits the
        // sign, but the ledger's own file grammar requires four leading ASCII
        // digits. Persisting one such date would leave a `.bean` file that no
        // later boot can parse — one authorized mutation bricks the node. The
        // mutation must be refused and the file left untouched.
        let dir = tempfile::tempdir().unwrap();
        let bean_path = dir.path().join("test.bean");
        std::fs::write(&bean_path, "").unwrap();

        let service = LedgerService::boot(&bean_path, "test-node".to_owned()).unwrap();
        let schema = build_schema_with_service(
            Arc::new(RwLock::new(service)),
            TransactionBroadcast::new(),
            p2p::node::PeerRegistry::new(),
            std::sync::Arc::new(security::signing::NoopSignatureProvider),
            true,
            None,
        );

        // Open the accounts first, so the append is refused for its date and
        // nothing else — otherwise the lifecycle check (I3) would mask the bug.
        for name in ["Assets:Cash", "Equity:Opening"] {
            let opened = schema
                .execute(format!(
                    r#"mutation {{ openAccount(name: "{name}", date: "2024-01-01") }}"#
                ))
                .await;
            assert!(opened.errors.is_empty(), "errors: {:?}", opened.errors);
        }
        let before = std::fs::read_to_string(&bean_path).unwrap();

        let result = schema
            .execute(
                r#"
                mutation {
                    appendTransaction(input: {
                        date: "+10000-01-01"
                        flag: "*"
                        postings: [
                            { account: "Assets:Cash", amount: { number: "1", currency: "USD" } },
                            { account: "Equity:Opening", amount: { number: "-1", currency: "USD" } }
                        ]
                    }) { txid }
                }
                "#,
            )
            .await;

        assert!(
            !result.errors.is_empty(),
            "a year outside 0001..=9999 must be rejected"
        );
        let message = result.errors[0].message.to_lowercase();
        assert!(
            message.contains("date") || message.contains("year"),
            "expected a date/year error, got: {:?}",
            result.errors
        );

        assert_eq!(
            std::fs::read_to_string(&bean_path).unwrap(),
            before,
            "the rejected date must never reach the ledger file"
        );
        LedgerService::boot(&bean_path, "test-node".to_owned())
            .expect("the ledger must still boot — the brick never happened");
    }

    #[tokio::test]
    async fn test_open_account_accepts_last_supported_date() {
        // The other side of H-04: the last date the file grammar can round-trip
        // stays usable, and the file it writes re-boots cleanly.
        let dir = tempfile::tempdir().unwrap();
        let bean_path = dir.path().join("test.bean");
        std::fs::write(&bean_path, "").unwrap();

        let service = LedgerService::boot(&bean_path, "test-node".to_owned()).unwrap();
        let schema = build_schema_with_service(
            Arc::new(RwLock::new(service)),
            TransactionBroadcast::new(),
            p2p::node::PeerRegistry::new(),
            std::sync::Arc::new(security::signing::NoopSignatureProvider),
            true,
            None,
        );

        let result = schema
            .execute(r#"mutation { openAccount(name: "Assets:Cash", date: "9999-12-31") }"#)
            .await;
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);

        let on_disk = std::fs::read_to_string(&bean_path).unwrap();
        assert!(
            on_disk.starts_with("9999-12-31 open Assets:Cash"),
            "unexpected ledger file: {on_disk:?}"
        );
        let rebooted = LedgerService::boot(&bean_path, "test-node".to_owned()).unwrap();
        assert_eq!(rebooted.directive_count(), 1);
    }

    // ── T33: `alreadyExisted` on appendTransaction (M-10, interim) ───────

    /// Accounts for the M-10 rent scenario — the recurring, predictable body a
    /// squatter can guess.
    const RENT_ACCOUNTS: &str = "2024-01-01 open Assets:Cash USD\n\
                                 2024-01-01 open Expenses:Rent USD\n";

    /// The victim's genuine monthly rent entry, as a GraphQL mutation.
    const RENT_MUTATION: &str = r#"
        mutation {
            appendTransaction(input: {
                date: "2024-02-01"
                flag: "*"
                payee: "Landlord"
                narration: "February rent"
                postings: [
                    { account: "Expenses:Rent", amount: { number: "1500.00", currency: "USD" } },
                    { account: "Assets:Cash", amount: { number: "-1500.00", currency: "USD" } }
                ]
            }) { txid author alreadyExisted }
        }
    "#;

    /// The same economic body, wearing another peer's envelope — what a
    /// squatter gossips onto the mesh before the victim writes it.
    fn rent_transaction_authored_by(author: &str) -> ledger::model::Directive {
        use ledger::model::{Amount, Flag, Posting, Transaction};
        use std::collections::BTreeMap;

        let posting = |account: &str, number: rust_decimal::Decimal| Posting {
            account: account.to_owned(),
            amount: Some(Amount {
                number,
                currency: "USD".to_owned(),
            }),
            cost: None,
            price: None,
            metadata: BTreeMap::new(),
        };
        let mut metadata = BTreeMap::new();
        metadata.insert("openledger-author".to_owned(), author.to_owned());
        metadata.insert("openledger-lamport".to_owned(), "3".to_owned());
        metadata.insert("openledger-parents".to_owned(), String::new());

        ledger::model::Directive::Transaction(Transaction {
            date: chrono::NaiveDate::from_ymd_opt(2024, 2, 1).unwrap(),
            flag: Flag::Complete,
            payee: Some("Landlord".to_owned()),
            narration: Some("February rent".to_owned()),
            tags: vec![],
            links: vec![],
            postings: vec![
                posting("Expenses:Rent", rust_decimal_macros::dec!(1500.00)),
                posting("Assets:Cash", rust_decimal_macros::dec!(-1500.00)),
            ],
            metadata,
        })
    }

    #[tokio::test]
    async fn test_append_transaction_reports_already_existed() {
        // M-10 (interim): appends are idempotent by economic content, so the
        // second call records nothing. It used to answer exactly like the
        // first — a txid and no errors — leaving the caller unable to tell that
        // its entry had been collapsed into an earlier identical one. The
        // payload must now carry that verdict on both calls.
        let (_dir, schema) = schema_over_ledger(RENT_ACCOUNTS);

        let first = schema.execute(RENT_MUTATION).await;
        assert!(first.errors.is_empty(), "errors: {:?}", first.errors);
        let first = first.data.into_json().unwrap();
        assert_eq!(
            first["appendTransaction"]["alreadyExisted"], false,
            "the first append really inserts: {first:?}"
        );

        let second = schema.execute(RENT_MUTATION).await;
        assert!(second.errors.is_empty(), "errors: {:?}", second.errors);
        let second = second.data.into_json().unwrap();
        assert_eq!(
            second["appendTransaction"]["alreadyExisted"], true,
            "an identical body records nothing new: {second:?}"
        );
        assert_eq!(
            second["appendTransaction"]["txid"], first["appendTransaction"]["txid"],
            "same economic body → same txid"
        );
    }

    #[tokio::test]
    async fn test_append_transaction_reports_a_body_a_peer_squatted_first() {
        // M-10 proper: the content hash excludes every `openledger-*` key, so a
        // peer that can predict a recurring body (rent, salary) publishes it
        // under ITS OWN author/signature first. The victim's genuine append
        // then resolves as a duplicate and the mesh keeps crediting the
        // squatter — and the caller used to see nothing but success.
        let (_dir, ledger, schema) = schema_and_ledger_over(RENT_ACCOUNTS);

        // The squatter's copy arrives over the P2P receive path.
        ledger
            .write()
            .await
            .insert_remote_directive(rent_transaction_authored_by("peer-squatter"))
            .unwrap()
            .expect("the squatter's entry is new to this node");

        let result = schema.execute(RENT_MUTATION).await;
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let data = result.data.into_json().unwrap();
        assert_eq!(
            data["appendTransaction"]["alreadyExisted"], true,
            "the squatter got there first: {data:?}"
        );
        // The warning is warranted: the envelope on record is not the caller's.
        assert_eq!(
            data["appendTransaction"]["author"], "peer-squatter",
            "the mesh still attributes the event to the squatter: {data:?}"
        );
    }

    #[tokio::test]
    async fn test_append_transaction_payload_keeps_its_existing_fields() {
        // The M-10 signal is additive: `alreadyExisted` joins the payload, and
        // every field clients already select off `appendTransaction` still
        // resolves in the same shape.
        let (_dir, schema) = schema_over_ledger(RENT_ACCOUNTS);

        let result = schema
            .execute(
                r#"
                mutation {
                    appendTransaction(input: {
                        date: "2024-02-01"
                        flag: "*"
                        payee: "Landlord"
                        narration: "February rent"
                        postings: [
                            { account: "Expenses:Rent", amount: { number: "1500.00", currency: "USD" } },
                            { account: "Assets:Cash", amount: { number: "-1500.00", currency: "USD" } }
                        ]
                    }) {
                        txid date flag payee narration tags links author signature parents
                        postings {
                            account
                            amount { number currency }
                            cost { number currency }
                            price { number currency }
                        }
                    }
                }
                "#,
            )
            .await;
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let txn = &result.data.into_json().unwrap()["appendTransaction"];
        assert_eq!(txn["txid"].as_str().unwrap().len(), 64);
        assert_eq!(txn["date"], "2024-02-01");
        assert_eq!(txn["flag"], "*");
        assert_eq!(txn["payee"], "Landlord");
        assert_eq!(txn["author"], "test-node");
        assert_eq!(txn["postings"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn test_append_transaction_payload_declares_already_existed() {
        // Schema-level: the field is non-null Boolean, so a client can rely on
        // it being present on every successful append.
        let schema = build_schema();
        let result = schema
            .execute(
                r#"{ __type(name: "AppendedTransaction") {
                        fields { name type { kind ofType { name } } }
                   } }"#,
            )
            .await;
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let data = result.data.into_json().unwrap();
        let fields = data["__type"]["fields"].as_array().unwrap();

        let already_existed = fields
            .iter()
            .find(|field| field["name"] == "alreadyExisted")
            .unwrap_or_else(|| panic!("appendTransaction payload must expose it: {fields:?}"));
        assert_eq!(already_existed["type"]["kind"], "NON_NULL");
        assert_eq!(already_existed["type"]["ofType"]["name"], "Boolean");

        // …alongside — not instead of — the transaction fields it flattens in.
        let names: Vec<&str> = fields
            .iter()
            .map(|field| field["name"].as_str().unwrap())
            .collect();
        for name in ["txid", "date", "flag", "postings", "author", "parents"] {
            assert!(names.contains(&name), "payload lost {name}: {names:?}");
        }
    }
}
