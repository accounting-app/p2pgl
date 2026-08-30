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
}
