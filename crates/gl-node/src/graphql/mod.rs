pub mod broadcast;
pub mod inputs;
pub mod mutation;
pub mod query;
pub mod scalars;
pub mod subscription;
pub mod types;

use async_graphql::Schema;
use async_graphql::http::GraphiQLSource;
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::extract::State;
use axum::response::{Html, IntoResponse};

use mutation::MutationRoot;
use query::QueryRoot;
use subscription::SubscriptionRoot;

/// The complete GraphQL schema type.
pub type AppSchema = Schema<QueryRoot, MutationRoot, SubscriptionRoot>;

/// Build the async-graphql schema with all roots.
pub fn build_schema() -> AppSchema {
    Schema::build(QueryRoot, MutationRoot, SubscriptionRoot).finish()
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
    Html(
        GraphiQLSource::build()
            .endpoint("/graphql")
            .subscription_endpoint("/graphql/ws")
            .finish(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_schema_introspection() {
        let schema = build_schema();
        let result = schema
            .execute("{ __schema { queryType { name } } }")
            .await;
        assert!(result.errors.is_empty(), "introspection errors: {:?}", result.errors);
        let data = result.data.into_json().unwrap();
        assert_eq!(data["__schema"]["queryType"]["name"], "QueryRoot");
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
        assert_eq!(data["health"]["heads"], 0);
        assert_eq!(data["health"]["peers"], 0);
        assert!(data["health"]["version"].is_string());
    }

    #[tokio::test]
    async fn test_trial_balance_stub() {
        let schema = build_schema();
        let result = schema
            .execute(r#"{ trialBalance(at: "2024-01-01") { at rows { account } totalDebit totalCredit } }"#)
            .await;
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let data = result.data.into_json().unwrap();
        assert_eq!(data["trialBalance"]["at"], "2024-01-01");
        assert_eq!(data["trialBalance"]["totalDebit"], "0");
        assert_eq!(data["trialBalance"]["totalCredit"], "0");
    }

    #[tokio::test]
    async fn test_journal_stub_empty() {
        let schema = build_schema();
        let result = schema.execute("{ journal { txid } }").await;
        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);
        let data = result.data.into_json().unwrap();
        assert_eq!(data["journal"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn test_append_transaction_returns_error() {
        let schema = build_schema();
        let result = schema
            .execute(
                r#"mutation {
                    appendTransaction(input: {
                        date: "2024-01-15",
                        postings: [
                            { account: "Assets:Cash", amount: { number: "1000", currency: "USD" } },
                            { account: "Equity:Opening" }
                        ]
                    }) { txid }
                }"#,
            )
            .await;
        assert!(!result.errors.is_empty(), "should error without ledger service");
        let error = &result.errors[0];
        let extensions = error.extensions.as_ref().unwrap();
        let code = extensions.get("code").unwrap();
        assert_eq!(code.to_string(), "\"INTERNAL\"");
    }

    #[tokio::test]
    async fn test_all_query_fields_present() {
        let schema = build_schema();
        // Verify all 9 query fields exist via introspection.
        let result = schema
            .execute(
                r#"{ __type(name: "QueryRoot") { fields { name } } }"#,
            )
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
            assert!(
                field_names.contains(name),
                "missing query field: {name}"
            );
        }
    }

    #[tokio::test]
    async fn test_all_mutation_fields_present() {
        let schema = build_schema();
        let result = schema
            .execute(
                r#"{ __type(name: "MutationRoot") { fields { name } } }"#,
            )
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
            assert!(
                field_names.contains(name),
                "missing mutation field: {name}"
            );
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
            assert_eq!(data["__type"]["kind"], "SCALAR", "expected {scalar_name} to be a SCALAR");
        }
    }
}
