//! Who is calling, and what their role lets them do (`docs/build-log/002-users-and-roles`).
//!
//! The auth middleware turns the request's key into a [`Caller`] and attaches
//! it to the GraphQL request. [`AccessControl`], a schema extension, then judges
//! the parsed request **before anything runs**: every query and subscription
//! needs [`Role::Read`], every mutation [`Role::Write`], and the access-management
//! fields in [`ADMIN_FIELDS`] [`Role::Admin`]. The rule is by operation type, so a
//! mutation added later is closed to read keys without anyone remembering to
//! guard it — deny by default. A document with several operations, aliases or
//! fragments is held to the strictest thing anywhere in it.

use std::collections::HashSet;
use std::sync::Arc;

use async_graphql::extensions::{Extension, ExtensionContext, ExtensionFactory, NextParseQuery};
use async_graphql::parser::types::{ExecutableDocument, OperationType, Selection, SelectionSet};
use async_graphql::{ServerError, ServerResult, Variables};

/// What a key may do. Ordered: each role includes the ones below it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Reports, balances, the journal, `verify`: nothing that changes anything.
    Read,
    /// Read, and enter transactions and manage accounts.
    Write,
    /// Everything, including managing people and keys.
    Admin,
}

impl std::fmt::Display for Role {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Role::Read => "read",
            Role::Write => "write",
            Role::Admin => "admin",
        })
    }
}

/// The authenticated caller of one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    pub who: CallerId,
    pub role: Role,
}

/// Who a caller is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallerId {
    /// The node's operator key (`auth.apiKey`, `GL_NODE_API_KEY`, the generated
    /// key file) — or anyone at all on a loopback node with auth turned off.
    /// Admin on this node only; never replicated.
    Operator,
    /// A person, by their user id (`u_` and 16 hex digits), from the access
    /// list the ledger's access records fold to (`crate::access_list`).
    User(String),
}

impl Caller {
    /// The node's operator: admin.
    pub fn operator() -> Self {
        Caller {
            who: CallerId::Operator,
            role: Role::Admin,
        }
    }
}

/// Root fields only an admin may use (access management). Empty until the
/// admin API exists; listed here so the rule is in one place.
pub const ADMIN_FIELDS: &[&str] = &[];

/// The schema extension that enforces [`Role`]s; see the module doc.
pub struct AccessControl;

impl ExtensionFactory for AccessControl {
    fn create(&self) -> Arc<dyn Extension> {
        Arc::new(AccessControlExtension)
    }
}

struct AccessControlExtension;

#[async_graphql::async_trait::async_trait]
impl Extension for AccessControlExtension {
    async fn parse_query(
        &self,
        ctx: &ExtensionContext<'_>,
        query: &str,
        variables: &Variables,
        next: NextParseQuery<'_>,
    ) -> ServerResult<ExecutableDocument> {
        let document = next.run(ctx, query, variables).await?;
        let needed = required_role(&document);
        match caller(ctx) {
            Some(caller) if caller.role >= needed => Ok(document),
            Some(caller) => Err(forbidden(format!(
                "this key's role is {}; the request needs {needed}",
                caller.role
            ))),
            None => Err(forbidden(
                "no authenticated caller for this request".to_owned(),
            )),
        }
    }
}

/// The request's caller, as the auth middleware attached it. There is no
/// fallback: a request that reached the schema any other way has none, and is
/// refused. (Tests attach the operator themselves: `ExecuteAsOperator`.)
fn caller<'a>(ctx: &ExtensionContext<'a>) -> Option<&'a Caller> {
    ctx.data_opt::<Caller>()
}

fn forbidden(message: String) -> ServerError {
    let mut extensions = async_graphql::ErrorExtensionValues::default();
    extensions.set("code", "FORBIDDEN");
    let mut error = ServerError::new(message, None);
    error.extensions = Some(extensions);
    error
}

/// The strictest role anything in `document` needs: [`Role::Write`] for any
/// mutation, [`Role::Admin`] for any root field in [`ADMIN_FIELDS`] (through
/// fragments too), [`Role::Read`] otherwise.
pub fn required_role(document: &ExecutableDocument) -> Role {
    required_role_with(document, ADMIN_FIELDS)
}

fn required_role_with(document: &ExecutableDocument, admin_fields: &[&str]) -> Role {
    let mut needed = Role::Read;
    for (_, operation) in document.operations.iter() {
        if operation.node.ty == OperationType::Mutation {
            needed = needed.max(Role::Write);
        }
        if root_fields_include_admin(
            document,
            admin_fields,
            &operation.node.selection_set.node,
            &mut HashSet::new(),
        ) {
            needed = Role::Admin;
        }
    }
    needed
}

fn root_fields_include_admin<'a>(
    document: &'a ExecutableDocument,
    admin_fields: &[&str],
    selections: &'a SelectionSet,
    visited: &mut HashSet<&'a str>,
) -> bool {
    selections
        .items
        .iter()
        .any(|selection| match &selection.node {
            Selection::Field(field) => admin_fields.contains(&field.node.name.node.as_str()),
            Selection::InlineFragment(fragment) => root_fields_include_admin(
                document,
                admin_fields,
                &fragment.node.selection_set.node,
                visited,
            ),
            Selection::FragmentSpread(spread) => {
                let name = spread.node.fragment_name.node.as_str();
                // A cycle is refused later by validation; here it must not loop.
                visited.insert(name)
                    && document.fragments.get(name).is_some_and(|fragment| {
                        root_fields_include_admin(
                            document,
                            admin_fields,
                            &fragment.node.selection_set.node,
                            visited,
                        )
                    })
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn role_of(query: &str, admin_fields: &[&str]) -> Role {
        let document = async_graphql::parser::parse_query(query).expect("parses");
        required_role_with(&document, admin_fields)
    }

    /// The role a request needs (002-users-and-roles): read for queries, write
    /// for any mutation — also beside a query in one document, or behind an
    /// alias — and admin for an admin field however it is reached: directly,
    /// aliased, in an inline fragment or a named one; a fragment cycle is not
    /// followed forever.
    ///
    /// Bug-catch: judge only the first operation, or skip fragments, and a
    /// mutation or admin field rides along unchecked.
    #[test]
    fn a_request_needs_the_strictest_role_anything_in_it_needs() {
        let admin = &["secretField"];
        assert_eq!(role_of("{ verify { ok } }", admin), Role::Read);
        assert_eq!(
            role_of("subscription { transactionAdded { txid } }", admin),
            Role::Read
        );
        assert_eq!(
            role_of(
                "mutation { openAccount(name: \"A\", date: \"2024-01-01\") }",
                admin
            ),
            Role::Write
        );
        assert_eq!(
            role_of("query Q { verify { ok } } mutation M { x: openAccount(name: \"A\", date: \"2024-01-01\") }", admin),
            Role::Write,
            "a mutation beside a query"
        );
        assert_eq!(role_of("{ s: secretField }", admin), Role::Admin, "aliased");
        assert_eq!(
            role_of("{ ... on QueryRoot { secretField } }", admin),
            Role::Admin,
            "inline fragment"
        );
        assert_eq!(
            role_of("{ ...F } fragment F on QueryRoot { secretField }", admin),
            Role::Admin,
            "named fragment"
        );
        assert_eq!(
            role_of("{ ...F } fragment F on QueryRoot { ...G } fragment G on QueryRoot { ...F verify { ok } }", admin),
            Role::Read,
            "a fragment cycle ends"
        );
    }
}
