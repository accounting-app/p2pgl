# People and keys

The ledger's access list. Needs an admin key or the operator key, on a ledger that signs (a company).

Set the variables first: [README](README.md).

## Access list

```bash
curl -s -X POST "$OPENLEDGER_URL$GRAPHQL_PATH" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "{ accessList { userId name role expires expired } }",
  "variables": {}
}
JSON
```

## Grant access (new person)

```bash
curl -s -X POST "$OPENLEDGER_URL$GRAPHQL_PATH" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "mutation($name: String, $role: AccessRole!, $expires: Date) { grantAccess(name: $name, role: $role, expires: $expires) { userId name role expires key } }",
  "variables": {
    "name": "Ana Ruiz",
    "role": "WRITE",
    "expires": null
  }
}
JSON
```

## Change a role / new key (existing person)

```bash
curl -s -X POST "$OPENLEDGER_URL$GRAPHQL_PATH" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "mutation($user: String!, $role: AccessRole!, $expires: Date) { grantAccess(userId: $user, role: $role, expires: $expires) { userId name role expires key } }",
  "variables": {
    "user": "PASTE-A-USER-ID",
    "role": "READ",
    "expires": "2026-12-31"
  }
}
JSON
```

## Rename a person

```bash
curl -s -X POST "$OPENLEDGER_URL$GRAPHQL_PATH" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "mutation($user: String!, $name: String!) { renameUser(userId: $user, name: $name) }",
  "variables": {
    "user": "PASTE-A-USER-ID",
    "name": "Ana Ruiz Pérez"
  }
}
JSON
```

## Revoke access

```bash
curl -s -X POST "$OPENLEDGER_URL$GRAPHQL_PATH" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "mutation($user: String!) { revokeAccess(userId: $user) }",
  "variables": {
    "user": "PASTE-A-USER-ID"
  }
}
JSON
```
