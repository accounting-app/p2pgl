# Node endpoint (companies)

POST /node/graphql — the operator key only. Add, list, restart and remove company ledgers.

Set the variables first: [README](README.md).

## List ledgers

```bash
curl -s -X POST "$OPENLEDGER_URL/node/graphql" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "{ ledgers { name served reason nodeId listenPort } }",
  "variables": {}
}
JSON
```

## Add a company (a mesh of its own)

```bash
curl -s -X POST "$OPENLEDGER_URL/node/graphql" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "mutation($name: String!, $ports: String) { addLedger(name: $name, newMeshPorts: $ports) { name served reason nodeId listenPort } }",
  "variables": {
    "name": "acme",
    "ports": "4433-4532"
  }
}
JSON
```

## Add a ledger (own settings)

```bash
curl -s -X POST "$OPENLEDGER_URL/node/graphql" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "mutation($name: String!, $settings: String) { addLedger(name: $name, settings: $settings) { name served reason nodeId listenPort } }",
  "variables": {
    "name": "notes",
    "settings": "{}"
  }
}
JSON
```

## Restart a ledger

```bash
curl -s -X POST "$OPENLEDGER_URL/node/graphql" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "mutation($name: String!) { restartLedger(name: $name) { name served reason nodeId listenPort } }",
  "variables": {
    "name": "acme"
  }
}
JSON
```

## Remove a ledger (moved aside, not deleted)

```bash
curl -s -X POST "$OPENLEDGER_URL/node/graphql" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "mutation($name: String!) { removeLedger(name: $name) { name movedTo } }",
  "variables": {
    "name": "acme"
  }
}
JSON
```
