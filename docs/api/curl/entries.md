# Books: entries

Writes: a key with the write role (or the operator key).

Set the variables first: [README](README.md).

## Open an account

```bash
curl -s -X POST "$OPENLEDGER_URL$GRAPHQL_PATH" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "mutation($name: String!, $date: Date!, $currencies: String) { openAccount(name: $name, date: $date, currencies: $currencies) }",
  "variables": {
    "name": "Assets:Bank:Checking",
    "date": "2026-01-01",
    "currencies": "USD"
  }
}
JSON
```

## Open an account (any currency)

```bash
curl -s -X POST "$OPENLEDGER_URL$GRAPHQL_PATH" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "mutation($name: String!, $date: Date!) { openAccount(name: $name, date: $date) }",
  "variables": {
    "name": "Income:Sales",
    "date": "2026-01-01"
  }
}
JSON
```

## Append a transaction

```bash
curl -s -X POST "$OPENLEDGER_URL$GRAPHQL_PATH" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "mutation($input: TransactionInput!) { appendTransaction(input: $input) { txid date narration alreadyExisted enteredByName postings { account amount { number currency } } } }",
  "variables": {
    "input": {
      "date": "2026-01-15",
      "flag": "*",
      "payee": "Acme Client",
      "narration": "Invoice 1001",
      "tags": [],
      "links": [],
      "postings": [
        {
          "account": "Assets:Bank:Checking",
          "amount": {
            "number": "1500.00",
            "currency": "USD"
          }
        },
        {
          "account": "Income:Sales",
          "amount": {
            "number": "-1500.00",
            "currency": "USD"
          }
        }
      ]
    }
  }
}
JSON
```

## Append a transaction (one amount elided)

```bash
curl -s -X POST "$OPENLEDGER_URL$GRAPHQL_PATH" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "mutation($input: TransactionInput!) { appendTransaction(input: $input) { txid postings { account amount { number currency } } } }",
  "variables": {
    "input": {
      "date": "2026-01-16",
      "flag": "*",
      "narration": "Elided posting balances it",
      "postings": [
        {
          "account": "Assets:Bank:Checking",
          "amount": {
            "number": "250.00",
            "currency": "USD"
          }
        },
        {
          "account": "Income:Sales"
        }
      ]
    }
  }
}
JSON
```

## Close an account

```bash
curl -s -X POST "$OPENLEDGER_URL$GRAPHQL_PATH" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "mutation($name: String!, $date: Date!) { closeAccount(name: $name, date: $date) }",
  "variables": {
    "name": "Assets:Bank:Checking",
    "date": "2026-12-31"
  }
}
JSON
```
