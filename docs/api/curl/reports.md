# Books: reports

Read-only: any key the ledger accepts (read role or above).

Set the variables first: [README](README.md).

## Accounts (chart of accounts)

```bash
curl -s -X POST "$OPENLEDGER_URL$GRAPHQL_PATH" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "{ accounts { name openedOn closedOn currencies } }",
  "variables": {}
}
JSON
```

## Trial balance

```bash
curl -s -X POST "$OPENLEDGER_URL$GRAPHQL_PATH" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "query($at: Date!) { trialBalance(at: $at) { at totalDebit totalCredit exact rows { account debit credit exact } } }",
  "variables": {
    "at": "2026-12-31"
  }
}
JSON
```

## Balance sheet

```bash
curl -s -X POST "$OPENLEDGER_URL$GRAPHQL_PATH" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "query($at: Date!) { balanceSheet(at: $at) { at exact assets { account balances { number currency } exact } liabilities { account balances { number currency } exact } equity { account balances { number currency } exact } } }",
  "variables": {
    "at": "2026-12-31"
  }
}
JSON
```

## Income statement

```bash
curl -s -X POST "$OPENLEDGER_URL$GRAPHQL_PATH" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "query($from: Date!, $to: Date!) { incomeStatement(from: $from, to: $to) { from to exact net { number currency } income { account balances { number currency } } expenses { account balances { number currency } } } }",
  "variables": {
    "from": "2026-01-01",
    "to": "2026-12-31"
  }
}
JSON
```

## Journal

```bash
curl -s -X POST "$OPENLEDGER_URL$GRAPHQL_PATH" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "query($account: String, $from: Date, $to: Date, $limit: Int!, $offset: Int!) { journal(account: $account, from: $from, to: $to, limit: $limit, offset: $offset) { txid date flag payee narration tags links enteredBy enteredByName postings { account amount { number currency } } } }",
  "variables": {
    "account": null,
    "from": null,
    "to": null,
    "limit": 100,
    "offset": 0
  }
}
JSON
```

## Transaction by txid (paste one from the journal)

```bash
curl -s -X POST "$OPENLEDGER_URL$GRAPHQL_PATH" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "query($txid: TxId!) { transaction(txid: $txid) { txid date flag payee narration postings { account amount { number currency } } author signature parents enteredByName } }",
  "variables": {
    "txid": "0000000000000000000000000000000000000000000000000000000000000000"
  }
}
JSON
```

## Account balance

```bash
curl -s -X POST "$OPENLEDGER_URL$GRAPHQL_PATH" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "query($name: String!, $at: Date) { account(name: $name, at: $at) { account exact balances { number currency } } }",
  "variables": {
    "name": "Assets:Bank:Checking",
    "at": null
  }
}
JSON
```

## Verify (DAG integrity)

```bash
curl -s -X POST "$OPENLEDGER_URL$GRAPHQL_PATH" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "{ verify { ok nodesChecked errors truncated quarantined quarantinedTotal unparsableBlocks balanceAssertions { evaluated passed failed ok failures { account date expected actual currency } } } }",
  "variables": {}
}
JSON
```

## Node health (GraphQL)

```bash
curl -s -X POST "$OPENLEDGER_URL$GRAPHQL_PATH" \
  -H "Content-Type: application/json" \
  -H "X-Api-Key: $OPENLEDGER_KEY" \
  -d @- <<'JSON' | jq .
{
  "query": "{ health { status heads peers version } peers { id } }",
  "variables": {}
}
JSON
```
