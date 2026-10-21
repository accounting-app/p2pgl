# Health

GET /health answers anyone; the detail (version, heads, peers) needs a key on a public node.

Set the variables first: [README](README.md).

## Health (no key)

```bash
curl -s "$OPENLEDGER_URL/health" | jq .
```

## Health (with key: version, heads, peers)

```bash
curl -s "$OPENLEDGER_URL/health" \
  -H "X-Api-Key: $OPENLEDGER_KEY" | jq .
```

## A company's health (needs a key it accepts)

```bash
curl -s "$OPENLEDGER_URL/ledgers/$LEDGER/health" \
  -H "X-Api-Key: $OPENLEDGER_KEY" | jq .
```
