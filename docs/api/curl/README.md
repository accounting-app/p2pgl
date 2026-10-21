# The openledger API with curl

The same requests as the Insomnia collection
([`../openledger.insomnia.json`](../openledger.insomnia.json)), as `curl`
commands: one file per folder of it. Each sends its JSON body through a quoted
heredoc, so the GraphQL and its variables are copied as they are, with no
shell escaping; edit the values under `variables`. The answers go through
`jq .` to be readable (drop it if you have no `jq`).

| File | What |
|---|---|
| [reports.md](reports.md) | Accounts, trial balance, balance sheet, income statement, journal, a transaction, an account's balance, `verify`, health |
| [entries.md](entries.md) | Open and close accounts, append transactions |
| [people.md](people.md) | The access list: grant, change, rename, revoke |
| [health.md](health.md) | `GET /health`, with and without a key |
| [node.md](node.md) | The node endpoint: list, add, restart and remove company ledgers (the operator key) |

## Set these first

```bash
export OPENLEDGER_URL=http://127.0.0.1:4000      # or https://your-domain on an installed server
export OPENLEDGER_KEY=PASTE-A-KEY-HERE           # the operator key, or a person's key
export GRAPHQL_PATH=/graphql                     # the config file's ledger …
# export GRAPHQL_PATH=/ledgers/acme/graphql      # … or a company's
export LEDGER=acme                               # the company the health page names
```

On a server set up by the installer, `sudo openledger key` prints the operator
key. A person's key works only on the ledger that issued it (and gets `401`
elsewhere); people and their keys belong to company ledgers, which sign — the
config file's own ledger keeps no access list (`NO_ACCESS_LIST`).

The requests that need an id (a transaction's `txid`, a person's `user`) carry
a placeholder: paste one from the journal or the access list.
