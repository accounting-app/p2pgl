# Intent: node logs, like `heroku logs --tail`

Author: Claude, with the maintainer. Status: **approved** (2026-11-09).

## Problem

An operator cannot see the HTTP requests their node serves. Caddy has no
access log, and the node writes a line only for a request its guard refuses
(M-41). When a client says "my posting failed" or "the app is slow", the
operator cannot see whether the request arrived, for which company, from
whom, what it answered or how long it took. Reading the logs that do exist
means knowing `docker logs openledger-node` and wading through colour escape
codes.

## Proposed outcome

- **One line per HTTP request**, written by the node, in the key=value style
  of Heroku's router lines:

  ```
  INFO http: ledger=acme method=POST path=/ledgers/acme/graphql operation=AddTransaction user=u_7f3a… status=200 errors=0 ms=12 client=203.0.113.9
  WARN http: ledger=acme method=POST path=/ledgers/acme/graphql operation=- user=- status=401 errors=0 ms=0 client=198.51.100.4
  ```

  Field names are full words (decision 4); `ms` is the one abbreviation
  kept. `ledger` is the company (`-` for none). `operation` is the GraphQL
  operation name (`-` when the request has none). `user` is the person,
  `operator` or `-` for a request no key let through. `errors` counts the
  GraphQL errors in a 200 answer. `client` is the caller's address as the
  rate limiter works it out.
- **`openledger logs`** on the server shows the node's log: the last lines,
  then exit. `--tail` keeps streaming. `openledger logs acme` shows only
  that company's lines, `--http` only the request lines, and `--since 1h`
  starts from a point in time.
- **The node's log is plain text when it is not on a terminal.** No colour
  codes in `docker logs` or in a log shipper.

## Who it is for

The operator of an installed server (entry 005), at an SSH session. Also
anyone running `gl-node` by hand or in Docker: the request line is the
node's, so it appears wherever the node's log goes.

## Constraints

- **Never the key, the body or the query text.** No `X-Api-Key`, no
  variables, no document and no URL query string (any URL can carry
  `?api_key=…`). Only the fields above. A user id is not a secret: it is 64
  random bits, and the ledger's access records already carry it.
- **A caller cannot forge or flood the log** (M-41, T77). Every
  caller-chosen value (path, method, operation name, ledger name) is checked
  or escaped, including CR and LF, so it can never start a new line, and
  every line is under 512 bytes. Only a request a key let through gets its
  own line. Everything else (strangers, refusals, 429s, unknown paths,
  requests cut short) keeps M-41's bound: one line per client per 10 s with
  the count it stood for, about 13 lines a second at most whatever an
  attacker controls.
- **The audits still hold.** The plan's *Security review against the
  audits* table checks each finding the change touches, and the existing
  revert checks for them must still bite.
- **Nothing the API answers changes**, and nothing a peer sees changes.
  Logging only.
- **No new remote endpoint.** Reading the log stays a server-side action,
  like every other `openledger` command.
- The default filter (`info,iroh::protocol=error`) keeps its meaning.
  `RUST_LOG` can turn the request line off (`http=off`).

## How we will know it worked

- A read key's query on `acme` writes one `INFO` line with `ledger=acme`,
  its user id, its operation name, `status=200` and a duration.
- A request with a wrong key writes a `WARN` line with `user=-` and
  `status=401`.
- Behind the installer's Caddy, `client=` is the caller's address, not
  `127.0.0.1`.
- The key, a variable's value, the query text and a GET query string
  appear nowhere in the captured log.
- A newline in an operation name, a path or a ledger name cannot start a
  second line, in the request line or in any other line the node writes.
- A flood of wrong-key requests writes one line per client per 10 s, with
  the count.
- An untrusted caller's `X-Forwarded-For` does not change its `client=`.
- On an installed server, `openledger logs --http` shows a request just
  made, `openledger logs acme` shows none of another company's lines
  (`acme-eu` included), and `docker logs openledger-node` has no escape
  codes.

## Decisions (maintainer, 2026-11-09)

1. **Health checks.** A `/health` that answers 200 logs at `debug`. Any
   other answer logs at its status's level (decision 3).
2. **On by default.** `RUST_LOG` (`http=off`) is the off switch; no new
   config key.
3. **Level by status.** `INFO` for 1xx–3xx, `WARN` for 4xx and 5xx, and for
   a request cut short. *Changed from the draft* (all at `INFO`):
   OPERATIONS' *What to watch* must say that a request line at `WARN` is a
   refused or failed request, not a fault of the node, and how to filter it
   (`target` `http`) out of an alert on warnings.
4. **Full words in field names.** `operation=`, not `op=`; `cut_short=true`,
   not `cut=1`. `ms` stays. An unnamed operation logs `operation=-`, and a
   name that fails the check logs `operation=?`.
5. **From a laptop** (an operator-only stream over `/node/graphql`): a later
   entry, not this one.
6. **A key holder rotating addresses** (IPv6 /48, L-61) can write as many
   lines as the requests the node already accepts from them; each line
   names their user id, and revoking the key stops it. **Accepted as a
   residual**, documented in the plan and the README. A node-wide cap would
   hide honest traffic during an incident.
7. **The existing echo in `Ledgers::dispatch`** (an unchecked, decoded
   ledger name in a span; plan, *An existing echo*) is fixed **first, as a
   commit of its own**, before the request line.
