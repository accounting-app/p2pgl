# Plan: node logs (from intent.md, 2026-10-28; decisions 2026-11-09)

## Design

**The request line: a middleware on the node's router.** A new
`crates/gl-node/src/request_log.rs` holds one `axum` middleware. It is the
outermost layer of `build_application_with_limiter` (`main.rs`, outside CORS
and the body limit), so it sees every response the router makes. It writes
with an explicit `target: "http"`, so `RUST_LOG=…,http=off` turns it off.

**Full line or throttled line — decided fail-closed.** The layer sits outside
the guard and every limiter, which is M-41's shape: a line per request there
would be a log echo outside every budget. So a request gets its **full line**
only when it carries a `RequestNote`. Only code behind a key sets that note:
`graphql::graphql_handler`, `ledger_admin::node_graphql`, and
`ledgers::take_a_slot` on its 503 `LEDGER_BUSY` (the "the app is slow"
case). These run after `auth_middleware` or `operator_only` (review: auth is
node-wide, `ledger_runtime.rs`, and auth off is refused whenever
`is_public()`). Every other response goes through a new
`connection_limiter::KeyedRefusalLog` keyed by
`bucket_key(client_ip(peer, headers))`: the forwarded client, **not** the
TCP peer the guard's throttle keys on, which behind the installer's Caddy is
`127.0.0.1` for everyone. That is the M-41/T77 throttle: one line per client
per 10 s, a summary of the count at expiry, and at most 64 sources plus one
overflow window, about 13 lines a second whatever an attacker controls. The
other responses include:

- strangers' 401s;
- 429s;
- guard refusals (403/415);
- CORS preflights `CorsLayer` answers itself;
- 413s from the body limit;
- 405s and the router's 404;
- the operator's 404 and 503 from `dispatch`, and its 400;
- extractor rejections;
- the GraphiQL page and every `/health` answer;
- cut-short requests.

A new path that reaches no handler is throttled by default; nothing has to
remember to mark it. This is a second ~13 lines/s bound beside the guard's,
not a share of it: a guard refusal now writes two throttled lines (the
guard's `warn!` and the request line), at most ~13 KB/s more node-wide.

**Cut short.** `serve_hardened`'s `TimeoutLayer` (408) sits *outside* the
router and drops the inner future, and so does a client that hangs up. A
drop guard in the middleware writes `status=- cut_short=true` for a request
that never finished, through the throttle, since no note was set.

**Level by status** (decision 3). `INFO` for 1xx–3xx; `WARN` for 4xx, 5xx
and a request cut short; and `DEBUG` for a `/health` that answers 200
(decision 1). The throttle's expiry summaries are `WARN`: they only ever
count refused or unbudgeted requests.

**Fields**, in this order: `ledger method path operation user status errors
ms client`, plus `cut_short=true` when it applies. Names are full words
(decision 4); `ms` is the one abbreviation kept. Every value is either a
constant or checked, and the whole line stays under 512 bytes, M-41's bar.

- **`path`** is `uri.path()` only, **never the query string**: any URL can
  carry `?api_key=…` or a document a client put there. (The node itself
  takes GraphQL only by POST; GraphiQL's GET ignores the query and is
  served only on non-public nodes.) A known route is written as it is. Any
  other path is escaped (below) and then cut to 128 bytes on a char
  boundary.
- **`method`** is the standard method's name (`GET`, `POST`, `OPTIONS`, …)
  and `?` for anything else. http 1.x accepts an extension method of any
  length up to hyper's 64 KiB head buffer, so the method is chosen by the
  caller, not the server (review).
- **`ledger`** is `default` for `/graphql` and `/health`. For
  `/ledgers/NAME/…` it is NAME **percent-decoded as axum's `Path` decodes
  it**, so `/ledgers/acm%65/graphql`, which serves `acme`, logs
  `ledger=acme` and cannot hide from `openledger logs acme`, when the
  decoded name passes `is_valid_ledger_name`. Anything else is `-`.
- **`operation`** is the GraphQL operation name when it is a GraphQL `Name`
  of at most 64 characters, `-` when there is none, and `?` otherwise.
- **`user`** is `operator`, the `u_…` id, or `-`, written by a function that
  matches on `CallerId`, never by `?caller`. User ids are 64 random bits
  (`access_list::new_user_id`), not derived from a key.
- **`client`** is `RateLimiter::client_ip` (made `pub(crate)`) on a twin of
  the node's limiter. It uses the rightmost-untrusted rule with L-36's cap,
  so `X-Forwarded-For` from a peer not in `trustedProxies` is ignored and an
  untrusted caller cannot choose its `client=`.
- **`errors`** is the count of the GraphQL response's errors, not their
  messages. **`ms`** comes from the server.
- **Escaping** is our own: every `char::is_control` (including `\n`, `\r`
  and `\t`) becomes `\u{…}`. tracing-subscriber 0.3.23 escapes ESC, BEL, BS,
  FF, DEL and C1 by default (`fmt/format/escape.rs`), but **not** CR or LF,
  so its escaping alone would let a path or name start a forged line.

**An existing echo, fixed first** (decision 7). `Ledgers::dispatch` opens
`info_span!("ledger", ledger = %name)` around `allow_request` with the
decoded name **unchecked** (`ledgers.rs:470` at 1a16f2a). The L-37 warning and the
M-21 overflow warning fire inside that span, so `/ledgers/x%0A…/graphql`
can start a forged line today, up to ~64 KiB long (review, 2026-10-28). The
span records the name only when `is_valid_ledger_name`, and `-` otherwise.
The second span, around `oneshot`, runs for served names only and is
already safe.

**Plain text off a terminal.** `main.rs` builds the subscriber with
`.with_ansi(std::io::stdout().is_terminal())`; 0.3.23 otherwise writes
colour codes into `docker logs` around every field name.

**`openledger logs`** goes in `deploy/install/install.sh`, beside `status`
(root, like every `openledger` command):

```
openledger logs [COMPANY] [--tail] [--since TIME] [--http] [-n N]
```

It runs `docker logs [--follow] [--since=T] --tail N openledger-node 2>&1`,
built as an argument array. `N` is digits only (default 200), and `T` must
match `^[0-9]+[smhd]$`. `COMPANY` passes the ledger-name rule before it
reaches grep, so it cannot become a regex, and the pattern is
`ledger=COMPANY([ }]|$)`: span lines read `ledger{ledger=acme}:`, and
`grep -w` would not keep `acme` from matching `acme-eu`, since `-` is not a
word character. Every stage is line-buffered (`grep --line-buffered`, and
`stdbuf -oL` on the rest), or `--tail` stalls behind a pipe buffer. A grep
that matches nothing is not a failure under `pipefail`. The last stage is
`stdbuf -oL tr -d '\000-\010\013-\037\177'`, which drops every C0 control
but tab and newline, so the operator's terminal is safe even if some line
ever carries an escape. C1 controls in UTF-8 are two bytes `tr` cannot
target. The node's own lines never carry them: tracing escapes C1 in every
field value.

## Order of work

Three commit-sized units, each passing `scripts/gate.sh`:

0. **The dispatch span fix** (decision 7): `ledgers.rs`, the test
   `an_invalid_name_never_reaches_the_dispatch_span`, revert check NL-R14,
   and CHANGELOG *Security*. It is small and stands alone, and it closes an
   echo open today without waiting for the feature.
1. **The request line** (Rust): `request_log.rs`, the notes in the GraphQL
   handlers and `take_a_slot`, the drop guard, the levels, ANSI off a
   terminal, the tests and revert checks, README (with decision 6's
   residual) and CHANGELOG, and OPERATIONS' *What to watch* (decision 3).
2. **`openledger logs`** (installer): the command, its usage line, the
   rehearsal checks, the OPERATIONS rows, and the CHANGELOG.

## Security review against the audits

| Finding | The rule | How this plan holds it |
|---|---|---|
| M-41, T66, T77 | No caller-controlled log line outside a budget; echoes bounded (< 512 B) | Full lines only behind a key; all else through a second T77 throttle keyed on the forwarded client (~13 lines/s); every field checked, escaped and cut, the method included; line < 512 B |
| M-41 (CR/LF) | A caller cannot forge lines | Own escaping of every control char (tracing's does not cover CR/LF); **and the unchecked name in `dispatch`'s span, an open echo today, is fixed** |
| H-01, L-50, M-32, L-23, L-56 | Never log a key or a quasi-credential | Named fields only; no headers, body, query string, document or variables; a test scans all output; topic and meshId untouched |
| M-04, L-36, L-37 | Client identity per trusted proxy; XFF capped; untrusted XFF ignored | `client_ip` reused, not reimplemented; a spoof test |
| 003 (name probing) | A stranger cannot tell a served name from a wrong key | Responses unchanged (logging only); `ledgers.json` revert checks re-run with the layer in place |
| L-09, L-42 | `/health` discloses nothing new; stays guarded and limited | Layer adds no route and changes no answer |
| M-13, M-22, M-33 | Timeouts and connection caps unchanged | `serve_hardened` untouched; a cut-short request still gets a (throttled) line |
| M-21, 003 budgets | A key holder's requests are budgeted | Their lines are bounded by their GraphQL budget, 60/min per client per ledger: one ~300 B line per request whose execution already costs far more |
| L3 / T12 | No internal detail leaks | Error count only, never messages (which may carry paths server-side) |

**Residual for the maintainer to accept:** a key holder rotating through
many addresses (IPv6 /48, L-61) gets a budget per bucket, up to 65,536 on
the `default` ledger and 8,192 on a folder ledger (`LEDGER_MAX_BUCKETS`),
plus the M-21 overflow, so their lines are bounded by the request rate the node
already accepts from them, not by a log cap. Each line names their user id,
and revoking the key stops it. The Docker rotation (10 MB × 5) bounds disk,
not how fast old lines are pushed out. A node-wide cap on full lines was
considered and rejected: it would hide honest traffic exactly when an
operator needs to see it.

## Risks

- **Leaking a secret into the log** — the worst outcome. Named fields only.
  A test scans *all* captured output for the key, a variable value, the
  query text and a GET query string.
- **Fail-open throttling** — if a full line could be produced without a key,
  M-41 reopens. The note is the only switch, and it is set only after auth.
  NL-R5 pins this.
- **Colour off changes the log's bytes.** Noted in the CHANGELOG.
- **Personal data.** Client addresses and user ids stay as long as Docker's
  rotation keeps them; root reads them. OPERATIONS says so.
- Nothing here touches replication, boot, signatures or the file format.

## Alternatives rejected

- **Caddy's access log:** it knows neither the user nor the operation, it
  writes `X-Api-Key` unless that is filtered (Caddy redacts only
  `Authorization`, `Cookie` and kin), and it logs the full URL, query
  string included.
- **Marking the unbudgeted responses (the first draft):** fail-open. Each of
  the paths above needed its own marker, and CorsLayer's preflight and the
  outer `TimeoutLayer` could not carry one.
- **`tower_http::trace::TraceLayer`:** a span, not this line. It would
  still need the note, the escaping and the throttle.
- **A config key (`http.requestLog`):** a second switch beside `RUST_LOG`.

## Proof

- Tests in `request_log.rs`, each doc comment starting `009:` and ending
  `Bug-catch:`, capturing with `test_support.rs`'s `capture_warnings` (moved
  there from the request guard's tests in unit 0):
  - `a_keyed_request_logs_one_line_with_ledger_user_operation_and_status`
  - `strangers_requests_log_one_line_per_client_per_window` (wrong key, 429,
    guard refusal, preflight, 413, 404 and 405 in a loop; the count reported)
  - `the_log_never_carries_the_key_the_variables_the_query_or_a_query_string`
  - `the_client_is_the_forwarded_address_only_behind_a_trusted_proxy`
  - `strangers_behind_one_proxy_are_throttled_per_forwarded_client`
  - `a_control_character_in_a_path_or_operation_name_cannot_start_a_line`
  - `every_line_is_under_512_bytes` (longest path, operation name and
    extension method)
  - `a_percent_encoded_ledger_name_logs_as_the_ledger_it_serves`
  - `a_busy_ledger_logs_the_key_holders_503_in_full`
  - `a_request_cut_short_still_logs_a_throttled_line`
  - `a_passing_health_check_logs_at_debug_only`
  - `the_level_follows_the_status` (200 at `INFO`, 401 and 503 at `WARN`)
- Unit 0, in `ledgers.rs`: `an_invalid_name_never_reaches_the_dispatch_span`
  (a `%0A` name with the L-37 warning firing: one line, no forged second).
- `shipped_binary.rs`: `the_shipped_binary_logs_each_request_in_plain_text`
  (stdout piped, one keyed request, the line is present, no `\x1b`).
- `scripts/rehearse_install.sh`: `openledger logs --http` shows a request
  just made with the caller's address; with companies `acme` and `acme-eu`,
  `openledger logs acme` leaves out `acme-eu`'s and `default`'s lines;
  `--tail` streams a new request under `timeout`; `openledger logs 'a|b'`
  and `--since '1h;x'` are refused; no 64-hex key appears in the output.
- Revert checks, `scripts/revert_specs/node_logs.json`:
  - NL-R1: the layer removed.
  - NL-R2: the note not set by `graphql_handler`.
  - NL-R3: `peer_of` used for `client`.
  - NL-R4: the operation name logged unchecked.
  - NL-R5: a full line for a request without a note.
  - NL-R6: health at `info`.
  - NL-R15: every line at `INFO` whatever its status.
  - NL-R7: ANSI always on.
  - NL-R8: `uri` logged instead of `uri.path()`.
  - NL-R9: the escaping left to tracing.
  - NL-R10: the drop guard removed.
  - NL-R11: the method logged as sent.
  - NL-R12: the throttle keyed on `peer_of`.
  - NL-R13: the ledger name taken from the raw path.
  - NL-R14: `dispatch`'s span given the unchecked name again.
- After unit 1: the existing `ledgers.json`, `h01_l23.json` and
  `audit_0927.json` revert checks still bite with the layer in place.
- Docs: README gets a *Request log* section beside *Log volume on a public
  bind*, which also gains the throttled-line bullet. CHANGELOG gets *Added*
  (with plain text off a terminal noted) and *Security* (what is never
  logged). OPERATIONS gets an `openledger logs` row, the retention note,
  and a *What to watch* note: a `WARN` with target `http` is a refused or
  failed request, not a node fault, and an alert on warnings should filter
  it out.
