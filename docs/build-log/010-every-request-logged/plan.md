# Plan: a log line for every request (from intent.md, 2026-11-17)

## Files that change
`crates/gl-node/src/request_log.rs` (the throttle and the `/health` level
removed; `RequestLogState` keeps only the client's twin limiter),
`crates/gl-node/src/ledgers.rs` (`test_node::node_with` loses its log
argument), `scripts/revert_specs/node_logs.json`, README (*Request log*,
*Log volume on a public bind*), CHANGELOG (the unreleased 009 bullets),
`docs/OPERATIONS.md`, `docs/audits/OUTSTANDING_TASKS_11_16.md`.

## Order of work
One unit: the change, its tests and docs.

## Risks
- **Log volume** — the decision above; documented, not mitigated in code.
- A secret or a forged line: unchanged code paths (fields, escaping), and
  009's tests for them stay.
- Nothing touches replication, boot, signatures or the file format.

## Alternatives rejected
- A node-wide cap on strangers' lines (every request in normal traffic, a
  count past ~50 a second): the maintainer chose no cap.
- Every request on a non-public node only: servers would still summarize.

## Proof
- `request_log.rs` tests:
  - `every_request_logs_a_line_of_its_own_strangers_included` (replaces
    `strangers_requests_log_one_line_per_client_per_window`);
  - `strangers_behind_one_proxy_are_logged_with_their_forwarded_address`
    (replaces `…_are_throttled_per_forwarded_client`);
  - `a_passing_health_check_logs_at_info` (replaces `…_at_debug_only`);
  - the others as in 009, a cut-short line without `suppressed=`.
- Revert checks: NL-R5, NL-R6 and NL-R12 retired (the throttle and the
  `/health` level they pinned are gone); new NL-R17 (a request without a
  note left out) and NL-R18 (a passing `/health` left out); NL-R3 also runs
  the forwarded-strangers test.

## Added: strangers' lines under their own target
`request_log.rs` writes a line without a note under `http::stranger`
(`tracing::enabled!` checked per target). The installer's `openledger logs`
matches ` http(::stranger)?: ` for `--http` and drops ` http::stranger: ` for
`--no-strangers`; `run_local_node.sh --no-strangers` appends
`http::stranger=off` to `RUST_LOG` (or to the node's default). Proof:
`stranger_lines_can_be_turned_off_alone` (both targets under the default
filter; `http::stranger=off` keeps only the key holder's; `http=off` keeps
none); NL-R20 (every line under `http`); NL-R19 (a stranger's refusal at
`INFO`) beside NL-R15; the smoke test and a rehearsal check for
`--no-strangers`.

## Added: `openledger request-log` and `--no-request-log`
`deploy/install/install.sh`: the `request-log` arm (in the backup lock; refused
during an unfinished restore or rollback; a hand-written `RUST_LOG` left
alone; the env file rewritten through a temp file at 0600; `docker compose …
up -d node`, then the health check). Recreating the container drops its
earlier `docker logs` lines: documented. `scripts/run_local_node.sh
--no-request-log` (`http=off`, exclusive with `--no-strangers`). Proof: the
offline smoke test (`target/logs_smoke/test_request_log.sh`) and three
rehearsal checks (on by default; `key-holders` logs a keyed request and not a
stranger's; `on` removes the line and the node serves).
