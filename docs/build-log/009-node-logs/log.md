# Log: node logs, like `heroku logs --tail`

Status: done (2026-11-16, last commit e5f93ec).

One entry per commit-sized unit, newest last, written when the unit is ready
to commit. The commit hash is filled in once the maintainer has committed.

## 2026-11-16 — The dispatch span shows only a valid name (unit 0)

- **What changed:** `ledgers.rs` `Ledgers::dispatch` — the span around the
  rate limiter (`info_span!("ledger", …)`, where the L-37 and M-21 warnings
  are written) shows the ledger name only when `is_valid_ledger_name` holds,
  `-` otherwise. Before, `/ledgers/x%0A…/graphql` with `X-Forwarded-For`
  from an untrusted peer put the decoded newline into the L-37 warning's
  line and started a forged one. `test_support.rs`: `capture_warnings`
  moved there from `request_guard.rs`'s tests, plus
  `capture_warnings_async`, which keeps `INFO` spans and `WARN` events as
  the node's default filter prints them (a `WARN`-only capture hides the
  span and so the bug). README (multi-ledger node: `ledger=-`), CHANGELOG
  *Security*.
- **Tests:** `an_invalid_name_never_reaches_the_dispatch_span`.
- **Gate:** `scripts/gate.sh` — 1757 passed, 0 failed, 0 ignored.
- **Revert checks:** `scripts/revert_specs/node_logs.json` (new) — 1 of 1
  bite (NL-R14).
- **Tracker:** L-158, task T104, in a new tracker for findings made after
  the audit series, `docs/audits/OUTSTANDING_TASKS_11_16.md` (maintainer's
  choice). `operation=-` for an unnamed operation confirmed for unit 1.
- **Departures from the plan:** the entry is 009, not 007 as first drafted
  (007 and 008 were taken on `main`); test doc comments start `009:`. The
  bug sits at `ledgers.rs:470` on 1a16f2a. The plan placed the
  `capture_warnings` move in unit 1; it came with unit 0, whose test needed
  it. `config.rs` and `p2p_service.rs` keep their own capture helpers.
- **For unit 1** (found by the review): an invalid folder name in
  `ledgersDir` is logged raw (`main.rs:595`). It comes from the filesystem,
  not a caller; unit 1 escapes it.
- **Commit:** 1efb01d (with unit 1; first committed alone as 6129b17)

## 2026-11-16 — The request line (unit 1)

- **What changed:** new `crates/gl-node/src/request_log.rs` — the
  `request_log` middleware, the outermost layer of
  `build_application_with_limiter` (`main.rs`; the routes without it are now
  `application_routes`, which tests wrap with a log of their own). A
  `RequestNote` in the response's extensions gives a request its own line;
  `graphql_handler`, `ledger_admin::node_graphql` and `take_a_slot`'s 503
  attach one. Every other answer goes through a `KeyedRefusalLog` keyed on
  `bucket_key` of the client `RateLimiter::client_of` works out (on a twin of
  the node's limiter), with a `WARN` summary when each window closes. A drop
  guard writes `status=- cut_short=true`. Levels: `INFO` below 400, `WARN`
  for 4xx, 5xx and cut short, `DEBUG` for a passing `/health`; a line the
  filter drops spends no window. `escaped` writes every control and
  whitespace character as `\u{…}` and cuts to 128 bytes; `main.rs` uses it
  for an invalid `ledgersDir` folder name. `main.rs`: `.with_ansi` only on a
  terminal. `Cargo.toml`: `percent-encoding` (already compiled in through
  axum). `ledgers.rs`: the tests' `node()` moved to `test_node`, with
  `node_with` and `hold_every_slot`. `test_support.rs`: `capture_logs`.
  README *Request log* and *Log volume on a public bind*; CHANGELOG *Added*
  and *Security*; OPERATIONS *What to watch* (*Requests*).
- **Tests:** in `request_log.rs`, the twelve of the plan's *Proof*; in
  `shipped_binary.rs`, `the_shipped_binary_logs_each_request_in_plain_text`.
- **Gate:** `scripts/gate.sh` — 1770 passed, 0 failed, 0 ignored.
- **Revert checks:** `scripts/revert_specs/node_logs.json` — 16 of 16 bite
  (NL-R1 to NL-R16). Three existing anchors moved with the code they name
  (`ledgers.json` L-R14, L-R51; `users.json` U-R7), same mutations; all three
  still bite.
  With the layer in place, the plan's re-run: `ledgers.json` 55 of 55,
  `h01_l23.json` 7 of 7 and `audit_0927.json` 30 of 30 bite (verifier).
- **Review:** no important findings. Taken: `graphql_handler` attaches its
  note only with a caller (fail-closed by construction, as `take_a_slot`;
  NL-R2's anchor follows); README and OPERATIONS say a `cut_short` posting
  may still have landed (a mutation runs to its end), that an auth-off
  loopback node logs everyone as `operator`, and that a cut path is marked
  `…`; the strangers test's window is 8 s, not 4. Left: `http=off` also
  matches any target starting `http` (EnvFilter matches targets by prefix;
  negligible today); `node_graphql`'s note has no revert check of its own
  (losing it costs only the operator's `/node/graphql` lines).
- **Departures from the plan:**
  - `operation` is the `operationName` the client sent; the document is not
    parsed for a name, so a named query sent without `operationName` logs
    `-`.
  - A throttled line ends `suppressed=N`, as the guard's lines do, which
    tells it from a line of its own.
  - `escaped` escapes whitespace as well as control characters (U+2028 is
    not a control character, and some viewers break lines on it).
  - `client_ip` stays private: `RateLimiter::client_of` already gave the
    same answer, `pub(crate)`.
  - NL-R12 keys the throttle on `127.0.0.1` — the TCP peer of every client
    behind the installer's Caddy — since the layer keeps no peer of its own
    to revert to. NL-R16 is new: the busy 503 without its note.
  - Unit 0's test now allows the request line's own L-37 warning, outside
    the span, beside the one in it; it still asserts that no line starts
    with the forged text (NL-R14 bites).
- **Commit:** 1efb01d (with unit 0)

## 2026-11-16 — `openledger logs` (unit 2)

- **What changed:** `deploy/install/install.sh` — `openledger logs [COMPANY]
  [--tail] [--since TIME] [--http] [-n N]` and its usage lines. It runs
  `docker logs [--follow] [--since T] --tail N openledger-node` from an
  argument array: `N` digits only (default 200), `TIME` a number and `s`,
  `m`, `h` or `d` (days become hours: docker takes Go durations, which have
  none), `COMPANY` by the ledger-name rule before it reaches grep. The
  company pattern is `ledger="?COMPANY"?([ },:]|$)`, so `acme` leaves out
  `acme-eu`; `--http` keeps ` http: ` lines. Every stage is line-buffered; a
  grep that matches nothing is not a failure; the last stage drops every
  control character but tab and newline. `scripts/rehearse_install.sh`: the
  plan's checks (a request from the VM's own address shows with
  `client=<that address>`; `acme` against `acme-eu` and `default`; `--tail`
  under `timeout`; `'a|b'` and `--since '1h;x'` refused; neither key in the
  log; no escape codes in `docker logs`). README (the install summary,
  *Request log*), OPERATIONS (the command table, *Requests*), CHANGELOG
  *Added*.
- **Tests:** the installer has none in the gate (it is rehearsed on Lima
  VMs). Smoke test, offline: the `openledger` command as the installer
  writes it, run in the 0.4.0 image (Debian 12, bash 5.2) against a fake
  `docker` printing node lines with escape codes and a CR — 35 of 35: the
  filters (`acme` leaves out `acme-eu` and `other_ledger=acme`), the
  arguments docker gets, thirteen refused arguments that never reach
  docker, a missing container said, `--tail` streaming a later line, and
  nothing left running after `timeout`. The harness is not kept in the
  repo (`target/logs_smoke/`).
- **Rehearsal:** `scripts/rehearse_install.sh` — passed on ubuntu-24.04 and
  debian-12 (74 checks, 37 each), after the review's fixes: the request
  from the VM's own address logged `client=192.168.5.15`, its user id and
  `operation=Books`; `openledger logs acme` left out `acme-eu`'s and
  `default`'s lines; `--tail` streamed a later request; both refusals were
  `openledger`'s own; no key in the log; no escape codes in `docker logs`.
- **Gate:** `scripts/gate.sh` — 1770 passed, 0 failed, 0 ignored (after the
  review's fixes).
- **Review:** no important findings. Taken: the rehearsal's colour check
  reads a captured log (a `grep -q` closing the pipe early, with
  `pipefail`, read as a pass under `!`); the refusal checks match
  `openledger`'s own message (docker refuses `1h;x` too); the `acme`
  check first asserts `acme-eu`'s and `default`'s lines are there; a
  missing container is said before a filter can hide docker's error; the
  company pattern takes the field `ledger` only (`(^|[ {])ledger=`, not
  `other_ledger=acme`); `-n` and `--since` take at most 9 and 6 digits;
  the usage, README and OPERATIONS say a filter keeps its lines among the
  last N, and that strangers' requests are throttled.
- **Revert checks:** none: the gate's revert checks run cargo tests, and the
  installer has none (as for 005's installer steps).
- **Also:** `scripts/run_local_node.sh --source` builds the working tree
  and runs it (the newest release, its default, predates the request
  line); tried with a loopback config, Plaid off: the keyed request's line
  and a wrong key's throttled one, no key in the log, Ctrl-C stops it.
  README *Bank connections (Plaid)*, the sentence on the script.
- **Departures from the plan:** `--since` takes days as hours; the company
  pattern also takes a quoted name (`ledger="acme"`, a `?` field), and the
  field `ledger` only.
- **Commit:** e5f93ec
