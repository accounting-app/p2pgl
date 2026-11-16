# Log: node logs, like `heroku logs --tail`

Status: in progress.

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
- **Commit:** 6129b17

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
- **Commit:** —
