# Outstanding Security Tasks — 2026-11-16

Findings made after the audit series ended (2026-09-28), in feature work rather
than by an audit. Nothing here is a dated audit report's: the reports stay
records. Finding IDs continue from [SECURITY_AUDIT_0927.md](SECURITY_AUDIT_0927.md)
(*Next IDs: H-26 / M-77 / L-158*), task numbers from
[OUTSTANDING_TASKS_09_27.md](OUTSTANDING_TASKS_09_27.md) (T98–T103). Every
finding those numbered is closed ([RESIDUALS.md](RESIDUALS.md)).

**Status legend:** ☐ not started · ◐ in progress · ☑ done
**Effort:** S = < ½ day, M = ~1–2 days.

| Task | Finding | Severity | Status |
|---|---|---|---|
| T104 | L-158 | Low | ☑ (009 unit 0) |

## ☑ T104 — The dispatch span shows only a valid ledger name (L-158) — S

**L-158 — A caller's ledger name, percent-decoded and unchecked, in a log
span.** Found 2026-10-28 while reviewing the plan for build-log 009 (node
logs). `Ledgers::dispatch` (`crates/gl-node/src/ledgers.rs`, line 470 at
`1a16f2a`) opened `info_span!("ledger", ledger = %name)` around the GraphQL
rate limiter, with `name` from axum's `Path`: percent-decoded, and not yet
checked against `is_valid_ledger_name`. Two warnings are written inside that
span: the L-37 untrusted-forwarder warning and the M-21 overflow warning.
tracing-subscriber 0.3.23 does not escape CR or LF in a field value, so
`/ledgers/x%0A…/graphql` started a forged line in the node's log, up to about
64 KiB long (hyper's head buffer). This is M-41's class (a caller's bytes in a
log line), in a place M-41's fix did not reach.

**Why Low.** No answer, ledger or peer is affected, only the log. L-37 fires
once per process, so any stranger forges one line, once, by sending
`X-Forwarded-For` from a peer not in `trustedProxies`. M-21's line fires once
per window, and only while the client table is full (65,536 clients on the
`default` ledger, 8,192 on a folder ledger).

**Fix.** The span shows the name only when `is_valid_ledger_name(name)` holds
(`[a-z0-9-]`, 1–40 bytes, no control character possible), and `-` otherwise.
The second span, around `oneshot`, and the Plaid webhook's span are opened
for served names only and were already safe.

**Proof.**
- Test: `ledgers::tests::an_invalid_name_never_reaches_the_dispatch_span`
  (the L-37 warning firing for a `%0A` name: shown in `ledger{ledger=-}`,
  and no line starts with the forged text; since 009 unit 1 the request
  line's own L-37 warning may come first, outside the span). It captures
  with `test_support::capture_warnings_async`, which keeps `INFO` spans as
  the node's default filter prints them; a `WARN`-only capture hides the
  span, and the bug with it.
- Revert check: NL-R14 in `scripts/revert_specs/node_logs.json` bites.
- CHANGELOG `[Unreleased]` *Security*; `docs/build-log/009-node-logs/log.md`.

**Commit:** 6129b17.

**Done in 009 unit 1.** A folder in `ledgersDir` whose name is not a valid
ledger name is logged raw (`error!(ledger = %name, …, "ledger not served")`,
`crates/gl-node/src/main.rs:595`). The name comes from the server's
filesystem, not a caller, so it is not a finding. 009's intent ("a newline in
… a ledger name cannot start a second line … in any other line the node
writes") covers it; unit 1 escapes it (`request_log::escaped`).
