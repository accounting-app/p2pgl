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
| T105 | L-159 | Low | ☑ |

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

**Commit:** 1efb01d (with 009 unit 1).

**Done in 009 unit 1.** A folder in `ledgersDir` whose name is not a valid
ledger name is logged raw (`error!(ledger = %name, …, "ledger not served")`,
`crates/gl-node/src/main.rs:595`). The name comes from the server's
filesystem, not a caller, so it is not a finding. 009's intent ("a newline in
… a ledger name cannot start a second line … in any other line the node
writes") covers it; unit 1 escapes it (`request_log::escaped`).

## ☑ T105 — No shipped image sets `RUST_LOG` (L-159) — S

**L-159 — The images replace the node's log filter, undoing L-72's.** Found
2026-11-17 while checking how an installed server is configured. The node's
default filter is `info,iroh::protocol=error` (`main.rs`,
`DEFAULT_LOG_FILTER`; T77), and an explicit `RUST_LOG` replaces it whole.
The repository's `Dockerfile` set `ENV RUST_LOG=info` (since 2026-07-25,
before T77), and so did the image the installer builds (`install.sh`, since
2026-10-20, 005) and the demo `deploy/docker-compose.yml`. So every node run
from an image logged iroh's protocol-router warnings again: one `WARN` per
failed inbound handshake (an unknown ALPN's `accepting failed`, a handshake
aborted by the peer), unthrottled, from anyone who dials the node's public
QUIC port — the half of L-72 its fix left to the filter (0923 measured
≈ 57 KB from 200 bad-ALPN dials in a second). On an installed server those
lines share Docker's 10 MB × 5 rotation with every other line, request lines
included.

**Why Low.** As L-72: the log only — no answer, ledger, peer or key is
affected, and a dial costs the dialer a TLS handshake each. Docker's rotation
bounds the disk, but not what is pushed out of it: at 0923's ≈ 83 KB/s from
eight dialers, the 50 MB are rotated away in about ten minutes, and the
request lines (009) with them.

**Fix.** Neither image nor the demo stack sets `RUST_LOG`; the node's own
default applies. An operator who sets one still replaces it, as the README
says (*Log volume on a public bind*). An installed server takes it when it
upgrades to a release that has it: the installer tags its image by the
binary's digest and the base image, so a new binary builds a new image from
the new installer — with `openledger upgrade --version X.Y.Z`, which fetches
that release's installer. **Residuals:**

- `openledger upgrade --binary FILE` alone runs the installer already on the
  server: on a server installed before this fix, that one still writes
  `RUST_LOG=info` into the new image. Upgrade with `--version`, or give
  `--binary FILE --installer NEW_INSTALL_SH`.
- Re-running an installer with the same binary keeps the image it already
  has (the tag is the binary's digest and the base image, not the image's
  definition); a rollback runs the previous release's image, as it should.
- Nothing pins `main`'s fallback to `DEFAULT_LOG_FILTER` when `RUST_LOG` is
  unset (`main.rs`, the subscriber's `EnvFilter`): T77's test builds its
  filter from the constant. A gap since T77, not opened here.

`deploy/iroh-relay/Dockerfile` keeps its `RUST_LOG=info`: it runs
`iroh-relay`, not the node, which has no such default.

**Proof.**
- Test: `config::tests::l159_no_shipped_image_sets_rust_log` reads the three
  files and refuses any line that sets `RUST_LOG`. What the default filter
  does to iroh's lines is pinned already (T77:
  `l72_refused_dials_on_a_public_bind_cost_at_most_one_line`).
- Revert checks: L159-R1 (`Dockerfile`), L159-R2 (`install.sh`'s image) and
  L159-R3 (`docker-compose.yml`) in `scripts/revert_specs/node_logs.json`,
  each `RUST_LOG=info` put back: 3 of 3 bite.
- CHANGELOG `[Unreleased]` *Security*.

**Commit:** —

## Accepted by the maintainer

**MA-1 (2026-11-17) — The request line is not bounded (build-log 010).**
(MA: accepted by the maintainer, not `RESIDUALS.md`'s A-series.) 009
gave a line of its own only to a request a key let through and held every
other answer to M-41's budget (one line per client per 10 s, the count at
expiry: about 13 lines a second whatever a stranger sends). The maintainer
chose a line for every request instead, with no cap (over a node-wide cap,
and over every request on non-public nodes only), and a passing `/health` at
`INFO`. So a caller with no key writes one line (under 512 bytes) per request
it sends, as fast as it sends them, and a flood can rotate Docker's
10 MB × 5 away in minutes, older lines with it. What M-41 also asked for
still holds: every caller-chosen value is checked or escaped (no forged
line), every line is under 512 bytes, and the request guard's own refusal
lines, which echo header values, keep their throttle. README *Request log*
and *Log volume on a public bind* say so, with the advice to rate-limit in
front of a public node or in the log shipper.
