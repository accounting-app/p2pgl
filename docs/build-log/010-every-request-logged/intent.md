# Intent: a log line for every request

Author: Claude, with the maintainer. Status: **approved** (2026-11-17, the
maintainer's choices).

## Problem
009's request log gives a line of its own only to a request a key let
through. Everything else — a wrong key, a 404, a preflight, a webhook, a
`/health` — gets one line per client per 10 s and a count, and a passing
`/health` is written at `DEBUG`, hidden by default. The maintainer wants to
see every request.

## Proposed outcome
- **Every HTTP request writes one line**, strangers' included: no per-client
  window, no `suppressed=N`, no summary lines.
- **A passing `/health` is `INFO`** like every other answer below 400
  (reverses 009's decision 1).
- The fields are 009's: `user` and `operation` come from a request a key let
  through, and are `-` otherwise. The level follows the status: `INFO` below
  400, `WARN` for 4xx, 5xx and a request cut short.

## Who it is for
The operator reading `openledger logs` or `docker logs`, and a developer
running `scripts/run_local_node.sh`.

## Constraints
- Unchanged from 009: no key, header, body, query text, variables or query
  string; every caller-chosen value checked or escaped (CR and LF included);
  every line under 512 bytes; `RUST_LOG=…,http=off` turns the lines off.
- The request guard's own refusal lines stay throttled: they echo header
  values (M-41's first half), which this does not touch.
- Nothing the API answers changes.

## How we will know it worked
- Sixty-odd requests from one stranger (wrong keys, a 429, a guard refusal,
  a preflight, a 413, a 404, a 405) write as many lines, none with
  `suppressed=`.
- `GET /health` writes an `INFO` line at the default filter.

## Decision recorded (maintainer, 2026-11-17)
**M-41's bound no longer covers the request line.** An unauthenticated caller
writes one line (≤ 512 B) per request it sends, as fast as it sends them; a
flood can rotate Docker's 50 MB away in minutes, older lines with it. Chosen
over a node-wide cap and over every-request-on-local-nodes-only. Recorded in
`docs/audits/OUTSTANDING_TASKS_11_16.md` and the README.

## Added (maintainer, 2026-11-17)
**Strangers' lines can be turned off alone.** A request no key let through
logs under its own target, `http::stranger`, so
`RUST_LOG=…,http::stranger=off` leaves those out and keeps the key holders'
(`http`); `http=off` still turns every request line off. No new config key
(009's decision 2). `openledger logs --no-strangers` and
`scripts/run_local_node.sh --no-strangers` do the same when reading or
running. Chosen over a config key and over a reading-only filter, in this
entry rather than a new one.

## Added (maintainer, 2026-11-17): the switches
**On by default, switched off by a command.** On a server,
`openledger request-log on|off|key-holders` writes (or removes) the
`RUST_LOG` line in `/opt/openledger/env` and recreates the node's container;
alone, it says which is set. Locally, `scripts/run_local_node.sh
--no-request-log` beside `--no-strangers`. `RUST_LOG` stays the one
mechanism underneath: no node change. Chosen over a node environment
variable and over a config key.
