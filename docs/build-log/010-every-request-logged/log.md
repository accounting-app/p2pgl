# Log: a log line for every request

Status: in progress.

One entry per commit-sized unit, newest last, written when the unit is ready
to commit. The commit hash is filled in once the maintainer has committed.

## 2026-11-17 — Every request logged, `/health` at `INFO`

- **What changed:** `crates/gl-node/src/request_log.rs` — the throttle is
  gone: every request writes its line, at `INFO` below 400 (a passing
  `/health` included) and `WARN` for 4xx, 5xx and a request cut short; no
  `suppressed=`, no expiry summaries. `RequestLogState` keeps only the twin
  limiter that works out `client`; `is_health` and the `DEBUG` level went.
  `ledgers.rs`: `test_node::node_with` takes no log. `test_support.rs`: the
  capture helpers rebuild tracing's interest cache once their subscriber
  exists (below). README (*Request log*, *Log volume on a public bind*),
  CHANGELOG (the unreleased 009 bullets rewritten), OPERATIONS (*Requests*,
  the command table), the tracker (MA-1).
- **Tests:** `every_request_logs_a_line_of_its_own_strangers_included`,
  `strangers_behind_one_proxy_are_logged_with_their_forwarded_address`,
  `a_passing_health_check_logs_at_info` replace the three throttle and
  `DEBUG` tests; `a_request_cut_short_still_logs_a_line` renamed; the rest
  as in 009.
- **Gate:** `scripts/gate.sh` — 1772 passed, 0 failed, 0 ignored (last run,
  after the second review's fixes; three more runs of the 242 log-capturing
  tests, all passed).
- **Revert checks:** `scripts/revert_specs/node_logs.json` — NL-R5, NL-R6
  and NL-R12 retired (what they pinned is gone); NL-R17 (a request without
  a note left out) and NL-R18 (a passing `/health` left out) new; NL-R10's
  anchor follows the code; NL-R3 also runs the forwarded-strangers test.
  18 of 18 bite.
- **Departures from the plan:** the capture helpers keep a second, idle
  dispatcher alive for the whole test process (`test_support.rs`,
  `keep_two_dispatchers`). One run captured nothing in
  `a_control_character_in_a_path_or_operation_name_cannot_start_a_line`.
  The cause (found by the review, in tracing-core 0.1.36's `callsite.rs`):
  while exactly one dispatcher is alive, tracing computes a log statement's
  interest from the *current thread's* default, so a test thread with no
  subscriber that reaches a statement first caches it as wanted by none,
  and a capture running elsewhere records nothing. A first fix, rebuilding
  the interest cache once a capture's subscriber existed, made it worse in
  `capture_warnings_async` (rebuilt before its subscriber was the thread's
  default: the L-158 test failed serially, and in 3 of 5 parallel runs of
  `ledgers::tests`); it is gone. With two dispatchers always alive, interest
  is computed over every live one, under tracing's lock: the serial
  reproduction passes, and so did five runs of `ledgers::tests` and six of
  the request-log, ledger and guard tests together.
- **Review:** one important finding (the first fix above, replaced);
  taken: comments that still said "throttled" or "a line of its own", the
  tracker's ID (MA-1, not A1, which `RESIDUALS.md` uses), the health test
  captured under the node's default filter.
- **Added in the same unit — strangers' lines under their own target:**
  `request_log.rs` writes a line without a note under `http::stranger`, so
  `RUST_LOG=…,http::stranger=off` leaves strangers out and keeps key
  holders' lines; `http=off` still covers both. `openledger logs` matches
  both targets for `--http` and gains `--no-strangers`;
  `run_local_node.sh` gains `--no-strangers`. Test
  `stranger_lines_can_be_turned_off_alone`; NL-R15 re-anchored, NL-R19 (a
  stranger's refusal at `INFO`) and NL-R20 (every line under `http`) new:
  `node_logs.json` 20 of 20 bite. Gate: 1772 passed, 0 failed, 0 ignored.
  The installer's smoke test (offline, 0.4.0 image, fake `docker`): 38 of
  38. Live, from source: by default four lines (two `/health`, the operator's
  query, a wrong key); with `--no-strangers` the operator's query only. A
  rehearsal check for `--no-strangers` is added; the rehearsal was not
  re-run.
- **Second review:** nothing important. Taken: two idle dispatchers (so
  tracing counts more than one before the first capture registers), and the
  helper called from the crate's other log captures too (`config.rs`,
  `p2p_service.rs` twice, `anti_entropy_alpn.rs`, `graphql/plaid.rs`); the
  rehearsal's `--no-strangers` check also wants a key holder's line; the
  docs say every `/health` is a stranger's line, a keyed one too (it checks
  the key itself, with no note); a `Bug-catch:` naming NL-R19; a comment
  tying `run_local_node.sh`'s fallback to `DEFAULT_LOG_FILTER`.
- **The same uncommitted diff also holds L-159 / T105** (the images no
  longer set `RUST_LOG`; `docs/audits/OUTSTANDING_TASKS_11_16.md`), at the
  maintainer's word: one commit for both.
- **Added in the same unit — the switches:** `openledger request-log
  [on|off|key-holders]` in the installer (above, *plan.md*) and
  `run_local_node.sh --no-request-log`. Offline smoke test, the 0.4.0 image
  with a fake `docker`: 22 of 22 for `request-log` (each value's line, the
  key kept, one `RUST_LOG` line, mode 0600, the container recreated, the
  same value twice restarting nothing, a hand-written `RUST_LOG` refused
  and untouched, bad values refused) and 38 of 38 for `logs`, as before.
  Three rehearsal checks added; the rehearsal was not re-run.
  The L-159 test (`l159_no_shipped_image_sets_rust_log`) now refuses only a
  line that sets `RUST_LOG` for the node — an image's `ENV …RUST_LOG…`, a
  compose service's `- RUST_LOG=…` or `RUST_LOG: …` — since the
  `request-log` arm names it to write the operator's env file (the gate
  caught the coarse grep); L159-R1..R3 still bite. Live: `run_local_node.sh
  --no-request-log`, no request line, the rest of the log as before. Gate:
  1772 passed, 0 failed, 0 ignored.
- **Third review** (the switches): two important findings, both taken.
  (1) A restart that failed left the env file saying the new value; the
  same command again then said "already" and started nothing. It now always
  runs `docker compose … up -d node` and the health check (compose changes
  nothing when both agree), and `openledger request-log` alone says when
  the running node was not started with what the file says, or is not
  running. (2) The rehearsal's stranger probe went to a path Caddy answers
  itself; the checks now send a stranger's 401 to the node, read the
  container's own `RUST_LOG` (`docker inspect`), exercise `off`, and assert
  no stranger line at all after `key-holders` (every health probe is one).
  Also taken: refused during an unfinished upgrade (`previous/pending`); a
  `RUST_LOG` in any form compose reads (`export`, spaces, `:`, empty), more
  than one, or one in `secrets.env` counts as hand-written; asking which
  takes no lock; the L-159 test reads the installer's two generated files
  (its image's Dockerfile and `compose.yml`) and refuses any line naming
  `RUST_LOG` there, as in the `Dockerfile` and the demo stack; a new test,
  `the_request_log_switches_build_on_the_nodes_default_filter`, ties both
  scripts' copies to `DEFAULT_LOG_FILTER` (NL-R21: 21 checks). Offline
  smoke test: 44 of 44 for `request-log` (a failed restart, then the same
  command again; five hand-written forms, two lines, `secrets.env`, an
  unfinished upgrade), 38 of 38 for `logs`. The harness empties its files
  inside the container: deleted on the Mac first, Docker Desktop's shared
  folder refused the next append (a harness fault, six false failures).
- **Rehearsal:** `scripts/rehearse_install.sh` — passed on ubuntu-24.04 and
  debian-12 (88 checks, 44 each), after the third review's fixes: on each,
  a stranger's request logged under `http::stranger` and left out by
  `--no-strangers` while a key holder's stayed; `request-log` on by
  default; `key-holders` and `off` each started the recreated container
  with the expected `RUST_LOG` (`docker inspect`); `key-holders` logged the
  key holder's request and no stranger line; `off` logged the node's own
  lines and no request line; `on` removed the line and the variable, served,
  and logged a stranger's `/health` again. Gate: 1773 passed, 0 failed, 0
  ignored.
- **Commit:** —
