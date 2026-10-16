# Log: no Python in the repo

Status: in progress.

One entry per commit-sized unit, newest last, written when the unit is ready
to commit. The commit hash is filled in once the maintainer has committed.

## 2026-10-15 — The unit

- **What changed:** `xtask/` — a workspace crate (`cargo xtask …`, alias in
  `.cargo/config.toml`; `serde` and `serde_json` only) with `revert-check`
  (the Python tool's behaviour and output, line for line; the spec read in
  file order through a small ordered visitor — serde_json's map sorts its
  keys unless another crate in the build turns on its `preserve_order`, so
  the order is not left to the build; plus `--check-all`, every spec file's anchors) and `measure-ledgers`
  (all four modes, the same JSON line; a guard type kills the node on every
  path; a failed run's directory is kept and named; a mesh poll that fails
  is retried where the Python tool stopped the run). `scripts/revert_check.sh`
  and `scripts/measure_ledgers.sh` run them from any directory. The gate
  gains two steps, `anchors` (`--check-all`) and `guard`.
  `.claude/hooks/guard_git.sh` replaces `guard_git.py`, with its cases in
  `guard_git_cases.jsonl` and `test_guard_git.sh` to run them; `settings.json`
  points at it. `deploy/mesh-init.sh` used Python too (UUIDs and the configs'
  JSON): `openssl rand` (already required) and `jq` now. The README's examples pretty-print with
  `jq .`. CLAUDE.md, the verifier agent, README and OPERATIONS name the new
  commands; the three `.py` files are gone.
- **The guard, and the review round that rewrote it.** Probing the Python
  guard before porting it showed it let through `(cd x); git commit`,
  `echo "$(git commit …)"`, `bash -c "git commit"`, `sh -c 'git push'`,
  `eval git add`, `command`/`xargs`/`sudo`/`time`/`nohup`/`exec git …`,
  `/usr/bin/git add`, and `git add` inside `if …; then` or a loop. The first
  shell guard closed those with a broad rule (`git` then a blocked word
  anywhere in a simple command), and this log said it blocked everything the
  Python one did. The review (one Important finding of three) showed it did
  not: `g\it commit`, `'g'it commit`, `git 'commit'`, `git co""mmit`, `git -C
  "$(pwd)" commit`, and an apostrophe in an unquoted heredoc body (which hid
  the rest of the command) all passed, where the Python guard refused them;
  and it failed open without `jq` or `awk`, and was quadratic (500 KB took
  21 s against the hook's 10 s). It was rewritten as one linear pass that
  reads a command as bash does — quotes and backslashes join a word, a line
  ending in `\` continues, `$( … )` and backticks are commands wherever they
  appear, a quoted string after a shell, `eval`, `env` or `trap` is a
  program, a heredoc body is data (only its `$( … )` runs, when the delimiter
  is unquoted), a `#` at a word's start is a comment, names compare in any
  case (APFS: `GIT` runs git) — and a blocked word counts only as git's
  subcommand, after its own options, which also stops it refusing `git stash
  push`, `git remote add` or `git grep add`. Its refusal is printed without
  `jq`, a missing `jq` or `awk` or an awk failure refuses, unclosed quotes
  refuse, and a line is read as a character array (indexing the line itself
  made BSD awk quadratic: 45 s for 1 MiB, now well under a second).
  Not caught, written in its header: a git in a variable (`$G commit`), an
  alias (`git -c alias.x=commit x`), a program piped to a shell, `$'…'`
  escapes — the permission prompts are the backstop.
- **Second review round** (reviewer subagent; nothing Important): the
  rewrite read any quoted string after `env`, `xargs`, `su` or `watch` as a
  program, so ordinary greps were refused (`git ls-files | xargs grep -l
  'git add'`, `env LC_ALL=C grep -rn "git push" docs`, and an apostrophe in
  such a string read as an unclosed quote). Only shells, `eval`, `trap`,
  `su`, `watch` and `env -S` (with or without a space before the quote) run
  their string now; those commands are allowed cases. A command ending in a
  continuation backslash is refused, as unclosed. The 1 MiB check allows 8 s
  (the gate runs it beside the QUIC tests; the quadratic reading took
  30–45 s). The port test runs on a fixed sequence, so its revert always
  bites; the mesh result lists crossed ledgers in arrival order. The
  reviewer declined to search for bypasses; it checked the guard against
  about 60 ordinary commands and replayed G-R1–G-R9 (each fails a case).
- **Found in use, after the second round:** the guard refused a command of
  mine that wrote an em dash ("awk failed"): in a UTF-8 locale macOS awk
  stops on a multi-byte character. Its awk now runs with `LC_ALL=C` — bytes,
  and no byte of a multi-byte character is a quote or a separator — and two
  non-ASCII cases are in the list (G-R10 reverts the locale; it bites where
  the locale is UTF-8, as on the maintainer's Mac). The next gate failed
  the size check once — 142 s for the 1 MiB command, where the same check
  took 2 s before and after, by hand and through `gate.sh --quick`; that gate
  ran overnight (26 min), and the check measured the clock, which a sleeping
  or throttled machine stretches. It now measures the hook's CPU time (the
  Python guard still fails it: 31 s of CPU).
- **Proof:** 128 cases (`guard_git_cases.jsonl`), each with what the Python
  guard decided (run from `HEAD` against the same file, recorded in a
  `python` field where it differs): the shell guard decides all 128 as
  expected; it refuses every case the Python one refused, and 38 it let
  through; there is no case the Python guard refused and this one allows.
  `test_guard_git.sh` also checks that with no tools on `PATH` the command
  is refused, and that a 1 MiB command ending in `git push` is refused within
  4 s — both of which the Python guard fails (no output, so allowed, without
  its interpreter; 32 s for the 1 MiB command, past the hook's 10 s); the gate runs it, and xtask's `guard` test runs it so that
  `scripts/revert_specs/tooling.json` can undo each of the guard's readings
  (G-R1–G-R9) and see a case fail. The live hook refused a test command after
  the switch. Revert checks, Python against Rust on four spec files (16
  checks): the same output, line for line; then every other check with the
  Rust tool: all 181 in the 10 spec files bite (audit_0927 30, boot_load_history
  8, ledgers 31, peer_discovery 19, residuals 12, users 65, and the 16), no
  compile failure, no restore warning. `measure-ledgers` reproduces 003's
  numbers within run-to-run noise (100 ledgers 1.6 s / 64 MiB; with P2P 2.0 s
  / 105 MiB; 30 × 10,000 entries 6.2 s / 1.78 GiB; the 100-pair mesh 100 of
  100, none crossed), in the old output format, and takes a relative
  `--binary`. The Docker image builds (844 s, its dependency layer rebuilt)
  and its binary reports `gl-node 0.1.0`. `mesh-init.sh`'s `jq` config writer gives the same
  JSON as the Python one for every node, identity and full configs alike; its
  UUIDs now come from `openssl rand` (already required) rather than
  `uuidgen`, which can be time-based.
- **Other review findings, fixed:** the Docker image no longer built (the
  workspace's new member was missing from the Dockerfile's dependency layer;
  neither the gate nor any test builds the image) — the manifest and a stub
  are copied, xtask is never built there; `measure-ledgers --binary` with a
  relative path, its output (Python's key order and spacing, a signal as a
  negative exit code) and its timeouts now match the Python tool; `cargo xtask` runs `--locked`; the test script fails on an
  empty case list. Left as they are: the revert tool's restore does not run
  on Ctrl-C (the next run's `rsync` heals the scratch tree), as the Python
  `finally` did.
- **Tests:** xtask — spec order, verdict reading, the exactly-once anchor
  rule, the measurement options, distinct clients and ports (chosen without
  binding any: tests stay off the network), the typed book and the output
  line; the guard test.
- **Gate:** `scripts/gate.sh` — fmt, clippy, anchors (197 checks in 11 spec files), guard (128 cases, fail-closed and size checks), and tests: 1,602 passed, 0 failed, 0 ignored (30 min: the test runs took their usual time; the rest was building while other projects' containers ran in the same VM).
- **Revert checks:** `scripts/revert_specs/tooling.json` — G-R1 to G-R10 (the
  guard's readings: case, backslashes, quotes joining a word, quoted
  programs, heredoc bodies, comments, git's options, a substitution's word,
  a refusal without `jq`, bytes in the C locale) and X-R1 to X-R6 (the tools'
  rules): 16 of 16 bite.
  None for the guard's linear reading (it changes how long, not what; the
  1 MiB check pins it).
- **Departures from the plan:** the guard is stricter than the Python one
  rather than identical (above); `deploy/mesh-init.sh` and the README examples were Python too and
  are converted; the 003 log keeps its mentions of the Python tools, as a
  record of what was true then (its notes say where the tool is now).
- **Commit:** (pending)
