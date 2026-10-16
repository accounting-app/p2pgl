# Plan: no Python in the repo (from intent.md, 2026-10-15; approved 2026-10-15)

## Design

**`xtask/`** — a workspace member (binary `xtask`), run through a cargo alias
in `.cargo/config.toml` (`xtask = "run -q -p xtask --"`). No dependency the
workspace does not already have (`serde`, `serde_json`, `tempfile`); the HTTP
the measurements need is the same few lines `gl-node user` already speaks.
It is never built into a release (`release.sh` builds `-p gl-node`), but the
gate builds, lints and tests it like every crate.

- **`revert-check`** — the Python tool's behaviour, line for line: read a spec
  file; `--check` counts every anchor (exactly once, else name it and fail);
  otherwise `rsync` the tree into `$REVERT_CHECK_DIR/tree` (default
  `$TMPDIR/openledger-revert-check`) without `target` and `.git`, apply each
  check's edits (first occurrence), run each `cargo test --offline` with its
  filters and the scratch target dir, read `test … FAILED` and `error[`
  lines, print the same verdicts, restore the files and check them against
  the repo. The output lines stay the same ("N of M checks bite", "does not
  bite: NAME"), so nothing reading them changes. One addition: `--check` on
  every spec file at once, which the gate now runs (stale anchors bit three
  times in 003 and were found by hand).
- **`measure-ledgers`** — the Python tool's modes and output (`--ledgers`,
  `--p2p`, `--entries`, `--mesh`, `--binary`), the same JSON line, the same
  care: the node is always killed, a failed run's work directory is kept and
  named.

**`.claude/hooks/guard_git.sh`** — the same rule as `guard_git.py`: `git add`,
`stage`, `mv`, `rm`, `commit` and `push` in command position (at the start,
after `;` `&&` `||` `|` `&` `(` `)` `{` `}` `!`, a newline, `$(` or a
backtick, after `VAR=value` or `env`, with `-C dir`-style git options before
the subcommand) are denied; the same words in quotes or in a heredoc body are
not commands and pass. `jq` reads the input (as the audit-report hook already
does); an `awk` scanner does the quote-aware splitting `shlex` did. Input it
cannot read is denied (the Python one let it pass).

## Order of work

One unit:

1. `xtask` with `revert-check`; run every spec file through it and compare
   with the Python tool's verdicts.
2. `measure-ledgers`; rerun the 003 measurements.
3. `guard_git.sh` and `.claude/hooks/guard_git_cases.txt` (one command per
   case, with the verdict expected); a test that runs both hooks over the
   cases and asserts they agree; then `settings.json` points at the shell
   hook, and the case list (against the shell hook alone) joins the gate.
4. Remove the three `.py` files; CLAUDE.md, OPERATIONS, the verifier agent,
   the 003 log's mentions of the old commands.

## Risks

- **The guard is a safety mechanism.** A bug that lets `git commit` through
  breaks the working agreement silently. Mitigation: the case list, compared
  with the Python guard before it goes, and kept in the gate; failing closed.
- **Revert verdicts drifting** between the tools would make old "bites" claims
  wrong. Mitigation: every spec file run through both, verdicts compared.
- **`cargo xtask` compiles on first use** (a minute); the wrappers say so.

## Alternatives rejected

- Plain `.sh` for the two scripts: multi-line anchors with quotes and
  backslashes, exact-once replacement and JSON are fragile in shell, and the
  mesh measurement drives two nodes over HTTP.
- The guard in Rust: a hook that needs a compiled binary fails open when the
  workspace does not build.

## Proof

- Every spec file's verdicts, Rust against Python, recorded in `log.md`.
- The guard case list: both hooks agree on every case; the gate runs it.
- `git ls-files '*.py'` empty; the gate passes.
