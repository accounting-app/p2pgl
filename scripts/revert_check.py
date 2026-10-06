#!/usr/bin/env python3
"""Revert checks: prove that a test actually catches the bug a fix closes.

Each check undoes one mechanism in a scratch copy of the working tree, runs the
tests that are supposed to catch it, and restores the file. A check "bites"
when at least one of its runs fails; one that bites nothing means the mechanism
is unpinned (or covered twice — see CLAUDE.md, "Revert checks").

    scripts/revert_check.py SPEC.json              # every check in the file
    scripts/revert_check.py SPEC.json NAME ...     # just these
    scripts/revert_check.py --check SPEC.json      # anchors only, no build

A spec file maps a check name to:

    {
      "file": "crates/…/x.rs", "old": "exact text", "new": "replacement",
      "runs": [["-p", "ledger", "--lib", "test_name_filter other_filter"]]
    }

`old` must occur exactly once. Use `"edits": [{"file", "old", "new"}, …]`
instead of file/old/new to change several places at once. Each run is cargo
test arguments followed by one string of space-separated test-name filters.

The repo itself is never modified: the scratch copy lives in
$REVERT_CHECK_DIR (default: $TMPDIR/openledger-revert-check), with its own
target directory reused across runs.
"""
import filecmp
import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORK = os.environ.get(
    "REVERT_CHECK_DIR", os.path.join(tempfile.gettempdir(), "openledger-revert-check")
)
TREE = os.path.join(WORK, "tree")


def edits_of(check):
    return check.get("edits") or [{"file": check["file"], "old": check["old"], "new": check["new"]}]


def check_anchors(spec, names):
    ok = True
    for name in names:
        for edit in edits_of(spec[name]):
            count = open(os.path.join(REPO, edit["file"])).read().count(edit["old"])
            if count != 1:
                print(f"{name}: anchor in {edit['file']} occurs {count} times (must be 1)")
                ok = False
    return ok


def sync_tree():
    os.makedirs(TREE, exist_ok=True)
    subprocess.run(
        ["rsync", "-a", "--delete", "--exclude", "target", "--exclude", ".git", REPO + "/", TREE + "/"],
        check=True,
    )


def run_check(name, check):
    edits = edits_of(check)
    files = sorted({edit["file"] for edit in edits})
    originals = {f: open(os.path.join(TREE, f)).read() for f in files}
    bit = False
    try:
        texts = dict(originals)
        for edit in edits:
            texts[edit["file"]] = texts[edit["file"]].replace(edit["old"], edit["new"], 1)
        for f, text in texts.items():
            open(os.path.join(TREE, f), "w").write(text)
        env = dict(os.environ, CARGO_TARGET_DIR=os.path.join(WORK, "target"))
        for run in check["runs"]:
            args, filters = run[:-1], run[-1].split()
            out = subprocess.run(
                ["cargo", "test", "--offline", *args, "--", *filters],
                cwd=TREE, env=env, capture_output=True, text=True,
            )
            lines = (out.stdout + out.stderr).splitlines()
            failed = [l.split()[1] for l in lines if l.startswith("test ") and l.endswith("FAILED")]
            compile_error = any(l.startswith("error[") for l in lines)
            if compile_error:
                verdict = "DOES NOT COMPILE (fix the spec)"
            elif failed:
                verdict = f"bites: {len(failed)} failed"
                bit = True
            else:
                verdict = "nothing failed"
            print(f"  {' '.join(args)} {' '.join(filters)}: {verdict}")
            for test in failed:
                print(f"      {test}")
    finally:
        for f, text in originals.items():
            open(os.path.join(TREE, f), "w").write(text)
        restored = all(filecmp.cmp(os.path.join(TREE, f), os.path.join(REPO, f), shallow=False) for f in files)
        if not restored:
            print(f"  WARNING: {name}: scratch copy differs from the repo after restore")
    return bit


def main():
    argv = sys.argv[1:]
    anchors_only = argv and argv[0] == "--check"
    if anchors_only:
        argv = argv[1:]
    if not argv:
        sys.exit(__doc__)
    spec = json.load(open(argv[0]))
    names = argv[1:] or list(spec)
    unknown = [n for n in names if n not in spec]
    if unknown:
        sys.exit(f"unknown checks: {', '.join(unknown)}")
    if not check_anchors(spec, names):
        sys.exit(1)
    if anchors_only:
        print(f"{len(names)} checks: every anchor occurs exactly once")
        return
    sync_tree()
    results = {}
    for name in names:
        print(name)
        results[name] = run_check(name, spec[name])
    toothless = [n for n, bit in results.items() if not bit]
    print(f"{len(results) - len(toothless)} of {len(results)} checks bite")
    for name in toothless:
        print(f"  does not bite: {name}")
    sys.exit(1 if toothless else 0)


if __name__ == "__main__":
    main()
