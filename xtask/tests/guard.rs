//! The git guard (`.claude/hooks/guard_git.sh`) against its cases
//! (`guard_git_cases.jsonl`), as the gate runs it — here so the revert checks
//! (`scripts/revert_specs/tooling.json`) can undo one of its rules and see a
//! case fail (docs/build-log/004-no-python).

use std::path::Path;
use std::process::Command;

/// Every case decided as recorded, input it cannot read refused, a 1 MiB
/// command decided in time.
///
/// Bug-catch: drop any one of the guard's readings — case, backslashes,
/// quotes joining a word, a quoted program after a shell, heredoc bodies,
/// comments, the subcommand rule — and a case it is held to fails.
#[test]
fn the_git_guard_decides_every_case() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the repository root");
    let output = Command::new(root.join(".claude/hooks/test_guard_git.sh"))
        .output()
        .expect("run test_guard_git.sh");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
