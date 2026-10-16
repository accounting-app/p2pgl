//! The project's own tools (`docs/build-log/004-no-python`), run as
//! `cargo xtask <tool> …` (the alias is in `.cargo/config.toml`) or through
//! `scripts/revert_check.sh` and `scripts/measure_ledgers.sh`.

mod measure;
mod revert_check;

use std::process::ExitCode;

const USAGE: &str = "usage: cargo xtask <tool> [args]

tools:
  revert-check     revert checks: undo a mechanism in a scratch copy and run the
                   tests that must catch it (run with no arguments for details)
  measure-ledgers  measure a gl-node serving many ledgers (--help for details)";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let tool = args.next();
    let rest: Vec<String> = args.collect();
    match tool.as_deref() {
        Some("revert-check") => revert_check::main(&rest),
        Some("measure-ledgers") => measure::main(&rest),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// The repository root: the parent of this crate.
fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask lives in the repository root")
        .to_path_buf()
}
