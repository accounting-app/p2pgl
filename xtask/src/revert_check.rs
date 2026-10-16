//! Revert checks: prove that a test actually catches the bug a fix closes.
//!
//! Each check undoes one mechanism in a scratch copy of the working tree, runs
//! the tests that are supposed to catch it, and restores the file. A check
//! "bites" when at least one of its runs fails; one that bites nothing means
//! the mechanism is unpinned (or covered twice — see CLAUDE.md, "Revert
//! checks").
//!
//! The Rust form of what was `scripts/revert_check.py`, with the same spec
//! format, the same behaviour and the same output lines (004-no-python).

use std::collections::BTreeSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use serde::de::{Deserializer, MapAccess, Visitor};
use serde::Deserialize;
use serde_json::Value;

const USAGE: &str = "Revert checks: prove that a test actually catches the bug a fix closes.

    scripts/revert_check.sh SPEC.json              # every check in the file
    scripts/revert_check.sh SPEC.json NAME ...     # just these
    scripts/revert_check.sh --check SPEC.json      # anchors only, no build
    scripts/revert_check.sh --check-all            # anchors of every spec file

A spec file maps a check name to:

    {
      \"file\": \"crates/…/x.rs\", \"old\": \"exact text\", \"new\": \"replacement\",
      \"runs\": [[\"-p\", \"ledger\", \"--lib\", \"test_name_filter other_filter\"]]
    }

`old` must occur exactly once. Use `\"edits\": [{\"file\", \"old\", \"new\"}, …]`
instead of file/old/new to change several places at once. Each run is cargo
test arguments followed by one string of space-separated test-name filters.

The repo itself is never modified: the scratch copy lives in
$REVERT_CHECK_DIR (default: $TMPDIR/openledger-revert-check), with its own
target directory reused across runs.";

/// One textual edit a check makes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Edit {
    file: String,
    old: String,
    new: String,
}

/// One revert check, as a spec file gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Check {
    edits: Vec<Edit>,
    /// Each run: cargo test arguments, then one string of test-name filters.
    runs: Vec<Vec<String>>,
}

/// A spec file's checks, in the order the file gives them.
#[derive(Debug)]
struct Spec(Vec<(String, Check)>);

impl Spec {
    fn parse(text: &str) -> Result<Spec, String> {
        let ordered: Ordered = serde_json::from_str(text).map_err(|error| error.to_string())?;
        let mut checks = Vec::new();
        for (name, value) in ordered.0 {
            checks.push((
                name.clone(),
                Check::from_value(&value).map_err(|error| format!("{name}: {error}"))?,
            ));
        }
        Ok(Spec(checks))
    }

    fn get(&self, name: &str) -> Option<&Check> {
        self.0
            .iter()
            .find(|(check, _)| check == name)
            .map(|(_, check)| check)
    }
}

impl Check {
    fn from_value(value: &Value) -> Result<Check, String> {
        let text = |value: &Value, key: &str| -> Result<String, String> {
            value[key]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("missing \"{key}\""))
        };
        let edits = match value.get("edits").and_then(Value::as_array) {
            Some(edits) if !edits.is_empty() => edits
                .iter()
                .map(|edit| {
                    Ok(Edit {
                        file: text(edit, "file")?,
                        old: text(edit, "old")?,
                        new: text(edit, "new")?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?,
            _ => vec![Edit {
                file: text(value, "file")?,
                old: text(value, "old")?,
                new: text(value, "new")?,
            }],
        };
        let runs = value["runs"]
            .as_array()
            .ok_or("missing \"runs\"")?
            .iter()
            .map(|run| {
                run.as_array()
                    .ok_or("a run is a list of strings")?
                    .iter()
                    .map(|arg| {
                        arg.as_str()
                            .map(str::to_owned)
                            .ok_or("a run is a list of strings")
                    })
                    .collect::<Result<Vec<String>, &str>>()
            })
            .collect::<Result<Vec<_>, &str>>()?;
        Ok(Check { edits, runs })
    }
}

/// A JSON object read in file order (serde_json's own map sorts its keys).
struct Ordered(Vec<(String, Value)>);

impl<'de> Deserialize<'de> for Ordered {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct OrderedVisitor;
        impl<'de> Visitor<'de> for OrderedVisitor {
            type Value = Ordered;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an object of revert checks")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Ordered, A::Error> {
                let mut entries = Vec::new();
                while let Some(entry) = map.next_entry::<String, Value>()? {
                    entries.push(entry);
                }
                Ok(Ordered(entries))
            }
        }
        deserializer.deserialize_map(OrderedVisitor)
    }
}

/// Every anchor of `names` occurs exactly once in `root`; prints each that
/// does not.
fn check_anchors(root: &Path, spec: &Spec, names: &[String]) -> bool {
    let mut ok = true;
    for name in names {
        let check = spec.get(name).expect("names are checked against the spec");
        for edit in &check.edits {
            let count = std::fs::read_to_string(root.join(&edit.file))
                .map(|text| text.matches(edit.old.as_str()).count())
                .unwrap_or(0);
            if count != 1 {
                println!(
                    "{name}: anchor in {} occurs {count} times (must be 1)",
                    edit.file
                );
                ok = false;
            }
        }
    }
    ok
}

/// What one test run's output says.
#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    DoesNotCompile,
    Bites(Vec<String>),
    NothingFailed,
}

/// Read `cargo test` output: the failed tests, or a compile error.
fn verdict_of(output: &str) -> Verdict {
    let lines: Vec<&str> = output.lines().collect();
    if lines.iter().any(|line| line.starts_with("error[")) {
        return Verdict::DoesNotCompile;
    }
    let failed: Vec<String> = lines
        .iter()
        .filter(|line| line.starts_with("test ") && line.ends_with("FAILED"))
        .filter_map(|line| line.split_whitespace().nth(1).map(str::to_owned))
        .collect();
    if failed.is_empty() {
        Verdict::NothingFailed
    } else {
        Verdict::Bites(failed)
    }
}

fn work_dir() -> PathBuf {
    std::env::var_os("REVERT_CHECK_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("openledger-revert-check"))
}

fn sync_tree(root: &Path, tree: &Path) -> Result<(), String> {
    std::fs::create_dir_all(tree).map_err(|error| error.to_string())?;
    let status = Command::new("rsync")
        .args(["-a", "--delete", "--exclude", "target", "--exclude", ".git"])
        .arg(format!("{}/", root.display()))
        .arg(format!("{}/", tree.display()))
        .status()
        .map_err(|error| format!("rsync: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("rsync failed: {status}"))
    }
}

/// Apply `check` to the scratch `tree`, run its tests, restore; whether any
/// run failed.
fn run_check(root: &Path, work: &Path, tree: &Path, name: &str, check: &Check) -> bool {
    let files: BTreeSet<&str> = check.edits.iter().map(|edit| edit.file.as_str()).collect();
    let originals: Vec<(&str, String)> = files
        .iter()
        .map(|file| {
            (
                *file,
                std::fs::read_to_string(tree.join(file)).unwrap_or_default(),
            )
        })
        .collect();
    let mut bit = false;
    let mut texts = originals.clone();
    for edit in &check.edits {
        if let Some((_, text)) = texts.iter_mut().find(|(file, _)| *file == edit.file) {
            *text = text.replacen(edit.old.as_str(), &edit.new, 1);
        }
    }
    for (file, text) in &texts {
        let _ = std::fs::write(tree.join(file), text);
    }
    for run in &check.runs {
        let (filters, args) = match run.split_last() {
            Some((filters, args)) => (filters.split_whitespace().collect::<Vec<_>>(), args),
            None => continue,
        };
        let output = Command::new("cargo")
            .arg("test")
            .arg("--offline")
            .args(args)
            .arg("--")
            .args(&filters)
            .current_dir(tree)
            .env("CARGO_TARGET_DIR", work.join("target"))
            .output();
        let text = match output {
            Ok(output) => format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            Err(error) => format!("error[run]: cargo: {error}"),
        };
        let verdict = verdict_of(&text);
        let label = match &verdict {
            Verdict::DoesNotCompile => "DOES NOT COMPILE (fix the spec)".to_owned(),
            Verdict::Bites(failed) => format!("bites: {} failed", failed.len()),
            Verdict::NothingFailed => "nothing failed".to_owned(),
        };
        println!("  {} {}: {label}", args.join(" "), filters.join(" "));
        if let Verdict::Bites(failed) = verdict {
            bit = true;
            for test in failed {
                println!("      {test}");
            }
        }
    }
    for (file, text) in &originals {
        let _ = std::fs::write(tree.join(file), text);
    }
    let restored = files
        .iter()
        .all(|file| std::fs::read(tree.join(file)).ok() == std::fs::read(root.join(file)).ok());
    if !restored {
        println!("  WARNING: {name}: scratch copy differs from the repo after restore");
    }
    bit
}

/// The anchors of every spec file in `scripts/revert_specs` (the gate's check).
fn check_all(root: &Path) -> ExitCode {
    let dir = root.join("scripts/revert_specs");
    let mut files: Vec<PathBuf> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "json")
            })
            .collect(),
        Err(error) => {
            eprintln!("{}: {error}", dir.display());
            return ExitCode::FAILURE;
        }
    };
    files.sort();
    let mut ok = true;
    let mut total = 0;
    for file in &files {
        let spec = match std::fs::read_to_string(file)
            .map_err(|error| error.to_string())
            .and_then(|text| Spec::parse(&text))
        {
            Ok(spec) => spec,
            Err(error) => {
                println!("{}: {error}", file.display());
                ok = false;
                continue;
            }
        };
        let names: Vec<String> = spec.0.iter().map(|(name, _)| name.clone()).collect();
        total += names.len();
        let file_name = file.file_name().unwrap_or_default().to_string_lossy();
        if !check_anchors(root, &spec, &names) {
            println!("  in {file_name}");
            ok = false;
        }
    }
    if ok {
        println!(
            "{total} checks in {} spec files: every anchor occurs exactly once",
            files.len()
        );
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

pub fn main(args: &[String]) -> ExitCode {
    let root = crate::repo_root();
    if args.first().map(String::as_str) == Some("--check-all") {
        return check_all(&root);
    }
    let anchors_only = args.first().map(String::as_str) == Some("--check");
    let args = if anchors_only { &args[1..] } else { args };
    let Some((spec_path, names)) = args.split_first() else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };
    let spec = match std::fs::read_to_string(spec_path)
        .map_err(|error| error.to_string())
        .and_then(|text| Spec::parse(&text))
    {
        Ok(spec) => spec,
        Err(error) => {
            eprintln!("{spec_path}: {error}");
            return ExitCode::FAILURE;
        }
    };
    let names: Vec<String> = if names.is_empty() {
        spec.0.iter().map(|(name, _)| name.clone()).collect()
    } else {
        names.to_vec()
    };
    let unknown: Vec<&str> = names
        .iter()
        .filter(|name| spec.get(name).is_none())
        .map(String::as_str)
        .collect();
    if !unknown.is_empty() {
        eprintln!("unknown checks: {}", unknown.join(", "));
        return ExitCode::FAILURE;
    }
    if !check_anchors(&root, &spec, &names) {
        return ExitCode::FAILURE;
    }
    if anchors_only {
        println!("{} checks: every anchor occurs exactly once", names.len());
        return ExitCode::SUCCESS;
    }
    let work = work_dir();
    let tree = work.join("tree");
    if let Err(error) = sync_tree(&root, &tree) {
        eprintln!("{error}");
        return ExitCode::FAILURE;
    }
    let mut toothless = Vec::new();
    for name in &names {
        println!("{name}");
        let check = spec.get(name).expect("names are checked against the spec");
        if !run_check(&root, &work, &tree, name, check) {
            toothless.push(name.as_str());
        }
    }
    println!(
        "{} of {} checks bite",
        names.len() - toothless.len(),
        names.len()
    );
    for name in &toothless {
        println!("  does not bite: {name}");
    }
    if toothless.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A spec is read in file order, with either one edit or several, and its
    /// runs as given.
    ///
    /// Bug-catch: read the spec into a sorted map and checks run and print in
    /// name order, not in the order the spec file was written in.
    #[test]
    fn a_spec_is_read_in_file_order() {
        let spec = Spec::parse(
            r#"{
              "Z-first": { "file": "a.rs", "old": "x", "new": "y",
                           "runs": [["-p", "ledger", "--lib", "one two"]] },
              "A-second": { "edits": [{ "file": "a.rs", "old": "1", "new": "2" },
                                      { "file": "b.rs", "old": "3", "new": "4" }],
                            "runs": [["-p", "gl-node", "--bin", "gl-node", "three"]] }
            }"#,
        )
        .expect("parses");
        let names: Vec<&str> = spec.0.iter().map(|(name, _)| name.as_str()).collect();
        assert_eq!(names, ["Z-first", "A-second"]);
        assert_eq!(spec.get("A-second").expect("second").edits.len(), 2);
        assert_eq!(
            spec.get("Z-first").expect("first").runs,
            [vec!["-p", "ledger", "--lib", "one two"]]
        );
        assert!(Spec::parse(r#"{ "x": { "file": "a.rs", "runs": [] } }"#).is_err());
    }

    /// `cargo test` output is read as the Python tool read it: a compile error
    /// first, then each `test … FAILED` line, else nothing failed.
    ///
    /// Bug-catch: miss the compile error and a spec that does not build reads
    /// as a check that bites.
    #[test]
    fn test_output_gives_the_verdict() {
        assert_eq!(
            verdict_of(
                "test a::b ... ok\ntest a::c ... FAILED\n\ntest result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s"
            ),
            Verdict::Bites(vec!["a::c".to_owned()])
        );
        assert_eq!(
            verdict_of("error[E0425]: cannot find value\ntest a ... FAILED"),
            Verdict::DoesNotCompile
        );
        assert_eq!(
            verdict_of("test a ... ok\ntest result: ok"),
            Verdict::NothingFailed
        );
    }

    /// An anchor counts only when it occurs exactly once.
    ///
    /// Bug-catch: count "at least once" and an anchor that also matches
    /// elsewhere reverts the wrong place.
    #[test]
    fn an_anchor_must_occur_exactly_once() {
        let dir = std::env::temp_dir().join(format!("xtask-anchor-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        std::fs::write(dir.join("a.rs"), "one two one").expect("write");
        let spec = Spec::parse(
            r#"{ "once": { "file": "a.rs", "old": "two", "new": "2", "runs": [] },
                 "twice": { "file": "a.rs", "old": "one", "new": "1", "runs": [] },
                 "never": { "file": "a.rs", "old": "three", "new": "3", "runs": [] } }"#,
        )
        .expect("parses");
        assert!(check_anchors(&dir, &spec, &["once".to_owned()]));
        assert!(!check_anchors(&dir, &spec, &["twice".to_owned()]));
        assert!(!check_anchors(&dir, &spec, &["never".to_owned()]));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
