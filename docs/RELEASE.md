# Cutting a release

A release is a tagged commit plus the files `scripts/release.sh` builds from it.
Versions follow Semantic Versioning; below 1.0 a minor version may break
compatibility, and the CHANGELOG's *Breaking* section says how.

## Steps

1. **Freeze.** Release work only from here to the tag.
2. **Version.** Set `version` in `[workspace.package]` of `Cargo.toml` (every
   crate inherits it) and run `cargo build` so `Cargo.lock` follows.
3. **CHANGELOG.** Rename `## [Unreleased]` to `## [X.Y.Z] — YYYY-MM-DD`, start a
   new empty `## [Unreleased]` above it, and check the release's summary and
   *Known limits* still hold.
4. **Docs.** README, `docs/OPERATIONS.md` and `deploy/gl-node.production.json`
   describe this release's behaviour and config keys.
5. **Commit** (maintainer), so the tree is clean.
6. **Build and check:** `scripts/release.sh --previous <the previous release's
   gl-node binary>` (leave out `--previous` for the first release). It stops at
   the first failure; see its header for what it runs. It skips the gate when
   the full gate already passed on exactly the committed files with the same
   compiler — the usual case, since the gate passes before the commit — and
   `--rerun-gate` runs it anyway. Everything it builds
   lands in `target/release-dist/X.Y.Z/` with `SHA256SUMS` and
   `RELEASE-INFO.txt` (commit, toolchain, image id).
7. **Tag and push** (maintainer) — the script prints the two commands:
   `git tag -a vX.Y.Z -m "openledger X.Y.Z" <commit>` and
   `git push origin vX.Y.Z`.
8. **Publish** (optional, maintainer): attach the files in
   `target/release-dist/X.Y.Z/` to a GitHub release, and push the Docker image
   to the registry you deploy from.
9. **Keep the binary** of this release: the next release's step 6 upgrades from
   it.

## What the checks prove, and what they do not

- The gate, the audit and the minimum-Rust build cover the code.
- `crates/gl-node/tests/shipped_binary.rs`, run with `--release`, starts the
  binary that ships from a fresh directory: boot, auth, signed writes,
  reports, `verify`, the health check, a clean stop and a restart. The gate
  runs the same test on the debug build at every commit.
- With `--previous`, the same file's upgrade test runs the upgrade and
  rollback procedure of `docs/OPERATIONS.md` from the previous release's
  binary to this one.
- None of them runs nodes on separate machines. Behaviour across a real
  network (NAT, relays, latency, partitions) is checked by the deployment's own
  rehearsal, not by a release.

## Platforms

`release.sh` ships the binary for the machine it runs on, and a Linux binary
copied out of the Docker image for the Docker host's architecture (on an Apple
Silicon Mac, `linux-arm64`). A Linux `amd64` build comes from running the
script on an `x86_64` machine, or from `docker build --platform linux/amd64`
(emulated, much slower).
