#!/usr/bin/env bash
# Build and check a release of the commit that is checked out (docs/RELEASE.md).
#
#   scripts/release.sh [--previous OLD_BINARY] [--rerun-gate]
#
# Runs, in order, and stops at the first failure:
#   1. preconditions: a clean working tree, and a CHANGELOG heading for the
#      workspace version ("## [X.Y.Z] — YYYY-MM-DD");
#   2. scripts/gate.sh (fmt, clippy -D warnings, every test) — skipped when
#      the full gate already passed on exactly this tree and toolchain
#      (target/gate/passed.fingerprint matches scripts/tree_fingerprint.sh),
#      which is the usual case: the gate passes before the commit is made.
#      --rerun-gate runs it regardless;
#   3. cargo audit over Cargo.lock (.cargo/audit.toml applies);
#   4. a build on the minimum supported Rust (`rust-version`), when that
#      toolchain is installed;
#   5. the release binary, and the shipped-binary tests run against that build
#      (crates/gl-node/tests/shipped_binary.rs: `cargo test --release`);
#   6. with --previous, the same tests' upgrade rehearsal from OLD_BINARY;
#   7. the Docker image openledger/gl-node:X.Y.Z, and the Linux binary copied
#      out of it;
#   8. checksums and a RELEASE-INFO.txt, in target/release-dist/X.Y.Z/.
#
# It changes nothing in git. The tag is the maintainer's: the script ends by
# printing the commands.
set -euo pipefail

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'RELEASE STOPPED: %s\n' "$*" >&2; exit 1; }

usage="usage: scripts/release.sh [--previous OLD_BINARY] [--rerun-gate]"
previous=""
rerun_gate=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --previous)
      [[ $# -ge 2 ]] || fail "$usage"
      # Resolved before the cd below, so a path relative to the caller works.
      [[ -f "$2" ]] || fail "--previous: no binary at $2"
      previous="$(cd "$(dirname "$2")" && pwd)/$(basename "$2")"
      shift 2 ;;
    --rerun-gate) rerun_gate=1; shift ;;
    *) fail "$usage" ;;
  esac
done
cd "$(dirname "$0")/.."

version=$(sed -n '/^\[workspace\.package\]/,/^\[/{s/^version *= *"\(.*\)"/\1/p;}' Cargo.toml)
msrv=$(sed -n '/^\[workspace\.package\]/,/^\[/{s/^rust-version *= *"\(.*\)"/\1/p;}' Cargo.toml)
commit=$(git rev-parse HEAD)
dist="target/release-dist/$version"

step "preconditions for $version at ${commit:0:7}"
[[ -z "$(git status --porcelain)" ]] || fail "the working tree has uncommitted changes — release a commit"
grep -qE "^## \[$version\] — [0-9]{4}-[0-9]{2}-[0-9]{2}" CHANGELOG.md \
  || fail "CHANGELOG.md has no '## [$version] — YYYY-MM-DD' heading"
if git rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
  fail "tag v$version already exists — bump the version first"
fi

step "gate"
recorded=target/gate/passed.fingerprint
if [[ -z "$rerun_gate" && -f "$recorded" && "$(cat "$recorded")" == "$(scripts/tree_fingerprint.sh)" ]]; then
  echo "skipped: the full gate passed on exactly this tree and toolchain ($(date -r "$recorded" '+%Y-%m-%d %H:%M')); --rerun-gate to run it again"
else
  scripts/gate.sh || fail "the gate failed (logs in target/gate/)"
fi

step "cargo audit"
cargo audit --version >/dev/null 2>&1 || fail "cargo-audit is not installed (cargo install cargo-audit --locked)"
cargo audit || fail "cargo audit reports a vulnerability"

step "minimum supported Rust ($msrv)"
if rustup run "$msrv" rustc --version >/dev/null 2>&1; then
  CARGO_TARGET_DIR=target/msrv cargo "+$msrv" build --workspace --all-targets --locked \
    || fail "the workspace does not build on Rust $msrv"
else
  echo "Rust $msrv is not installed — skipped (rustup toolchain install $msrv --profile minimal)"
fi

step "release binary and the shipped-binary tests${previous:+ (upgrade from $previous)}"
cargo build --release --locked -p gl-node
# `--release`: the tests start target/release/gl-node, the binary that ships.
GL_NODE_PREVIOUS_BINARY="$previous" cargo test --release --locked -p gl-node --test shipped_binary \
  || fail "the shipped-binary tests failed"

step "Docker image openledger/gl-node:$version"
rm -rf "$dist" && mkdir -p "$dist"
host="$(uname -s | tr 'A-Z' 'a-z')-$(uname -m)"
cp target/release/gl-node "$dist/gl-node-$version-$host"
if docker info >/dev/null 2>&1; then
  # The image is built from the working tree: it must still be the commit.
  [[ -z "$(git status --porcelain)" ]] || fail "the working tree changed during the release"
  # The classic builder: it needs no buildx, and the Dockerfile uses nothing
  # BuildKit-only.
  DOCKER_BUILDKIT=0 docker build -t "openledger/gl-node:$version" . || fail "the Docker build failed"
  image_id=$(docker image inspect --format '{{.Id}}' "openledger/gl-node:$version")
  linux_arch=$(docker image inspect --format '{{.Architecture}}' "openledger/gl-node:$version")
  container=$(docker create "openledger/gl-node:$version")
  trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT
  docker cp "$container:/usr/local/bin/gl-node" "$dist/gl-node-$version-linux-$linux_arch"
  image_version=$(docker run --rm --entrypoint gl-node "openledger/gl-node:$version" --version)
  [[ "$image_version" == *"$version"* ]] || fail "the image's binary reports '$image_version', not $version"
else
  image_id="(not built: Docker is not running)"
  echo "Docker is not running — image and Linux binary skipped"
fi

step "checksums"
(cd "$dist" && shasum -a 256 gl-node-* > SHA256SUMS && cat SHA256SUMS)
{
  echo "openledger gl-node $version"
  echo "commit:      $commit"
  echo "built:       $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "rustc:       $(rustc --version)"
  echo "docker image openledger/gl-node:$version $image_id"
  echo
  cat "$dist/SHA256SUMS"
} > "$dist/RELEASE-INFO.txt"

printf '\nRELEASE %s READY in %s\n' "$version" "$dist"
cat <<EOF

To publish it (maintainer):
  git tag -a v$version -m "openledger $version" $commit
  git push origin v$version
Then, optionally, attach the files in $dist to a GitHub release.
EOF
