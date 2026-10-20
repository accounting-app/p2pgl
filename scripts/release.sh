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
#      out of it; the other Linux architecture cross-compiled (Dockerfile.cross)
#      and, where the Docker host emulates it, booted to a passing health check;
#   8. checksums and a RELEASE-INFO.txt, in target/release-dist/X.Y.Z/.
#
# It changes nothing in git. The tag is the maintainer's: the script ends by
# printing the commands.
set -euo pipefail

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'RELEASE STOPPED: %s\n' "$*" >&2; exit 1; }
# The architecture a Linux (ELF) binary is for, from its header — e_machine,
# bytes 18–19 — whatever an image's metadata says.
elf_arch() {
  [[ "$(od -An -tx1 -N4 "$1" | tr -d ' \n')" == 7f454c46 ]] || { echo "not-elf"; return; }
  case "$(od -An -tx1 -j18 -N2 "$1" | tr -d ' \n')" in
    3e00) echo amd64 ;;
    b700) echo arm64 ;;
    *) echo unknown ;;
  esac
}

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
# The installer installs this release by default, on the image's own base.
installer=deploy/install/install.sh
grep -qx "RELEASE_VERSION=\"$version\"" "$installer" \
  || fail "$installer installs another version by default: set RELEASE_VERSION=\"$version\""
runtime_base=$(sed -n 's/^FROM \(debian:[^ ]*\) AS runtime$/\1/p' Dockerfile)
grep -qx "NODE_BASE=\"$runtime_base\"" "$installer" \
  || fail "$installer builds the node's image on another base than the Dockerfile's runtime stage ($runtime_base)"
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
  image_arch=$(docker image inspect --format '{{.Architecture}}' "openledger/gl-node:$version")
  container=$(docker create "openledger/gl-node:$version") || fail "could not create a container from the image"
  trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT
  docker cp "$container:/usr/local/bin/gl-node" "$dist/gl-node-linux" \
    || fail "could not copy the binary out of the image"
  # Named by what the binary is, and checked against the image: with Docker's
  # classic image store, pulling another platform of the multi-arch base (the
  # emulated check below) re-points its pinned digest, and the classic builder
  # then builds the runtime stage on that platform without complaint — the
  # image's metadata would name the binary after the wrong architecture.
  linux_arch=$(elf_arch "$dist/gl-node-linux")
  [[ "$linux_arch" == "$image_arch" ]] \
    || fail "the image says linux/$image_arch but its gl-node is $linux_arch: the Dockerfile's runtime base on this Docker host is another platform's (classic image store). Pull it again for linux/$linux_arch, or use the containerd image store, and rerun."
  mv "$dist/gl-node-linux" "$dist/gl-node-$version-linux-$linux_arch"
  image_version=$(docker run --rm --entrypoint gl-node "openledger/gl-node:$version" --version)
  [[ "$image_version" == *"$version"* ]] || fail "the image's binary reports '$image_version', not $version"

  # The other Linux architecture, cross-compiled (Dockerfile.cross): servers are
  # mostly amd64, an Apple Silicon Mac builds arm64.
  case "$linux_arch" in
    arm64) other=amd64 target=x86_64-unknown-linux-gnu gcc_arch=x86-64 ;;
    amd64) other=arm64 target=aarch64-unknown-linux-gnu gcc_arch=aarch64 ;;
    *) fail "no cross build from linux-$linux_arch" ;;
  esac
  step "linux-$other binary (cross-compiled)"
  DOCKER_BUILDKIT=0 docker build -f Dockerfile.cross --build-arg "TARGET=$target" \
    --build-arg "GCC_ARCH=$gcc_arch" --build-arg "DEB_ARCH=$other" -t "openledger/gl-node-cross:$version-$other" . \
    || fail "the linux-$other cross build failed"
  cross=$(docker create "openledger/gl-node-cross:$version-$other") \
    || fail "could not create a container from the cross build"
  trap 'docker rm -f "$container" "$cross" >/dev/null 2>&1 || true' EXIT
  docker cp "$cross:/gl-node" "$dist/gl-node-$version-linux-$other" \
    || fail "could not copy the cross-compiled binary out"
  [[ "$(elf_arch "$dist/gl-node-$version-linux-$other")" == "$other" ]] \
    || fail "the cross-compiled binary is not a linux-$other binary"
  # Run it, emulated, on the image's own base: it boots from an empty
  # directory and passes its own health check. Without emulation (binfmt) in
  # the Docker host, say so: the binary ships unrun. (Dockerfile.cross has
  # already refused a binary needing a glibc newer than that base's.)
  base=$(sed -n 's/^FROM \(debian:[^ ]*\) AS runtime$/\1/p' Dockerfile)
  [[ -n "$base" ]] || fail "the Dockerfile has no 'FROM debian:… AS runtime' line to run the binary on"
  docker pull -q --platform "linux/$other" "$base" >/dev/null \
    || fail "could not fetch the runtime base for linux/$other ($base)"
  if docker run --rm --platform "linux/$other" "$base" true >/dev/null 2>&1; then
    # A throwaway key for an empty node, through the environment (never on a
    # command line).
    GL_NODE_API_KEY=$(openssl rand -hex 32)
    export GL_NODE_API_KEY
    docker run --rm --platform "linux/$other" -e GL_NODE_API_KEY \
      -v "$PWD/$dist/gl-node-$version-linux-$other:/usr/local/bin/gl-node:ro" "$base" sh -c '
        cd /tmp && echo "{\"ledgerPath\": \"./data/ledger.bean\"}" > c.json
        export GL_NODE_CONFIG=/tmp/c.json
        gl-node --version
        gl-node > node.log 2>&1 &
        for i in $(seq 120); do gl-node --health-check >/dev/null 2>&1 && exit 0; sleep 1; done
        cat node.log; exit 1' \
      || fail "the linux-$other binary did not boot and pass its health check (emulated)"
    unset GL_NODE_API_KEY
    cross_run="booted and passed its health check, emulated"
  else
    cross_run="not run: no linux/$other emulation in this Docker host"
  fi
  echo "linux-$other: $cross_run"
else
  image_id="(not built: Docker is not running)"
  echo "Docker is not running — image and Linux binary skipped"
fi

step "checksums"
# The installer goes with the release, so SHA256SUMS covers it too.
install -m 0755 deploy/install/install.sh "$dist/install.sh"
(cd "$dist" && shasum -a 256 gl-node-* install.sh > SHA256SUMS && cat SHA256SUMS)
{
  echo "openledger gl-node $version"
  echo "commit:      $commit"
  echo "built:       $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "rustc:       $(rustc --version)"
  echo "docker image openledger/gl-node:$version $image_id"
  if [[ -n "${other:-}" ]]; then
    echo "linux-$other: cross-compiled (Dockerfile.cross), $cross_run"
  fi
  echo
  cat "$dist/SHA256SUMS"
} > "$dist/RELEASE-INFO.txt"

printf '\nRELEASE %s READY in %s\n' "$version" "$dist"
cat <<EOF

To publish it (maintainer):
  git tag -a v$version -m "openledger $version" $commit
  git push origin v$version
Then attach the files in $dist to the v$version GitHub release: the installer
downloads gl-node-$version-linux-*, install.sh and SHA256SUMS from there.
EOF
