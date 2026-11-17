#!/usr/bin/env bash
# Run a node on this machine with its secrets from an env file, for trying
# the API locally — Plaid's sandbox above all (README, *Bank connections
# (Plaid)*; docs/api/openledger.insomnia.json).
#
#   scripts/run_local_node.sh [--env FILE] [--config FILE] [--no-strangers | --no-request-log]
#                              [--source | --watch | BINARY]
#
#   --env FILE      the secrets, one NAME=value a line (default: .env, which
#                   .gitignore keeps out of git): GL_NODE_PLAID_CLIENT_ID,
#                   GL_NODE_PLAID_SECRET and GL_NODE_SECRETS_KEY for Plaid.
#                   It must be readable by you alone (chmod 600).
#   --config FILE   the node's config (default: gl-node.local.json).
#   BINARY          the gl-node to run (default: the newest release in
#                   releases/ for this machine, else target/release/gl-node).
#   --source        build the working tree (cargo build -p gl-node, a debug
#                   build) and run that: what is on disk now, not a release.
#   --watch         --source, and again on every change: crates/, Cargo.toml,
#                   Cargo.lock or the config, checked each second. A change
#                   that builds restarts the node (SIGTERM: it folds its
#                   journals in first); one that does not leaves it running.
#   --no-strangers  leave out the request lines no key let through (adds
#                   http::stranger=off to RUST_LOG, or to the node's default
#                   filter when RUST_LOG is unset).
#   --no-request-log  leave out every request line (adds http=off, the same way).
#
# The secrets are exported to the node only: this script is a process of its
# own, so nothing it reads stays set in your terminal. It prints the names it
# found, never a value. Stop the node (and --watch) with Ctrl-C.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { printf 'run_local_node: %s\n' "$*" >&2; exit 1; }

env_file=.env
config=gl-node.local.json
binary="" from_source="" watch="" no_strangers="" no_request_log=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --env) [[ $# -ge 2 ]] || fail "--env needs a file"; env_file=$2; shift 2 ;;
    --config) [[ $# -ge 2 ]] || fail "--config needs a file"; config=$2; shift 2 ;;
    --source) from_source=1; shift ;;
    --watch) from_source=1; watch=1; shift ;;
    --no-strangers) no_strangers=1; shift ;;
    --no-request-log) no_request_log=1; shift ;;
    -h|--help) sed -n '2,29p' "$0"; exit 0 ;;
    -*) fail "unknown option $1 (see --help)" ;;
    *) [[ -z "$binary" ]] || fail "one binary only"; binary=$1; shift ;;
  esac
done
[[ -z "$no_strangers" || -z "$no_request_log" ]] || fail "--no-strangers or --no-request-log, not both"

# The secrets: there, yours alone, and not tracked by git.
[[ -f "$env_file" ]] || fail "no $env_file: put GL_NODE_PLAID_CLIENT_ID, GL_NODE_PLAID_SECRET and GL_NODE_SECRETS_KEY in it, one NAME=value a line"
mode=$(stat -f '%Lp' "$env_file" 2>/dev/null || stat -c '%a' "$env_file")
[[ "$mode" == 600 || "$mode" == 400 ]] || fail "$env_file is mode $mode: others on this machine can read it — run: chmod 600 $env_file"
if git ls-files --error-unmatch "$env_file" >/dev/null 2>&1; then
  fail "$env_file is tracked by git: it must never be committed — git rm --cached $env_file, and change the secrets in it"
fi

# Every NAME=value line exported to the node (and to it only: this process).
set -a
# shellcheck disable=SC1090
case "$env_file" in */*) source "$env_file" ;; *) source "./$env_file" ;; esac
set +a
found=()
for name in GL_NODE_PLAID_CLIENT_ID GL_NODE_PLAID_SECRET GL_NODE_SECRETS_KEY GL_NODE_API_KEY; do
  if [[ -n "${!name:-}" ]]; then found+=("$name"); fi
done
if [[ -n "${GL_NODE_SECRETS_KEY:-}" && ! "$GL_NODE_SECRETS_KEY" =~ ^[0-9a-fA-F]{64}$ ]]; then
  fail "GL_NODE_SECRETS_KEY in $env_file is not 64 hex characters (openssl rand -hex 32), and once banks are connected it must not change"
fi
if { [[ -n "${GL_NODE_PLAID_CLIENT_ID:-}" ]] && [[ -z "${GL_NODE_PLAID_SECRET:-}" ]]; } \
  || { [[ -z "${GL_NODE_PLAID_CLIENT_ID:-}" ]] && [[ -n "${GL_NODE_PLAID_SECRET:-}" ]]; }; then
  fail "set both GL_NODE_PLAID_CLIENT_ID and GL_NODE_PLAID_SECRET in $env_file, or neither"
fi

# The request lines no key let through, or every one, left out (010).
# The fallback is a copy of the node's own default filter, DEFAULT_LOG_FILTER
# in crates/gl-node/src/main.rs: change the two together.
if [[ -n "$no_strangers" ]]; then
  export RUST_LOG="${RUST_LOG:-info,iroh::protocol=error},http::stranger=off"
fi
if [[ -n "$no_request_log" ]]; then
  export RUST_LOG="${RUST_LOG:-info,iroh::protocol=error},http=off"
fi

# The config.
[[ -f "$config" ]] || fail "no $config (a config with \"plaid\": { \"enabled\": true, \"environment\": \"sandbox\" }, for one)"
export GL_NODE_CONFIG="$config"

# The working tree, built, when asked for.
if [[ -n "$from_source" ]]; then
  [[ -z "$binary" ]] || fail "--source (or --watch) or a BINARY, not both"
  cargo build -q -p gl-node || fail "the working tree did not build"
  binary=target/debug/gl-node
fi

# The binary: given, else the newest release for this machine, else a build.
if [[ -z "$binary" ]]; then
  os=$(uname -s | tr '[:upper:]' '[:lower:]')
  case "$(uname -m)" in
    arm64|aarch64) arch=arm64 ;;
    x86_64|amd64) arch=amd64 ;;
    *) arch=$(uname -m) ;;
  esac
  binary=$(ls releases/gl-node-*-"$os-$arch" 2>/dev/null | sort -V | tail -1 || true)
  [[ -n "$binary" ]] || binary=target/release/gl-node
fi
[[ -x "$binary" ]] || fail "no runnable gl-node at $binary: give one, put a release in releases/, or cargo build --release"

printf 'run_local_node: %s, config %s, secrets from %s (%s)\n' \
  "$binary" "$config" "$env_file" "${found[*]:-none}"
[[ -n "$watch" ]] || exec "$binary"

# --watch: the node in the background, rebuilt and restarted on a change.
node_pid=""
start_node() {
  "$binary" &
  node_pid=$!
}
stop_node() {
  [[ -n "$node_pid" ]] || return 0
  if kill -0 "$node_pid" 2>/dev/null; then
    # SIGTERM, as `docker stop` sends it; past 30 s it is killed.
    kill -TERM "$node_pid" 2>/dev/null || true
    for _ in $(seq 300); do
      kill -0 "$node_pid" 2>/dev/null || break
      sleep 0.1
    done
    kill -KILL "$node_pid" 2>/dev/null || true
  fi
  wait "$node_pid" 2>/dev/null || true
  node_pid=""
}
# A file changed since the stamp (the first found).
changed_since() {
  find crates Cargo.toml Cargo.lock "$config" -type f -newer "$1" \
    ! -name '.*' ! -path '*/target/*' 2>/dev/null | head -1
}
mtime() { stat -c %Y "$1" 2>/dev/null || stat -f %m "$1" 2>/dev/null || printf 0; }
stamp=$(mktemp "${TMPDIR:-/tmp}/run_local_node.XXXXXX")
trap 'stop_node; rm -f "$stamp"' EXIT
trap 'exit 0' INT TERM
start_node
printf 'run_local_node: watching crates/, Cargo.toml, Cargo.lock and %s (Ctrl-C stops)\n' "$config"
while true; do
  sleep 1
  if [[ -n "$node_pid" ]] && ! kill -0 "$node_pid" 2>/dev/null; then
    code=0
    wait "$node_pid" || code=$?
    node_pid=""
    printf 'run_local_node: the node exited (status %s); waiting for a change\n' "$code"
  fi
  changed=$(changed_since "$stamp" || true)
  [[ -n "$changed" ]] || continue
  sleep 0.5  # an editor saving several files at once
  config_changed=$(find "$config" -newer "$stamp" 2>/dev/null || true)
  touch "$stamp"
  before=$(mtime "$binary")
  printf 'run_local_node: %s changed: building\n' "$changed"
  if ! cargo build -q -p gl-node; then
    printf 'run_local_node: the build failed; %s\n' \
      "$([[ -n "$node_pid" ]] && printf 'the node runs on as it was' || printf 'no node runs')" >&2
    continue
  fi
  if [[ -n "$node_pid" && -z "$config_changed" && "$(mtime "$binary")" == "$before" ]]; then
    printf 'run_local_node: built; the node is unchanged, so it runs on\n'
    continue
  fi
  printf 'run_local_node: restarting the node\n'
  stop_node
  start_node
done
