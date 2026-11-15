#!/usr/bin/env bash
# Run a node on this machine with its secrets from an env file, for trying
# the API locally — Plaid's sandbox above all (README, *Bank connections
# (Plaid)*; docs/api/openledger.insomnia.json).
#
#   scripts/run_local_node.sh [--env FILE] [--config FILE] [BINARY]
#
#   --env FILE      the secrets, one NAME=value a line (default: .env, which
#                   .gitignore keeps out of git): GL_NODE_PLAID_CLIENT_ID,
#                   GL_NODE_PLAID_SECRET and GL_NODE_SECRETS_KEY for Plaid.
#                   It must be readable by you alone (chmod 600).
#   --config FILE   the node's config (default: gl-node.local.json).
#   BINARY          the gl-node to run (default: the newest release in
#                   releases/ for this machine, else target/release/gl-node).
#
# The secrets are exported to the node only: this script is a process of its
# own, so nothing it reads stays set in your terminal. It prints the names it
# found, never a value. Stop the node with Ctrl-C.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { printf 'run_local_node: %s\n' "$*" >&2; exit 1; }

env_file=.env
config=gl-node.local.json
binary=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --env) [[ $# -ge 2 ]] || fail "--env needs a file"; env_file=$2; shift 2 ;;
    --config) [[ $# -ge 2 ]] || fail "--config needs a file"; config=$2; shift 2 ;;
    -h|--help) sed -n '2,19p' "$0"; exit 0 ;;
    -*) fail "unknown option $1 (see --help)" ;;
    *) [[ -z "$binary" ]] || fail "one binary only"; binary=$1; shift ;;
  esac
done

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

# The config.
[[ -f "$config" ]] || fail "no $config (a config with \"plaid\": { \"enabled\": true, \"environment\": \"sandbox\" }, for one)"
export GL_NODE_CONFIG="$config"

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
exec "$binary"
