#!/usr/bin/env bash
# Rehearse deploy/install/install.sh on fresh Lima VMs (docs/build-log/
# 005-installer): the node built from the working tree, installed the way a
# customer's server installs it, then checked from inside the VM as a client
# sees it, installed again (nothing may change) and rebooted.
#
#   scripts/rehearse_install.sh [--keep] [TEMPLATE…]   (default: ubuntu-24.04 debian-12)
#
# Each VM is new (`ol-rehearsal-<template>`, deleted first if left over, and
# afterwards unless --keep). The domain is ledger.test with Caddy's own
# certificate authority (--test-tls), reached inside the VM through
# `curl --resolve`. Needs Docker (to build the binary) and Lima; the VMs fetch
# their system image, Docker and Caddy from the internet.
set -euo pipefail
cd "$(dirname "$0")/.."

fail() { printf 'REHEARSAL FAILED: %s\n' "$*" >&2; exit 1; }
step() { printf '\n== %s\n' "$*"; }
check() {  # description, then a command that must succeed
  local what=$1
  shift
  if "$@"; then printf '  ok: %s\n' "$what"; else fail "$what"; fi
}

keep=""
templates=()
for arg in "$@"; do
  case "$arg" in
    --keep) keep=1 ;;
    -*) fail "unknown option $arg" ;;
    *) templates+=("$arg") ;;
  esac
done
[[ ${#templates[@]} -gt 0 ]] || templates=(ubuntu-24.04 debian-12)
command -v limactl >/dev/null || fail "Lima is not installed (brew install lima)"
docker info >/dev/null 2>&1 || fail "Docker is not running"

# Logs of earlier runs may hold a key: start clean.
rm -f target/rehearsal/*.log

step "the node, built from the working tree"
DOCKER_BUILDKIT=0 docker build -q -t openledger/gl-node:rehearsal . >/dev/null || fail "the image did not build"
arch=$(docker image inspect --format '{{.Architecture}}' openledger/gl-node:rehearsal)
mkdir -p target/rehearsal
binary="$PWD/target/rehearsal/gl-node-linux-$arch"
container=$(docker create openledger/gl-node:rehearsal)
docker cp "$container:/usr/local/bin/gl-node" "$binary" >/dev/null
docker rm "$container" >/dev/null
echo "  $binary ($(docker run --rm --entrypoint gl-node openledger/gl-node:rehearsal --version))"

installer="$PWD/deploy/install/install.sh"
domain=ledger.test
for template in "${templates[@]}"; do
  vm="ol-rehearsal-${template//./-}"
  log="$PWD/target/rehearsal/$vm.log"
  step "$template ($vm)"
  limactl delete -f "$vm" >/dev/null 2>&1 || true
  limactl start --name="$vm" --tty=false "template://$template" > "$log" 2>&1 \
    || fail "the VM did not start (see $log)"
  in_vm() { limactl shell "$vm" "$@"; }
  install_it() {  # [email]
    in_vm sudo bash "$installer" --domain "$domain" --email "${1:-ops@ledger.test}" \
      --binary "$binary" --test-tls
  }

  install_it >> "$log" 2>&1 || { tail -20 "$log"; fail "the installer failed on $template (see $log)"; }
  echo "  installed (log: $log)"
  check "the key is not written into the log (output not a terminal; where it is, said)" \
    sh -c "! grep -q 'Operator key: [0-9a-f]\{64\}' '$log' && grep -q 'Operator key: in /opt/openledger/env' '$log'"

  key=$(in_vm sudo sed -n 's/^GL_NODE_API_KEY=//p' /opt/openledger/env)
  root=/var/lib/openledger/caddy/data/caddy/pki/authorities/local/root.crt
  https() {  # path [key] [body]: status and body, from inside the VM
    local args=(-sS --max-time 10 --cacert "$root" --resolve "$domain:443:127.0.0.1"
      -o /dev/stdout -w '\n%{http_code}')
    [[ -n "${2:-}" ]] && args+=(-H "X-Api-Key: $2")
    [[ -n "${3:-}" ]] && args+=(-H 'Content-Type: application/json' -d "$3")
    in_vm sudo curl "${args[@]}" "https://$domain$1"
  }
  answer() { https "$@" | tail -1; }
  body() { https "$@" | sed '$d'; }

  check "a stranger's /health is ok and nothing else" \
    test "$(body /health)" = '{"status":"ok"}'
  check "the operator's /health has the version" \
    grep -q '"version"' <(body /health "$key")
  check "GraphQL without a key is refused (401)" \
    test "$(answer /graphql '' '{"query":"{ verify { ok } }"}')" = 401
  check "GraphQL with the operator key answers" \
    grep -q '"ok":true' <(body /graphql "$key" '{"query":"{ verify { ok } }"}')
  check "anything but the API is not served (404)" \
    test "$(answer /)" = 404
  vm_ip=$(in_vm hostname -I | awk '{ print $1 }')
  check "the VM has an address of its own ($vm_ip)" test -n "$vm_ip"
  check "the node answers on 127.0.0.1:4000 inside the VM" \
    in_vm curl -fsS --max-time 3 -o /dev/null http://127.0.0.1:4000/health
  refused() {  # url: curl's "connection refused" (exit 7), nothing else
    local code=0
    in_vm curl -sS --max-time 3 -o /dev/null "$1" 2>/dev/null || code=$?
    [[ $code -eq 7 ]]
  }
  check "the node binds 127.0.0.1 only: $vm_ip:4000 is refused" refused "http://$vm_ip:4000/health"
  check "Caddy's admin API is off: 127.0.0.1:2019 is refused" refused "http://127.0.0.1:2019/config/"
  check "the books and the node belong to the openledger system user" \
    sh -c "test \"\$(limactl shell '$vm' sudo stat -c '%U %a' /var/lib/openledger/data)\" = 'openledger 700' && test \"\$(limactl shell '$vm' ps -o user= -C gl-node | sort -u)\" = openledger"
  check "the firewall is on, admitting 443 and the ledgers' UDP ports" \
    sh -c "limactl shell '$vm' sudo ufw status | grep -q 'Status: active' && limactl shell '$vm' sudo ufw status | grep -q '443/tcp' && limactl shell '$vm' sudo ufw status | grep -q '4433:4532/udp'"
  check "the key file is root's only (0600)" \
    test "$(in_vm sudo stat -c '%a %U' /opt/openledger/env)" = "600 root"

  rerun="$PWD/target/rehearsal/$vm.rerun.log"
  install_it > "$rerun" 2>&1 || { tail -20 "$rerun"; fail "the second run failed"; }
  check "a second run changes nothing" grep -q "^Nothing to change" "$rerun"
  check "a second run shows no key (only where it is)" \
    sh -c "! grep -q 'Operator key: [0-9a-f]\{64\}' '$rerun' && grep -q 'Operator key: in /opt/openledger/env' '$rerun'"

  update="$PWD/target/rehearsal/$vm.update.log"
  install_it ops-2@ledger.test > "$update" 2>&1 || { tail -20 "$update"; fail "the run with a new e-mail failed"; }
  check "a run with a new e-mail updates the Caddyfile the installer wrote (no .new) and restarts Caddy" \
    sh -c "grep -q 'updated /opt/openledger/caddy/Caddyfile' '$update' && grep -q 'restarted openledger-caddy' '$update' && ! limactl shell '$vm' test -e /opt/openledger/caddy/Caddyfile.new"
  check "and it serves after it" test "$(body /health)" = '{"status":"ok"}'

  limactl stop "$vm" >> "$log" 2>&1 && limactl start "$vm" >> "$log" 2>&1 || fail "the VM did not restart"
  ok_after=""
  for _ in $(seq 60); do
    [[ "$(body /health 2>/dev/null)" == '{"status":"ok"}' ]] && { ok_after=1; break; }
    sleep 2
  done
  check "after a reboot it serves again" test -n "$ok_after"

  if [[ -z "$keep" ]]; then
    limactl delete -f "$vm" >/dev/null 2>&1
  else
    echo "  kept: limactl shell $vm"
  fi
done
printf '\nREHEARSAL PASSED: %s\n' "${templates[*]}"
