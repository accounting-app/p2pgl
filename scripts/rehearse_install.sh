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
  # Its boot scripts can take more than Lima's default 10 min on a busy Mac.
  limactl start --name="$vm" --tty=false --timeout=20m "template://$template" > "$log" 2>&1 \
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
  check "the secret-store key is root's only (0600), and the node has it" \
    sh -c "test \"\$(limactl shell '$vm' sudo stat -c '%a %U' /opt/openledger/secrets.env)\" = '600 root' && limactl shell '$vm' sudo grep -Eq '^GL_NODE_SECRETS_KEY=[0-9a-f]{64}$' /opt/openledger/secrets.env && limactl shell '$vm' sudo docker exec openledger-node printenv GL_NODE_SECRETS_KEY | grep -Eq '^[0-9a-f]{64}$'"

  rerun="$PWD/target/rehearsal/$vm.rerun.log"
  install_it > "$rerun" 2>&1 || { tail -20 "$rerun"; fail "the second run failed"; }
  check "a second run changes nothing" grep -q "^Nothing to change" "$rerun"
  check "a second run shows no key (only where it is)" \
    sh -c "! grep -q 'Operator key: [0-9a-f]\{64\}' '$rerun' && grep -q 'Operator key: in /opt/openledger/env' '$rerun'"

  verify='{"query":"{ verify { ok } }"}'
  acme=$(in_vm sudo openledger company add acme) || fail "openledger company add acme failed"
  check "openledger company add: acme in a mesh of its own, on UDP 4433" \
    grep -q "UDP port: 4433" <(printf '%s\n' "$acme")
  beta=$(in_vm sudo openledger company add beta) || fail "openledger company add beta failed"
  check "a second company gets the next port (4434)" \
    grep -q "UDP port: 4434" <(printf '%s\n' "$beta")
  check "openledger company list: both served, on their ports" \
    sh -c "limactl shell '$vm' sudo openledger company list | grep -Eq '^acme +served +4433 ' && limactl shell '$vm' sudo openledger company list | grep -Eq '^beta +served +4434 '"
  person=$(in_vm sudo openledger person add acme --name Ana --role write) \
    || fail "openledger person add failed"
  ana=$(sed -n 's/^ *key: *//p' <<< "$person")
  check "openledger person add gives Ana a key" test -n "$ana"
  check "Ana's key works on acme over HTTPS" \
    grep -q '"ok":true' <(body /ledgers/acme/graphql "$ana" "$verify")
  check "and is refused on beta (401)" test "$(answer /ledgers/beta/graphql "$ana" "$verify")" = 401
  check "openledger person list acme shows Ana" grep -q Ana <(in_vm sudo openledger person list acme)
  check "openledger status: HTTPS ok" in_vm sudo openledger status
  check "openledger key is the operator key" test "$(in_vm sudo openledger key)" = "$key"

  # 009: the request log, read with openledger logs. Requests from the VM's
  # own address, so Caddy forwards a caller that is not 127.0.0.1.
  in_vm sudo openledger company add acme-eu >/dev/null || fail "openledger company add acme-eu failed"
  from_vm() {  # path key body
    in_vm sudo curl -sS --max-time 10 --cacert "$root" --resolve "$domain:443:$vm_ip" -o /dev/null \
      -H "X-Api-Key: $2" -H 'Content-Type: application/json' -d "$3" "https://$domain$1"
  }
  from_vm /ledgers/acme/graphql "$ana" '{"query":"query Books { verify { ok } }","operationName":"Books"}'
  from_vm /ledgers/acme-eu/graphql "$key" "$verify"
  from_vm /graphql "$key" "$verify"
  logs=$(in_vm sudo openledger logs --http -n 200)
  check "openledger logs --http: Ana's request, her user id and the caller's address ($vm_ip)" \
    grep -Eq " INFO http: ledger=acme method=POST path=/ledgers/acme/graphql operation=Books user=u_[0-9a-f]{16} status=200 errors=0 ms=[0-9]+ client=$vm_ip\$" \
    <(printf '%s\n' "$logs")
  others_logged() {  # what openledger logs acme must leave out is there to leave out
    grep -q ' ledger=acme-eu ' <<< "$logs" && grep -q ' ledger=default ' <<< "$logs"
  }
  check "the log holds acme-eu's and default's requests too" others_logged
  only_acme() {  # the lines of openledger logs acme
    grep -q ' ledger=acme ' <<< "$1" && ! grep -Eq 'ledger=(acme-eu|default)' <<< "$1"
  }
  check "openledger logs acme: acme's lines, none of acme-eu's or default's" \
    only_acme "$(in_vm sudo openledger logs acme -n 1000)"
  tailed=$(in_vm sudo bash -c 'timeout 12 openledger logs --tail --http -n 0 & sleep 4
    curl -sS --max-time 5 --cacert "$1" --resolve "$2:443:$3" -o /dev/null -H "X-Api-Key: $4" \
      -H "Content-Type: application/json" -d "{\"query\":\"query Tailed { verify { ok } }\",\"operationName\":\"Tailed\"}" \
      "https://$2/graphql"
    wait || true' _ "$root" "$domain" "$vm_ip" "$key")
  check "openledger logs --tail streams a request made after it started" \
    grep -q ' operation=Tailed user=operator status=200 ' <(printf '%s\n' "$tailed")
  # 010: a stranger's request (no key) has its own line, target
  # http::stranger, and --no-strangers leaves it out.
  answer /ledgers/acme/graphql '' "$verify" >/dev/null
  strangers() {
    local all keyed
    all=$(in_vm sudo openledger logs --http -n 50) || return 1
    keyed=$(in_vm sudo openledger logs --http --no-strangers -n 50) || return 1
    grep -q ' WARN http::stranger: ledger=acme method=POST path=/ledgers/acme/graphql operation=- user=- status=401 ' <<< "$all" \
      && grep -q ' operation=Tailed user=operator ' <<< "$keyed" \
      && ! grep -q ' http::stranger: ' <<< "$keyed"
  }
  check "a stranger's request is logged (http::stranger); --no-strangers leaves it out and keeps the key holders'" strangers
  logs_refused() {  # what openledger says, then the arguments: refused by it, not by docker
    local said=$1 out
    shift
    if out=$(in_vm sudo openledger logs "$@" 2>&1); then return 1; fi
    grep -qF -- "$said" <<< "$out"
  }
  check "openledger logs refuses a COMPANY that is not a company name ('a|b')" \
    logs_refused 'is not a company name' 'a|b'
  check "and a --since that is not a time ('1h;x')" \
    logs_refused '--since takes' --since '1h;x'
  all_logs=$(in_vm sudo openledger logs -n 100000)
  no_key() { ! grep -qF -e "$key" -e "$ana" <<< "$all_logs"; }
  check "no key in the node's log (the operator's, Ana's)" no_key
  # Captured first: `grep -q` closing a pipe early would fail the pipe, and the
  # `!` would turn that into a pass.
  docker_log=$(in_vm sudo docker logs openledger-node 2>&1)
  no_colour() { ! grep -q $'\x1b' <<< "$docker_log"; }
  check "docker logs openledger-node has no colour codes" no_colour
  # 010: openledger request-log switches the node's request lines (last of
  # the log checks: each switch recreates the container, and its log with
  # it — so every line read after one was written after it).
  check "openledger request-log: on by default" test "$(in_vm sudo openledger request-log)" = on
  started_with() {  # the RUST_LOG the running container was started with
    in_vm sudo docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' openledger-node \
      | sed -n 's/^RUST_LOG=//p'
  }
  in_vm sudo openledger request-log key-holders >/dev/null || fail "openledger request-log key-holders failed"
  check "request-log key-holders: the node was started with it" \
    test "$(started_with)" = 'info,iroh::protocol=error,http::stranger=off'
  answer /ledgers/acme/graphql '' "$verify" >/dev/null
  from_vm /graphql "$key" '{"query":"query AfterSwitch { verify { ok } }","operationName":"AfterSwitch"}'
  key_holders_only() {
    local lines
    lines=$(in_vm sudo openledger logs --http -n 500) || return 1
    # No stranger line at all: the stranger's 401 above and every health
    # probe since the restart are strangers'.
    grep -q ' operation=AfterSwitch user=operator ' <<< "$lines" && ! grep -q ' http::stranger: ' <<< "$lines"
  }
  check "request-log key-holders: a key holder's request logged, no stranger's" key_holders_only
  in_vm sudo openledger request-log off >/dev/null || fail "openledger request-log off failed"
  check "request-log off: the node was started with it" \
    test "$(started_with)" = 'info,iroh::protocol=error,http=off'
  from_vm /graphql "$key" '{"query":"query WhileOff { verify { ok } }","operationName":"WhileOff"}'
  no_request_lines() {
    local lines
    lines=$(in_vm sudo openledger logs -n 500) || return 1
    grep -q 'gl-node starting' <<< "$lines" && ! grep -qE ' http(::stranger)?: ' <<< "$lines"
  }
  check "request-log off: the node logs, but no request line" no_request_lines
  in_vm sudo openledger request-log on >/dev/null || fail "openledger request-log on failed"
  back_on() {
    local rust_logs
    rust_logs=$(in_vm sudo grep -c '^RUST_LOG=' /opt/openledger/env || true)
    test "$(in_vm sudo openledger request-log)" = on \
      && test "$rust_logs" = 0 \
      && test -z "$(started_with)" \
      && test "$(body /health)" = '{"status":"ok"}' \
      && grep -q ' INFO http::stranger: ledger=default method=GET path=/health ' \
        <<< "$(in_vm sudo openledger logs --http -n 500)"
  }
  check "request-log on: no RUST_LOG line or variable, it serves, and logs a stranger's /health again" back_on

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
  check "and the companies with it: Ana's key works on acme" \
    grep -q '"ok":true' <(body /ledgers/acme/graphql "$ana" "$verify")

  if [[ -z "$keep" ]]; then
    limactl delete -f "$vm" >/dev/null 2>&1
  else
    echo "  kept: limactl shell $vm"
  fi
done
printf '\nREHEARSAL PASSED: %s\n' "${templates[*]}"
