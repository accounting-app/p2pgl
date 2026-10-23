#!/usr/bin/env bash
# Rehearse joining a second server to a company's mesh (docs/build-log/
# 005-installer, step 5) on two fresh Lima VMs that reach each other (Lima's
# vzNAT network): each installed by deploy/install/install.sh, the company
# added on A, invited, joined from B, accepted on A — all with `openledger` —
# then entries written on each reach the other, a person added on A works on
# B, and B serves while A is stopped and A catches up when it is back.
#
#   scripts/rehearse_join.sh [--keep] [TEMPLATE]   (default: ubuntu-24.04)
#
# A is a.ledger.test and B b.ledger.test, with Caddy's own certificate
# authority (--test-tls); each VM resolves the other's name through
# /etc/hosts, and the API is reached inside each VM through `curl --resolve`.
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
template=ubuntu-24.04
for arg in "$@"; do
  case "$arg" in
    --keep) keep=1 ;;
    -*) fail "unknown option $arg" ;;
    *) template=$arg ;;
  esac
done
command -v limactl >/dev/null || fail "Lima is not installed (brew install lima)"
docker info >/dev/null 2>&1 || fail "Docker is not running"
mkdir -p target/rehearsal
rm -f target/rehearsal/ol-join-*.log

step "the node, built from the working tree"
DOCKER_BUILDKIT=0 docker build -q -t openledger/gl-node:rehearsal . >/dev/null || fail "the image did not build"
arch=$(docker image inspect --format '{{.Architecture}}' openledger/gl-node:rehearsal)
binary="$PWD/target/rehearsal/gl-node-linux-$arch"
container=$(docker create openledger/gl-node:rehearsal)
docker cp "$container:/usr/local/bin/gl-node" "$binary" >/dev/null
docker rm "$container" >/dev/null
echo "  $binary"

installer="$PWD/deploy/install/install.sh"
vm_a="ol-join-a" vm_b="ol-join-b"
log_a="$PWD/target/rehearsal/$vm_a.log" log_b="$PWD/target/rehearsal/$vm_b.log"
in_vm() { local vm=$1; shift; limactl shell "$vm" "$@"; }
cleanup() {
  [[ -n "$keep" ]] && { echo "  kept: limactl shell $vm_a / $vm_b"; return; }
  limactl delete -f "$vm_a" "$vm_b" >/dev/null 2>&1 || true
}
trap cleanup EXIT

step "two VMs on one network ($template)"
for vm in "$vm_a" "$vm_b"; do
  limactl delete -f "$vm" >/dev/null 2>&1 || true
  # Its boot scripts can take more than Lima's default 10 min on a busy Mac.
  limactl start --name="$vm" --tty=false --timeout=20m --network=vzNAT "template://$template" \
    > "$PWD/target/rehearsal/$vm.log" 2>&1 || fail "$vm did not start (see target/rehearsal/$vm.log)"
done
ip_of() { in_vm "$1" ip -4 -o addr show dev lima0 | awk '{ split($4, a, "/"); print a[1] }'; }
ip_a=$(ip_of "$vm_a") ip_b=$(ip_of "$vm_b")
[[ -n "$ip_a" && -n "$ip_b" && "$ip_a" != "$ip_b" ]] || fail "the VMs have no addresses of their own on the shared network"
in_vm "$vm_a" sudo sh -c "echo '$ip_b b.ledger.test' >> /etc/hosts"
in_vm "$vm_b" sudo sh -c "echo '$ip_a a.ledger.test' >> /etc/hosts"
# Apple's NAT network (vzNAT) isolates its VMs from each other: the host
# reaches both, but neither resolves the other's address (ARP incomplete).
# Through the gateway — the host — they do, as two servers on the internet.
gateway=$(in_vm "$vm_a" ip -4 route show dev lima0 default | awk '{ print $3; exit }')
[[ -n "$gateway" ]] || fail "no gateway on the shared network"
in_vm "$vm_a" sudo ip route add "$ip_b/32" via "$gateway" dev lima0
in_vm "$vm_b" sudo ip route add "$ip_a/32" via "$gateway" dev lima0
check "the VMs reach each other ($ip_a ↔ $ip_b, through $gateway)" \
  in_vm "$vm_b" ping -c2 -W2 "$ip_a"
echo "  a.ledger.test $ip_a, b.ledger.test $ip_b"

step "the installer on both"
install_on() {  # vm domain log
  in_vm "$1" sudo bash "$installer" --domain "$2" --email ops@ledger.test --binary "$binary" --test-tls \
    >> "$3" 2>&1 || { tail -20 "$3"; fail "the installer failed on $1 (see $3)"; }
}
install_on "$vm_a" a.ledger.test "$log_a"
install_on "$vm_b" b.ledger.test "$log_b"
echo "  installed"

step "acme on A, joined from B"
added=$(in_vm "$vm_a" sudo openledger company add acme) || fail "company add failed on A"
invitation=$(in_vm "$vm_a" sudo openledger invite acme | grep '^openledger-invite-v1\.' || true)
check "A writes an invitation" test -n "$invitation"
joined=$(in_vm "$vm_b" sudo openledger join "$invitation") || fail "join failed on B: $joined"
reply=$(grep '^openledger-reply-v1\.' <<< "$joined" || true)
check "B joins and writes a reply" test -n "$reply"
accepted=$(printf '%s\n' "$reply" | limactl shell "$vm_a" sudo openledger accept) || fail "accept failed on A: $accepted"
check "A accepts it, the reply read from stdin, and names the node it admitted" \
  grep -q "now replicates with node $(in_vm "$vm_b" sudo openledger company list | awk '$1 == "acme" { print $4 }')" <(printf '%s\n' "$accepted")
check "B listens on its own port" grep -q 'UDP port: 443[0-9]' <(printf '%s\n' "$joined")

root=/var/lib/openledger/caddy/data/caddy/pki/authorities/local/root.crt
api() {  # vm domain key query: the answer, from inside that VM through its Caddy
  local body
  body=$(jq -cn --arg q "$4" '{ query: $q }')
  in_vm "$1" sudo curl -sS --max-time 10 --cacert "$root" --resolve "$2:443:127.0.0.1" \
    -H 'Content-Type: application/json' -H "X-Api-Key: $3" -d "$body" "https://$2/ledgers/acme/graphql"
}
person=$(in_vm "$vm_a" sudo openledger person add acme --name Ana --role write) || fail "person add failed"
ana=$(sed -n 's/^ *key: *//p' <<< "$person")
check "Ana has a key from A" test -n "$ana"
A() { api "$vm_a" a.ledger.test "$ana" "$1"; }
B() { api "$vm_b" b.ledger.test "$ana" "$1"; }
arrives() {  # side narration
  local side=$1 narration=$2
  for _ in $(seq 90); do
    "$side" '{ journal { narration } }' 2>/dev/null | grep -q "\"$narration\"" && return 0
    sleep 2
  done
  return 1
}
op_a=$(in_vm "$vm_a" sudo openledger key)
for account in Assets:Bank Income:Sales; do
  api "$vm_a" a.ledger.test "$op_a" "mutation { openAccount(name: \"$account\", date: \"2026-01-01\") }" >/dev/null
done
txn() {  # date narration
  printf 'mutation { appendTransaction(input: { date: "%s", narration: "%s", postings: [{ account: "Assets:Bank", amount: { number: "10", currency: "USD" } }, { account: "Income:Sales" }] }) { txid } }' "$1" "$2"
}
check "Ana's key, issued on A, works on B (the access list replicated)" \
  sh -c "for i in \$(seq 90); do limactl shell '$vm_b' sudo curl -sS --max-time 10 --cacert '$root' --resolve b.ledger.test:443:127.0.0.1 -H 'Content-Type: application/json' -H 'X-Api-Key: $ana' -d '{\"query\":\"{ verify { ok } }\"}' https://b.ledger.test/ledgers/acme/graphql 2>/dev/null | grep -q '\"ok\":true' && exit 0; sleep 2; done; exit 1"
check "Ana writes on A" grep -q txid <(A "$(txn 2026-01-02 'written on A')")
check "it reaches B" arrives B "written on A"
check "Ana writes on B" grep -q txid <(B "$(txn 2026-01-03 'written on B')")
check "it reaches A" arrives A "written on B"

step "A stopped, then back"
in_vm "$vm_a" sudo docker stop openledger-node >/dev/null
check "B serves while A is stopped" grep -q '"written on A"' <(B '{ journal { narration } }')
check "Ana writes on B while A is stopped" grep -q txid <(B "$(txn 2026-01-04 'while A was down')")
in_vm "$vm_a" sudo docker start openledger-node >/dev/null
check "A, back, catches up" arrives A "while A was down"
for side in A B; do
  check "$side verifies, nothing quarantined" \
    grep -q '"ok":true,"quarantined":\[\]' <("$side" '{ verify { ok quarantined } }')
done

printf '\nREHEARSAL PASSED: join on %s\n' "$template"
