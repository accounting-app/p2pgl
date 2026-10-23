#!/usr/bin/env bash
# Rehearse backups, restore, upgrade and rollback on an installed server
# (docs/build-log/005-installer, step 6) on a fresh Lima VM, all with
# `openledger`: a backup is the books as they were, a restore brings them
# back and moves the data it replaces aside, an upgrade backs up first and
# changes the image, a rollback puts back the books and the image from before
# it; the nightly unit runs, 14 backups are kept (and never the one a
# rollback needs), and two of these never run at once.
#
#   scripts/rehearse_backup.sh [--keep] [TEMPLATE]   (default: ubuntu-24.04)
#
# The upgrade's "new release" is the working tree's binary with one byte
# appended: another digest, so another image, and the same behaviour.
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

step "the node, built from the working tree"
DOCKER_BUILDKIT=0 docker build -q -t openledger/gl-node:rehearsal . >/dev/null || fail "the image did not build"
arch=$(docker image inspect --format '{{.Architecture}}' openledger/gl-node:rehearsal)
binary="$PWD/target/rehearsal/gl-node-linux-$arch"
container=$(docker create openledger/gl-node:rehearsal)
docker cp "$container:/usr/local/bin/gl-node" "$binary" >/dev/null
docker rm "$container" >/dev/null
next="$PWD/target/rehearsal/gl-node-linux-$arch-next"
cp "$binary" "$next"
printf '\0' >> "$next"
echo "  $binary, and $next (one byte more)"

installer="$PWD/deploy/install/install.sh"
vm="ol-backup"
log="$PWD/target/rehearsal/$vm.log"
in_vm() { limactl shell "$vm" "$@"; }
cleanup() {
  [[ -n "$keep" ]] && { echo "  kept: limactl shell $vm"; return; }
  limactl delete -f "$vm" >/dev/null 2>&1 || true
}
trap cleanup EXIT

step "a VM ($template)"
limactl delete -f "$vm" >/dev/null 2>&1 || true
# Its boot scripts can take more than Lima's default 10 min on a busy Mac.
limactl start --name="$vm" --tty=false --timeout=20m "template://$template" > "$log" 2>&1 \
  || fail "$vm did not start (see $log)"

step "the installer"
domain=backup.ledger.test
piped=$(in_vm sh -c "cat '$installer' | sudo bash -s -- --domain $domain --email ops@ledger.test --test-tls" 2>&1 || true)
check "it refuses to run from a pipe, before changing anything" \
  sh -c "grep -q 'run it from a file' <<'EOF'
$piped
EOF
! limactl shell '$vm' id -u openledger >/dev/null 2>&1"
in_vm sudo bash "$installer" --domain "$domain" --email ops@ledger.test --binary "$binary" --test-tls \
  >> "$log" 2>&1 || { tail -20 "$log"; fail "the installer failed (see $log)"; }
check "it keeps a copy of itself, root only" \
  test "$(in_vm sudo stat -c %a /opt/openledger/install.sh)" = 700
check "the nightly backup timer is enabled and active" \
  in_vm systemctl is-active --quiet openledger-backup.timer
image() { in_vm sudo docker inspect --format '{{.Config.Image}}' openledger-node; }
first_image=$(image)
echo "  $first_image"

root=/var/lib/openledger/caddy/data/caddy/pki/authorities/local/root.crt
op=$(in_vm sudo openledger key)
api() {  # key query: the answer, from inside the VM through Caddy
  local body
  body=$(jq -cn --arg q "$2" '{ query: $q }')
  in_vm sudo curl -sS --max-time 10 --cacert "$root" --resolve "$domain:443:127.0.0.1" \
    -H 'Content-Type: application/json' -H "X-Api-Key: $1" -d "$body" "https://$domain/ledgers/acme/graphql"
}
txn() {  # date narration
  printf 'mutation { appendTransaction(input: { date: "%s", narration: "%s", postings: [{ account: "Assets:Bank", amount: { number: "10", currency: "USD" } }, { account: "Income:Sales" }] }) { txid } }' "$1" "$2"
}
journal() { api "$op" '{ journal { narration } }'; }
has() { grep -q "\"$1\"" <(journal); }
lacks() { ! grep -q "\"$1\"" <(journal); }
verified() { grep -q '"ok":true,"quarantined":\[\]' <(api "$op" '{ verify { ok quarantined } }'); }

step "acme, and its books before the backup"
in_vm sudo openledger company add acme >> "$log" || fail "company add failed"
for account in Assets:Bank Income:Sales; do
  api "$op" "mutation { openAccount(name: \"$account\", date: \"2026-01-01\") }" >/dev/null
done
person=$(in_vm sudo openledger person add acme --name Ana --role write) || fail "person add failed"
ana=$(sed -n 's/^ *key: *//p' <<< "$person")
check "Ana writes" grep -q txid <(api "$ana" "$(txn 2026-01-02 'before the backup')")

step "a backup"
check "openledger backup completes" in_vm sudo openledger backup
file=$(in_vm sudo sh -c 'ls -1 /var/lib/openledger/backups/openledger-*.tar.gz | tail -1')
echo "  $file"
check "it is root's alone (0600, in a 0700 folder)" \
  test "$(in_vm sudo stat -c %a "$file" /var/lib/openledger/backups | tr '\n' ' ')" = "600 700 "
listing=$(in_vm sudo tar -tzf "$file")
for member in data/gl-node.config.json data/ledgers/acme/ledger.json data/ledgers/acme/ledger.bean settings env; do
  check "it holds $member" grep -qx "$member" <<< "$listing"
done
check "and no lock file" sh -c "! grep -q '\\.lock\$' <<'EOF'
$listing
EOF"
check "the node serves again after it" verified
check "openledger status names it as the last backup" grep -q "last backup: $file, 0h ago" <(in_vm sudo openledger status)
check "Ana writes after it" grep -q txid <(api "$ana" "$(txn 2026-01-03 'after the backup')")
# A command run in the VM while something else holds the lock: refused?
refused_while_locked() {
  ! in_vm sudo sh -c "flock /run/openledger.lock sleep 8 & sleep 2; $1; s=\$?; wait; exit \$s"
}
check "two never run at once: a backup is refused while another holds the lock" \
  refused_while_locked "openledger backup"
check "  and so is the installer" \
  refused_while_locked "bash /opt/openledger/install.sh --domain $domain --email ops@ledger.test --binary '$binary' --test-tls"

step "a stopped node, and a boot after a backup cut short"
state() { in_vm sudo docker inspect -f '{{.State.Status}}' openledger-node; }
stopped() { [[ "$(state)" == exited ]]; }
eventually() { local _; for _ in $(seq 60); do "$@" && return 0; sleep 2; done; return 1; }
in_vm sudo docker stop openledger-node >/dev/null
check "a backup of a stopped node completes" in_vm sudo openledger backup
check "  and leaves it stopped" stopped
mark=/var/lib/openledger/.node-stopped-by-openledger
in_vm sudo touch "$mark"
check "the resume unit is enabled at boot" in_vm systemctl is-enabled --quiet openledger-resume.service
check "at boot, a node a backup left stopped starts again" in_vm sudo systemctl start openledger-resume.service
check "  (it serves)" eventually verified
check "  (the mark is gone)" sh -c "! limactl shell '$vm' sudo test -e '$mark'"

step "a restore, after one cut short"
# As a crash halfway through a restore leaves it: the node stopped, the data
# moved aside and a partial one in its place, the marks set.
restoring=/var/lib/openledger/.restore-in-progress
cut=/var/lib/openledger/data.before-restore-cut
in_vm sudo sh -c "docker stop openledger-node >/dev/null && mv /var/lib/openledger/data '$cut' && install -d -m 0700 /var/lib/openledger/data && cp '$cut/gl-node.config.json' /var/lib/openledger/data/ && printf '%s\\n%s\\n' '$cut' '$file' > '$restoring' && touch '$mark'"
check "at boot, a node a restore left halfway stays stopped" in_vm sudo systemctl start openledger-resume.service
check "  (stopped)" stopped
check "  status says the restore did not finish, and which backup it was" \
  grep -q "RESTORE NOT FINISHED (restoring $file;" <(in_vm sudo openledger status || true)
check "  a backup is refused: no half-restored data archived" \
  sh -c "! limactl shell '$vm' sudo openledger backup"
check "  the installer will not start it" \
  sh -c "! limactl shell '$vm' sudo bash /opt/openledger/install.sh --domain $domain --email ops@ledger.test --binary '$binary' --test-tls"
check "  (stopped)" stopped
again=$(in_vm sudo openledger restore "$file" 2>&1) || fail "openledger restore, again, failed: $again"
check "openledger restore, again, completes, naming the data from before the cut-short one" \
  grep -q "before the restore that was cut short is in $cut" <<< "$again"
check "  (no mark is left)" sh -c "! limactl shell '$vm' sudo test -e '$restoring' && ! limactl shell '$vm' sudo test -e '$mark'"
check "the books are the backup's: before it, present" has "before the backup"
check "and after it, gone" lacks "after the backup"
check "Ana's key still works (the access list restored)" grep -q txid <(api "$ana" "$(txn 2026-01-04 'after the restore')")
check "it verifies, nothing quarantined" verified
check "it leaves no mark for a boot to act on" sh -c "! limactl shell '$vm' sudo test -e '$mark'"
aside=$(in_vm sudo sh -c 'ls -d /var/lib/openledger/data.before-restore-*' | tail -1)
check "the data it replaced is kept aside, with the write after the backup" \
  in_vm sudo grep -rqs 'after the backup' "$aside/ledgers/acme"
check "a file that is no backup is refused, the books untouched" \
  sh -c "! limactl shell '$vm' sudo openledger restore /opt/openledger/settings"
check "  (still served)" has "after the restore"

step "an upgrade: refused, failed, then done"
in_vm sudo cp /opt/openledger/compose.yml /root/compose.yml.orig
in_vm sudo sh -c 'echo "# an edit" >> /opt/openledger/compose.yml'
check "an upgrade is refused while compose.yml is edited" \
  sh -c "! limactl shell '$vm' sudo openledger upgrade --binary '$next' --installer '$installer'"
in_vm sudo cp /root/compose.yml.orig /opt/openledger/compose.yml
check "  (and changed nothing)" in_vm sudo test ! -e /opt/openledger/previous
check "a --version that is no X.Y.Z is refused" \
  sh -c "! limactl shell '$vm' sudo openledger upgrade --version 1.2"
bad="$PWD/target/rehearsal/not-a-binary"
printf 'not a binary\n' > "$bad"
check "an upgrade whose installer fails says so" \
  sh -c "! limactl shell '$vm' sudo openledger upgrade --binary '$bad' --installer '$installer'"
check "  status says it did not finish" grep -q 'UPGRADE NOT FINISHED' <(in_vm sudo openledger status || true)
check "  the node still serves its books" has "after the restore"
before_upgrade=$(in_vm sudo sed -n 's/^BACKUP=//p' /opt/openledger/previous/info)
in_vm sudo docker stop openledger-node >/dev/null
check "openledger upgrade, again — the node stopped — completes" \
  in_vm sudo openledger upgrade --binary "$next" --installer "$installer"
upgraded_image=$(image)
echo "  $upgraded_image"
check "the node runs another image" test "$upgraded_image" != "$first_image"
check "its books are intact" has "after the restore"
check "it verifies, nothing quarantined" verified
check "it is finished" in_vm sudo test ! -e /opt/openledger/previous/pending
check "a rollback still goes back to before the failed attempt: its backup, and the binary that ran" \
  in_vm sudo sh -c "test -s '$before_upgrade' && grep -qx 'BACKUP=$before_upgrade' /opt/openledger/previous/info && cmp -s /opt/openledger/previous/gl-node '$binary'"
check "Ana writes after the upgrade" grep -q txid <(api "$ana" "$(txn 2026-01-05 'after the upgrade')")

step "14 backups kept, never the one a rollback needs"
# Fourteen that sort just after the rollback's backup (and before the newer
# ones), then a backup: the rollback's is now past the fourteen newest.
in_vm sudo sh -c "for i in \$(seq 10 23); do : > '${before_upgrade%.tar.gz}'x\$i.tar.gz; done"
check "the nightly unit runs a backup" in_vm sudo systemctl start openledger-backup.service
count=$(in_vm sudo sh -c 'ls -1 /var/lib/openledger/backups/openledger-*.tar.gz | wc -l')
check "14 are kept, and the rollback's backup beside them ($count)" test "$count" -eq 15
check "  (the rollback's backup is there)" in_vm sudo test -s "$before_upgrade"
check "  (the oldest is gone)" sh -c "! limactl shell '$vm' sudo test -e '$file'"
in_vm sudo sh -c "rm -f '${before_upgrade%.tar.gz}'x*.tar.gz"

step "a rollback that fails halfway, then goes on"
in_vm sudo cp /opt/openledger/previous/install.sh /root/install.sh.orig
in_vm sudo sed -i '2i exit 3' /opt/openledger/previous/install.sh
check "a rollback whose installer fails says so" sh -c "! limactl shell '$vm' sudo openledger rollback"
check "  the node stays stopped on the restored books" stopped
check "  status says the rollback did not finish" grep -q 'ROLLBACK NOT FINISHED' <(in_vm sudo openledger status || true)
check "  a backup leaves it stopped" sh -c "limactl shell '$vm' sudo openledger backup"
check "  (stopped)" stopped
in_vm sudo touch "$mark"
check "  and so does a boot" in_vm sudo systemctl start openledger-resume.service
check "  (stopped)" stopped
in_vm sudo rm -f "$mark"
check "  a restore is refused" sh -c "! limactl shell '$vm' sudo openledger restore '$before_upgrade'"
check "  and an upgrade" sh -c "! limactl shell '$vm' sudo openledger upgrade --binary '$next' --installer '$installer'"
check "  and the installer run by hand" \
  sh -c "! limactl shell '$vm' sudo bash /opt/openledger/install.sh --domain $domain --email ops@ledger.test --binary '$next' --test-tls"
check "  (stopped)" stopped
in_vm sudo cp /root/install.sh.orig /opt/openledger/previous/install.sh
# As a crash in the middle of the rollback's own restore leaves it.
in_vm sudo sh -c "rm -f /opt/openledger/previous/restored && printf '%s\\n%s\\n' /var/lib/openledger/data.before-restore-rollback '$before_upgrade' > '$restoring'"
check "  status says the rollback, not a restore, did not finish" \
  sh -c "limactl shell '$vm' sudo openledger status | grep -q 'ROLLBACK NOT FINISHED'"
redo=$(in_vm sudo openledger rollback 2>&1) || fail "openledger rollback, again, failed: $redo"
check "openledger rollback, again, does its restore again and completes" \
  grep -q 'its restore did not finish, so it is done again' <<< "$redo"
check "the node runs the image from before the upgrade" test "$(image)" = "$first_image"
check "the books are the upgrade's backup: after the restore, present" has "after the restore"
check "and after the upgrade, gone" lacks "after the upgrade"
check "it verifies, nothing quarantined" verified
check "status is clean" sh -c "! limactl shell '$vm' sudo openledger status | grep -q 'NOT FINISHED'"
check "there is no second rollback" sh -c "! limactl shell '$vm' sudo openledger rollback"
in_vm sudo sh -c 'mkdir -p /opt/openledger/previous && printf "BACKUP=/var/lib/openledger/backups/gone.tar.gz\nVERSION=x\nIMAGE=y\n" > /opt/openledger/previous/info'
check "a rollback whose backup is gone is refused" sh -c "! limactl shell '$vm' sudo openledger rollback"
check "  and leaves no rollback unfinished" in_vm sudo test ! -e /opt/openledger/previous/rolling-back
check "  (the node serves on)" verified
in_vm sudo sh -c 'rm -f /opt/openledger/previous/info && : > /opt/openledger/previous/pending'
check "the installer, run again, changes nothing" \
  sh -c "limactl shell '$vm' sudo bash /opt/openledger/install.sh --domain $domain --email ops@ledger.test --binary '$binary' --test-tls | grep -q 'Nothing to change'"
check "  and finishes an upgrade left pending" in_vm sudo test ! -e /opt/openledger/previous/pending
in_vm sudo rmdir /opt/openledger/previous

printf '\nREHEARSAL PASSED: backups, restore, upgrade and rollback on %s\n' "$template"
