#!/usr/bin/env bash
# The openledger installer (docs/build-log/005-installer): one command on a
# fresh Ubuntu (22.04 or later) or Debian (12 or later) server puts a node into
# production behind HTTPS.
#
#   sudo bash install.sh --domain ledger.example.com --email you@example.com
#
# Point the domain's DNS at this server first: the certificate is issued for it.
#
#   --domain NAME    the name clients use (https://NAME/ledgers/<company>/graphql)
#   --email ADDRESS  for the certificate authority (expiry notices)
#   --version X.Y.Z  the release to install, 0.3.0 or later (default: this
#                    script's release)
#   --binary FILE    a gl-node binary you already have and trust, instead of
#                    downloading the release (our hosted service; rehearsals)
#   --ssh-port PORT  the port SSH listens on, when the installer cannot tell
#   --test-tls       certificates from Caddy's own authority, not Let's
#                    Encrypt: for a rehearsal whose domain does not resolve
#   --no-firewall    leave the firewall alone (one in front of the server)
#
# What it sets up, all under /opt/openledger (settings) and /var/lib/openledger
# (data):
#   - Docker, from Docker's own apt repository, its signing key checked by
#     fingerprint;
#   - the node: the release's Linux binary, checked against the release's
#     SHA256SUMS, in a small image built here on the same pinned Debian base as
#     the project's image, run as the `openledger` system user (no login); its
#     config from `gl-node init` (a loopback bind, public behind its proxy);
#     its operator key, generated here, in a file only root reads;
#   - Caddy (pinned by digest), the only public listener: HTTPS with automatic
#     certificates, forwarding the API and nothing else to the node, its admin
#     API off;
#   - the firewall (ufw): SSH, 80, 443 and the UDP ports companies' ledgers
#     use (4433–4532), nothing else;
#   - restarts on failure and on boot, and rotated logs;
#   - a backup every night (a systemd timer), and the `openledger` command:
#     companies, people, invitations, backups, restore, upgrade, rollback.
#
# Running it again changes nothing that is set up and says so; with another
# --version, --binary or --email it updates what it wrote before. It never
# deletes or overwrites books, keys, a config or a file you edited: an edited
# file is kept, and the installer's version is written beside it as FILE.new.
# Both containers use the host's network: the node binds 127.0.0.1 only, and a
# company added later opens its UDP port without recreating anything.
set -euo pipefail
umask 077

# The release this script installs by default; scripts/release.sh checks it
# is the version being released.
RELEASE_VERSION="0.3.0"
REPO_URL="https://github.com/accounting-app/p2pgl"
# The project image's runtime base (Dockerfile, `AS runtime`) — release.sh
# checks they are the same — and Caddy, both pinned by digest (L-10).
NODE_BASE="debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171"
CADDY_IMAGE="caddy:2.10.2@sha256:c3d7ee5d2b11f9dc54f947f68a734c84e9c9666c92c88a7f30b9cba5da182adb"
# Docker's apt signing key (https://docs.docker.com/engine/install/).
DOCKER_KEY_FINGERPRINT="9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
# The UDP ports the node's ledgers may listen on: 4433 and up, one per
# company (deploy/mesh-init.sh, `gl-node ledger add`), up to maxLedgers.
LEDGER_UDP_PORTS="4433:4532"

ETC=/opt/openledger
DATA=/var/lib/openledger/data
CADDY_DATA=/var/lib/openledger/caddy
# The node's user: a system account of its own, which no one logs in as —
# not uid 1000, the first login account on most servers, which would own the
# books and could read the node's environment (its key) from /proc.
NODE_USER=openledger

say() { printf '%s\n' "$*"; }
step() { printf '\n== %s\n' "$*"; }
fail() { printf 'install: %s\n' "$*" >&2; exit 1; }
changes=0
did() { changes=$((changes + 1)); say "  $*"; }
same() { say "  $* (unchanged)"; }
# Downloads: https only, from the start to every redirect.
fetch() { curl --proto '=https' --tlsv1.2 -fsSL "$@"; }

usage="usage: sudo bash install.sh --domain NAME --email ADDRESS [--version X.Y.Z] [--binary FILE] [--ssh-port PORT] [--test-tls] [--no-firewall]"
domain="" email="" version="$RELEASE_VERSION" binary="" ssh_port_given="" test_tls="" firewall=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --domain|--email|--version|--binary|--ssh-port)
      [[ $# -ge 2 ]] || fail "$1 needs a value"
      case "$1" in
        --domain) domain=$2 ;;
        --email) email=$2 ;;
        --version) version=$2 ;;
        --binary) binary=$2 ;;
        --ssh-port) ssh_port_given=$2 ;;
      esac
      shift 2 ;;
    --test-tls) test_tls=1; shift ;;
    --no-firewall) firewall=""; shift ;;
    -h|--help) say "$usage"; exit 0 ;;
    *) fail "unknown argument $1
$usage" ;;
  esac
done
[[ -n "$domain" && -n "$email" ]] || fail "$usage"
domain=$(printf '%s' "$domain" | tr 'A-Z' 'a-z')
[[ "$domain" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]] \
  || fail "--domain must be a name such as ledger.example.com (no https://, port or path)"
[[ "$email" =~ ^[^@[:space:]\"]+@[^@[:space:]\"]+\.[^@[:space:]\"]+$ ]] || fail "--email must be an e-mail address"
if [[ -n "$binary" ]]; then
  [[ -f "$binary" ]] || fail "--binary: no file at $binary"
else
  [[ "$version" =~ ^([0-9]+)\.([0-9]+)\.[0-9]+$ ]] || fail "--version must be X.Y.Z"
  if (( BASH_REMATCH[1] == 0 && BASH_REMATCH[2] < 3 )); then
    fail "openledger $version predates this installer: it needs gl-node init, from 0.3.0"
  fi
fi
if [[ -n "$ssh_port_given" ]]; then
  [[ "$ssh_port_given" =~ ^[1-9][0-9]{0,4}$ ]] && (( ssh_port_given < 65536 )) \
    || fail "--ssh-port must be a TCP port number"
fi

# ── The system ────────────────────────────────────────────────────────────────
step "this server"
[[ $(id -u) -eq 0 ]] || fail "run it as root (sudo bash install.sh …)"
# It keeps a copy of itself, for `openledger upgrade` and `rollback`: a file,
# not a pipe (curl … | bash).
self=${BASH_SOURCE[0]:-}
[[ -f "$self" ]] || fail "run it from a file: download install.sh, check it against SHA256SUMS, then sudo bash install.sh …"
# One at a time with `openledger backup`, restore, upgrade and rollback (which
# hold the lock already when they run it): a backup never stops the node in
# the middle of an install, nor an install start it in the middle of a backup.
[[ /proc/self/fd/9 -ef /run/openledger.lock ]] || exec 9>/run/openledger.lock
flock -n 9 || fail "a backup, restore, upgrade or rollback is running: wait for it, then run this again"
# Never the node started on half-restored books, nor the newer release on a
# rollback's: only the rollback itself runs the installer then.
if [[ -z "${OPENLEDGER_ROLLBACK:-}" ]]; then
  [[ ! -e /var/lib/openledger/.restore-in-progress ]] \
    || fail "a restore did not finish (the data may be partial): run openledger restore again first"
  [[ ! -e /opt/openledger/previous/rolling-back ]] \
    || fail "a rollback did not finish: run openledger rollback again first"
fi
[[ -r /etc/os-release ]] || fail "no /etc/os-release: not a Linux distribution this installer knows"
# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}" in
  ubuntu) [[ "${VERSION_ID%%.*}" -ge 22 ]] || fail "Ubuntu $VERSION_ID is too old: 22.04 or later" ;;
  debian) [[ "${VERSION_ID:-0}" -ge 12 ]] || fail "Debian ${VERSION_ID:-?} is too old: 12 or later" ;;
  *) fail "${PRETTY_NAME:-this system} is not Ubuntu or Debian" ;;
esac
case "$(uname -m)" in
  x86_64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) fail "no openledger build for $(uname -m)" ;;
esac
command -v systemctl >/dev/null || fail "systemd is required"
say "  $PRETTY_NAME, $arch"
if id -u "$NODE_USER" >/dev/null 2>&1; then
  same "user $NODE_USER"
else
  useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$NODE_USER" \
    || fail "could not create the $NODE_USER system user"
  did "user $NODE_USER (a system account, no login)"
fi
node_uid=$(id -u "$NODE_USER")
node_gid=$(id -g "$NODE_USER")

# ── Docker ────────────────────────────────────────────────────────────────────
step "Docker"
apt_ready=""
apt_install() {  # packages…
  if [[ -z "$apt_ready" ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq || fail "apt-get update failed"
    apt_ready=1
  fi
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "$@" >/dev/null \
    || fail "could not install $*"
}
if command -v docker >/dev/null && docker compose version >/dev/null 2>&1; then
  same "$(docker --version)"
else
  apt_install ca-certificates curl gnupg
  install -m 0755 -d /etc/apt/keyrings
  key=$(mktemp)
  fetch "https://download.docker.com/linux/$ID/gpg" -o "$key" \
    || { rm -f "$key"; fail "could not fetch Docker's signing key"; }
  # Exactly one key, and Docker's: apt trusts every key in the file, so a
  # second one appended to the download would be trusted too.
  listing=$(gpg --show-keys --with-colons "$key" 2>/dev/null || true)
  keys=$(awk -F: '$1 == "pub" { n++ } END { print n + 0 }' <<< "$listing")
  fingerprint=$(awk -F: '$1 == "pub" { primary = 1; next } primary && $1 == "fpr" { print $10; primary = 0 }' <<< "$listing")
  if [[ "$keys" != 1 || "$fingerprint" != "$DOCKER_KEY_FINGERPRINT" ]]; then
    rm -f "$key"
    fail "Docker's signing key is not the one expected ($keys key(s), fingerprint '$fingerprint', not $DOCKER_KEY_FINGERPRINT): refusing it"
  fi
  gpg --dearmor < "$key" > /etc/apt/keyrings/docker.gpg
  chmod 0644 /etc/apt/keyrings/docker.gpg
  rm -f "$key"
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$ID ${VERSION_CODENAME:?} stable" \
    > /etc/apt/sources.list.d/docker.list
  chmod 0644 /etc/apt/sources.list.d/docker.list
  apt_ready=""
  apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker >/dev/null 2>&1 || fail "Docker did not start"
  did "installed $(docker --version)"
fi

# ── The node's binary and image ───────────────────────────────────────────────
step "the node"
install -m 0755 -d "$ETC" "$ETC/image" "$ETC/caddy" /var/lib/openledger
install -m 0700 -d "$ETC/.installed"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if [[ -n "$binary" ]]; then
  install -m 0755 "$binary" "$work/gl-node"
  source_note="from $binary"
else
  base="$REPO_URL/releases/download/v$version"
  command -v curl >/dev/null || apt_install ca-certificates curl
  fetch "$base/SHA256SUMS" -o "$work/SHA256SUMS" \
    || fail "could not fetch $base/SHA256SUMS: is $version released, with its files attached?"
  file="gl-node-$version-linux-$arch"
  grep -E "^[0-9a-f]{64}  $file\$" "$work/SHA256SUMS" > "$work/sum" \
    || fail "the release's SHA256SUMS lists no $file"
  fetch "$base/$file" -o "$work/$file" || fail "could not fetch $base/$file"
  (cd "$work" && sha256sum -c --quiet sum) || fail "$file does not match the release's SHA256SUMS: refusing it"
  install -m 0755 "$work/$file" "$work/gl-node"
  source_note="release $version, matching its SHA256SUMS"
fi
# One tag per binary and base, however the binary came (a release, or
# --binary): a rollback reinstalling the previous binary finds the image it
# ran before, and builds nothing.
digest=$({ sha256sum < "$work/gl-node"; printf '%s\n' "$NODE_BASE"; } | sha256sum | cut -c1-12)
tag="openledger/gl-node:$digest-u$node_uid"
if docker image inspect "$tag" >/dev/null 2>&1; then
  same "image $tag"
else
  install -m 0755 "$work/gl-node" "$ETC/image/gl-node"
  cat > "$ETC/image/Dockerfile" <<EOF
# Written by the openledger installer: the node's image, the project's runtime
# stage (Dockerfile, AS runtime) around the binary it was given, its user the
# host's $NODE_USER account ($node_uid:$node_gid).
FROM $NODE_BASE
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \\
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --non-unique --gid $node_gid glnode \\
    && useradd --non-unique --uid $node_uid --gid glnode --no-create-home \\
       --home-dir /data --shell /usr/sbin/nologin glnode
COPY gl-node /usr/local/bin/gl-node
RUN mkdir -p /data && chown glnode:glnode /data
USER glnode
WORKDIR /data
ENV GL_NODE_CONFIG=/data/gl-node.config.json
ENV RUST_LOG=info
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \\
    CMD ["/usr/local/bin/gl-node", "--health-check"]
ENTRYPOINT ["gl-node"]
EOF
  chmod 0644 "$ETC/image/Dockerfile"
  docker build -q -t "$tag" "$ETC/image" >/dev/null || fail "the node's image did not build"
  reported=$(docker run --rm "$tag" --version) || fail "the node's binary does not run in its image"
  did "image $tag ($reported, $source_note)"
fi

# ── Its data, config and key ──────────────────────────────────────────────────
install -d -m 0700 -o "$node_uid" -g "$node_gid" "$DATA"
config="$DATA/gl-node.config.json"
if [[ -e "$config" ]]; then
  grep -qF "\"$domain\"" "$config" \
    || fail "$config is for another domain (its allowedHosts does not list $domain); it is kept — run with that domain, or move the config aside to start over"
  same "config $config"
else
  docker run --rm --user "$node_uid:$node_gid" -v "$DATA:/data" "$tag" init --domain "$domain" >/dev/null \
    || fail "gl-node init did not write the config (gl-node 0.3.0 or later is needed)"
  did "config $config (gl-node init, for https://$domain)"
fi
env_file="$ETC/env"
new_key=""
if [[ -s "$env_file" ]]; then
  same "operator key in $env_file"
else
  # 32 random bytes, hex: the kernel's generator, no tool beyond coreutils.
  new_key=$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')
  [[ "$new_key" =~ ^[0-9a-f]{64}$ ]] || fail "could not generate a key"
  printf '# The node operator key (root only). Never commit or share this file.\nGL_NODE_API_KEY=%s\n' "$new_key" > "$env_file"
  chmod 0600 "$env_file"
  did "operator key generated into $env_file (root only)"
fi

# ── Files the installer owns ──────────────────────────────────────────────────
# A file is the installer's while it still has the content the installer last
# wrote (its hash is kept in $ETC/.installed): then a new version replaces it.
# Once someone edits it, it is theirs: it is kept, and the installer's version
# is written beside it as FILE.new.
put_changed=""
put() {  # file mode, content on stdin
  local file=$1 mode=$2 tmp record
  record="$ETC/.installed/$(basename "$file").sha256"
  tmp=$(mktemp)
  cat > "$tmp"
  put_changed=""
  if [[ ! -e "$file" ]]; then
    install -m "$mode" "$tmp" "$file"
    did "wrote $file"
    put_changed=1
  elif cmp -s "$tmp" "$file"; then
    same "$file"
  elif [[ -s "$record" && "$(sha256sum < "$file" | cut -d' ' -f1)" == "$(cat "$record")" ]]; then
    install -m "$mode" "$tmp" "$file"
    did "updated $file"
    put_changed=1
  else
    install -m "$mode" "$tmp" "$file.new"
    did "kept your edited $file; the installer's version is $file.new"
  fi
  if cmp -s "$tmp" "$file"; then
    sha256sum < "$file" | cut -d' ' -f1 > "$record"
  fi
  rm -f "$tmp"
}

step "HTTPS (Caddy)"
tls_line=""
[[ -n "$test_tls" ]] && tls_line=$'\n\ttls internal'
install -d -m 0700 "$CADDY_DATA" "$CADDY_DATA/data" "$CADDY_DATA/config"
put "$ETC/caddy/Caddyfile" 0644 <<EOF
# Written by the openledger installer. The only public listener: HTTPS for
# $domain, forwarding the node's API and nothing else to it. The Host header
# goes through unchanged (the node checks it against allowedHosts, and its
# same-origin rule compares it). The admin API is off: on the host's network
# it would let anything on this machine rewrite where the API goes.
{
	admin off
	email $email
}

$domain {${tls_line}
	@api path /graphql /ledgers/* /health
	handle @api {
		reverse_proxy 127.0.0.1:4000
	}
	handle {
		respond 404
	}
}
EOF
caddyfile_changed=$put_changed

step "services"
put "$ETC/compose.yml" 0644 <<EOF
# Written by the openledger installer: the node and its HTTPS proxy, on the
# host's network (the node binds 127.0.0.1 only; Caddy listens on 80 and 443).
name: openledger
services:
  node:
    image: $tag
    container_name: openledger-node
    network_mode: host
    restart: unless-stopped
    env_file: $env_file
    volumes:
      - $DATA:/data
    # Every ledger folds its journal in on the way out (OPERATIONS, Sizing).
    stop_grace_period: 60s
    logging:
      driver: json-file
      options: { max-size: "10m", max-file: "5" }
  caddy:
    image: $CADDY_IMAGE
    container_name: openledger-caddy
    network_mode: host
    restart: unless-stopped
    volumes:
      # The folder, not the file: an updated Caddyfile is seen on restart.
      - $ETC/caddy:/etc/caddy:ro
      - $CADDY_DATA/data:/data
      - $CADDY_DATA/config:/config
    logging:
      driver: json-file
      options: { max-size: "10m", max-file: "5" }
EOF

step "the openledger command"
put "$ETC/settings" 0644 <<EOF
# Written by the openledger installer: what the openledger command needs,
# and the options an upgrade or a rollback runs the installer with again.
# The command sources it: every value is quoted for the shell.
DOMAIN=$(printf %q "$domain")
EMAIL=$(printf %q "$email")
TEST_TLS=$(printf %q "$test_tls")
NO_FIREWALL=$([[ -n "$firewall" ]] || printf 1)
SSH_PORT=$(printf %q "$ssh_port_given")
LEDGER_UDP_PORTS=${LEDGER_UDP_PORTS/:/-}
EOF
put /usr/local/sbin/openledger 0755 <<'COMMAND'
#!/usr/bin/env bash
# openledger: the day-to-day command of a node set up by the openledger
# installer (docs/build-log/005-installer, step 4). Run it as root. Each
# command is the node's own (`gl-node ledger`, `gl-node user`), run in its
# container with its operator key; the node judges every change.
set -euo pipefail
settings=/opt/openledger/settings
usage="usage:
  openledger company add NAME        a company, in a mesh of its own (a free UDP port of the firewall's range)
  openledger company list            every company: served or not and why, its port and node id
  openledger company restart NAME    picks up an edited ledger.json
  openledger company remove NAME     stops it; its folder moves to ledgers/.removed/ (nothing deleted)
  openledger person add COMPANY --name NAME --role read|write|admin [--expires YYYY-MM-DD]
  openledger person list COMPANY
  openledger person rename COMPANY USER_ID --name NAME
  openledger person revoke COMPANY USER_ID
  openledger invite COMPANY          an invitation to COMPANY's mesh (a credential: keep it safe)
  openledger join [INVITATION]       on the new server: join the company; prints the reply
  openledger accept [REPLY]          on every server already in the mesh: the new one joins
                                     (join and accept read the line from stdin without one)
  openledger backup                  a backup now (the node stops for seconds); 14 are kept
  openledger backups                 the backups on this server
  openledger restore FILE            the books as FILE has them (the current data moved aside)
  openledger upgrade --version X.Y.Z a backup, then release X.Y.Z (or --binary FILE [--installer FILE])
  openledger rollback                back to before the last upgrade: its backup and its binary
  openledger key                     the operator key
  openledger status                  the services, the node, HTTPS as a client sees it, the last backup"
fail() { printf 'openledger: %s\n' "$*" >&2; exit 1; }
[[ $(id -u) -eq 0 ]] || fail "run it as root (sudo openledger …)"
[[ -r "$settings" ]] || fail "no $settings: is this server set up by the openledger installer?"
# shellcheck disable=SC1090
. "$settings"
# No -i: nothing here reads stdin, and docker exec -i would swallow a
# script's input (`while read …; do openledger …; done < list`).
node() { docker exec openledger-node gl-node "$@"; }
# A line handed to the node on its stdin, never on a command line (ps).
node_line() { local line=$1; shift; printf '%s\n' "$line" | docker exec -i openledger-node gl-node "$@"; }
backups=/var/lib/openledger/backups
# What `openledger rollback` goes back to: the last upgrade's backup, and the
# binary, image and installer that ran before it.
previous=/opt/openledger/previous
# Set while a backup or a restore has the node stopped: `openledger resume`,
# at boot, starts it again if the server went down meanwhile.
stopped_mark=/var/lib/openledger/.node-stopped-by-openledger
# Set by a rollback before it touches the books, until the previous release
# runs on them: no backup, boot, restore or upgrade starts the newer release
# on them, nor the installer run by hand, and `openledger rollback` goes on
# from there. `restored` beside it: the restore is done and whole.
rolling_mark=$previous/rolling-back
restored_mark=$previous/restored
# Set while a restore swaps the data, until the backup's is whole: a boot
# never starts the node on half-unpacked books.
restoring_mark=/var/lib/openledger/.restore-in-progress
# What the restoring mark says: the data from before it (line 1) and the
# backup being restored (line 2).
restoring_what() {
  printf 'restoring %s; the data from before it is in %s' \
    "$(sed -n 2p "$restoring_mark" 2>/dev/null)" "$(sed -n 1p "$restoring_mark" 2>/dev/null)"
}
# FILE an openledger backup? (listed whole, then searched: grep -q on tar's
# pipe would cut tar short).
check_backup() {
  local listing
  [[ -f "$1" ]] || fail "no backup at $1"
  listing=$(tar -tzf "$1" 2>/dev/null) || fail "$1 is not a readable archive"
  grep -qx 'data/gl-node.config.json' <<<"$listing" || fail "$1 is not an openledger backup"
}
# Running, or restarting after a crash (Docker would start it again
# meanwhile): either way stopped for a backup, and started after it.
running() {
  case "$(docker inspect -f '{{.State.Status}}' openledger-node 2>/dev/null)" in
    running|restarting) return 0 ;;
    *) return 1 ;;
  esac
}
answers() { docker exec openledger-node gl-node --health-check >/dev/null 2>&1; }
# The node answers its own health check (after a start).
healthy() {
  local _
  for _ in $(seq 120); do
    answers && return 0
    sleep 1
  done
  return 1
}
image_now() { docker inspect -f '{{.Config.Image}}' openledger-node; }
# The installer's compose.yml as it wrote it: edited, an upgrade or a rollback
# would not change the image it names.
compose_is_ours() {
  [[ "$(sha256sum < /opt/openledger/compose.yml | cut -d' ' -f1)" \
     == "$(cat /opt/openledger/.installed/compose.yml.sha256 2>/dev/null)" ]]
}
# Where the node is, in words, for a message.
where_node() {
  local s
  s=$(docker inspect -f '{{.State.Status}}' openledger-node 2>/dev/null || printf 'missing')
  printf '%s, image %s' "$s" "$(image_now 2>/dev/null || printf '?')"
}
unfinished_rollback() {
  [[ ! -e "$rolling_mark" ]] \
    || fail "a rollback did not finish (the node is $(where_node)): run openledger rollback again, it goes on from there"
}
unfinished_restore() {
  [[ ! -e "$restoring_mark" ]] \
    || fail "a restore did not finish ($(restoring_what)): the data may be partial; run openledger restore again"
}
# A backup now: a running node stopped — every ledger folds its journal in —
# its data (books and node keys) and the server's settings and operator key
# archived, and the node started again; a stopped node is left stopped. The
# 14 newest are kept. Prints the archive's path. Each step checks its own
# result: a caller's `$(backup_now) || …` turns set -e off in here.
backup_now() {
  local stamp file started old keep was_running="" was_answering=""
  # Never a half-restored data folder archived as the newest backup.
  unfinished_restore
  install -d -m 0700 "$backups" || fail "cannot make $backups"
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  file="$backups/openledger-$stamp.tar.gz"
  [[ ! -e "$file" ]] || fail "$file exists already: try again in a second"
  # A backup cut short by a crash (the lock is held: none is being written).
  rm -f "$backups"/openledger-*.tar.gz.partial
  started=$(date +%s)
  if running; then
    was_running=1
    answers && was_answering=1
    : > "$stopped_mark" || fail "cannot write $stopped_mark"
    trap 'docker start openledger-node >/dev/null 2>&1 && rm -f "$stopped_mark"' EXIT
    docker stop -t 60 openledger-node >/dev/null || fail "the node did not stop"
  fi
  (umask 077 && tar -czf "$file.partial" --exclude='*.lock' \
     -C /var/lib/openledger data -C /opt/openledger settings env) \
    || { rm -f "$file.partial"; fail "the backup did not complete${was_running:+ (the node is started again)}"; }
  mv "$file.partial" "$file" || fail "could not name the backup $file"
  if [[ -n "$was_running" ]]; then
    docker start openledger-node >/dev/null || fail "the node did not start again: docker start openledger-node"
    rm -f "$stopped_mark"
    trap - EXIT
    if ! healthy; then
      # A node that did not answer before the backup is not failed by it.
      [[ -z "$was_answering" ]] || fail "the node did not become healthy after the backup: docker logs openledger-node"
      printf 'note: the node does not answer its health check (it did not before the backup either)\n' >&2
    fi
  fi
  printf 'Backup %s (%s)%s.\n' "$file" "$(du -h "$file" | cut -f1)" \
    "${was_running:+; the node was stopped $(( $(date +%s) - started ))s}" >&2
  # The 14 newest are kept; only the command's own archives are counted, and
  # never the one an upgrade can roll back to.
  keep=$(rollback_backup) || keep=""
  if [[ -e "$previous/info" && -z "$keep" ]]; then
    # Fail closed: an unreadable record deletes nothing.
    printf 'note: %s/info names no backup: none deleted\n' "$previous" >&2
  else
    for old in $(ls -1 "$backups"/openledger-*.tar.gz | LC_ALL=C sort | head -n -14); do
      [[ "$old" == "$keep" ]] || rm -f "$old"
    done
  fi
  printf '%s\n' "$file"
}
# The backup the last upgrade can roll back to, if any.
rollback_backup() {
  [[ -r "$previous/info" ]] || return 0
  (BACKUP=""; . "$previous/info"; printf '%s' "$BACKUP")
}
mesh_rule() {
  cat >&2 <<EOM
Check each company: { verify { ok quarantined } } — ok true, quarantined empty — and a balance you know.
On a mesh, make NO write here until this server has caught up with its peers: compare
{ verify { nodesChecked } } with a peer's (OPERATIONS, Restoring a backup) — a write before then
can reissue sequence numbers this server already signed.
EOM
}
# The books as backup FILE has them: the node stopped, its data moved aside
# (never deleted) and the backup's put in its place. With "start", the node
# is started on it; a rollback starts the previous release on it instead, so
# the newer one never boots on the restored books.
restore_from() {
  local file=$1 start=${2:-} stamp aside had_data prior=""
  check_backup "$file"
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  aside="/var/lib/openledger/data.before-restore-$stamp"
  [[ ! -e "$aside" ]] || fail "$aside exists already: try again in a second"
  # After a restore cut short, the data in place is what it left — not to be
  # put back or started — and its mark keeps naming the data from before it.
  if [[ -e "$restoring_mark" ]]; then
    prior=$(sed -n 1p "$restoring_mark")
    # The data in place is not the original already: a rollback whose restore
    # fails from here on stays unfinished.
    books_touched=1
  fi
  printf '%s\n%s\n' "${prior:-$aside}" "$file" > "$restoring_mark" || fail "cannot write $restoring_mark"
  if ! docker stop -t 60 openledger-node >/dev/null; then
    [[ -n "$prior" ]] || rm -f "$restoring_mark"
    fail "the node did not stop"
  fi
  # No data at all after a restore cut short right after this move.
  had_data=""
  if [[ -e /var/lib/openledger/data ]]; then
    books_touched=1
    mv /var/lib/openledger/data "$aside"
    had_data=1
  fi
  if ! tar -xzf "$file" -C /var/lib/openledger data; then
    rm -rf /var/lib/openledger/data
    [[ -n "$had_data" && -z "$prior" ]] \
      || fail "$file did not unpack, after a restore cut short: the node stays stopped; restore another backup (the data from before is in ${prior:-$aside})"
    mv "$aside" /var/lib/openledger/data
    books_touched=""
    rm -f "$restoring_mark"
    docker start openledger-node >/dev/null 2>&1 || true
    fail "$file did not unpack: the data is as it was"
  fi
  chown -R "$(id -u openledger):$(id -g openledger)" /var/lib/openledger/data
  chmod 0700 /var/lib/openledger/data
  # The books are whole: from here a boot may start the node on them.
  [[ -z "$start" ]] || : > "$stopped_mark" || fail "cannot write $stopped_mark"
  rm -f "$restoring_mark"
  if [[ -n "$prior" ]]; then
    printf 'Restored %s. The data from before the restore that was cut short is in %s\n' "$file" "$prior" >&2
    printf '(nothing was deleted; %s holds what that restore left).\n' "${had_data:+$aside}${had_data:-nothing}" >&2
  elif [[ -n "$had_data" ]]; then
    printf 'Restored %s. The data it replaced is in %s (nothing was deleted;\n' "$file" "$aside" >&2
    printf 'a company added since the backup is there, not in the restored books).\n' >&2
  else
    printf 'Restored %s (there was no data before it).\n' "$file" >&2
  fi
  if [[ -n "$start" ]]; then
    docker start openledger-node >/dev/null || fail "the node did not start: docker logs openledger-node"
    rm -f "$stopped_mark"
    healthy || fail "the node did not become healthy on the restored data: docker logs openledger-node"
    mesh_rule
  fi
}
# The installer's own options, for running it again (upgrade, rollback),
# into the array `args`.
installer_args() {
  [[ -n "${DOMAIN:-}" && -n "${EMAIL:-}" ]] \
    || fail "$settings has no DOMAIN or EMAIL: run the installer once more by hand (it writes them)"
  args=(--domain "$DOMAIN" --email "$EMAIL")
  if [[ -n "${TEST_TLS:-}" ]]; then args+=(--test-tls); fi
  if [[ -n "${NO_FIREWALL:-}" ]]; then args+=(--no-firewall); fi
  if [[ -n "${SSH_PORT:-}" ]]; then args+=(--ssh-port "$SSH_PORT"); fi
}
# The line given, or read from stdin (asked for on a terminal).
line_arg() {  # what [given]
  if [[ $# -ge 2 ]]; then printf '%s' "$2"; return; fi
  [[ -t 0 ]] && printf 'Paste the %s, then Enter: ' "$1" >&2
  local line
  IFS= read -r line || true
  printf '%s' "$line"
}
[[ $# -ge 1 ]] || { printf '%s\n' "$usage"; exit 2; }
what=$1
shift
# One at a time: the nightly backup never stops the node in the middle of a
# restore or an upgrade (its own backup runs in the same lock).
case "$what" in
  resume)
    # At boot it waits (a missed night's backup may start beside it).
    exec 9>/run/openledger.lock
    flock -w 900 9 || fail "the lock stayed held for 15 min: openledger status" ;;
  backup|restore|upgrade|rollback)
    exec 9>/run/openledger.lock
    flock -n 9 || fail "another backup, restore, upgrade or rollback is running: wait for it" ;;
esac
case "$what" in
  company)
    [[ $# -ge 1 ]] || fail "$usage"
    action=$1
    shift
    case "$action" in
      add) [[ $# -eq 1 ]] || fail "company add takes one NAME"
           node ledger add "$1" --new-mesh "$LEDGER_UDP_PORTS" ;;
      list) [[ $# -eq 0 ]] || fail "company list takes no arguments"
            node ledger list ;;
      restart|remove) [[ $# -eq 1 ]] || fail "company $action takes one NAME"
                      node ledger "$action" "$1" ;;
      *) fail "unknown company command $action
$usage" ;;
    esac ;;
  person)
    [[ $# -ge 2 ]] || fail "$usage"
    action=$1 company=$2
    shift 2
    case "$action" in
      add|list|rename|revoke) node user --ledger "$company" "$action" "$@" ;;
      *) fail "unknown person command $action
$usage" ;;
    esac ;;
  invite)
    [[ $# -eq 1 ]] || fail "invite takes one COMPANY"
    node ledger invite "$1" --address "$DOMAIN" ;;
  join)
    [[ $# -le 1 ]] || fail "join takes one INVITATION, or reads it from stdin"
    line=$(line_arg invitation "$@")
    [[ -n "$line" ]] || fail "no invitation given"
    node_line "$line" ledger join - --address "$DOMAIN" --new-mesh "$LEDGER_UDP_PORTS" ;;
  accept)
    [[ $# -le 1 ]] || fail "accept takes one REPLY, or reads it from stdin"
    line=$(line_arg reply "$@")
    [[ -n "$line" ]] || fail "no reply given"
    node_line "$line" ledger accept - ;;
  backup)
    [[ $# -eq 0 ]] || fail "backup takes no arguments"
    backup_now >/dev/null ;;
  backups)
    ls -lh "$backups"/openledger-*.tar.gz 2>/dev/null || printf 'No backups yet in %s.\n' "$backups" ;;
  restore)
    [[ $# -eq 1 ]] || fail "restore takes one backup FILE (openledger backups lists them)"
    unfinished_rollback
    restore_from "$1" start ;;
  resume)
    # At boot (openledger-resume.service): the node started again if a backup
    # or a restore had it stopped when the server went down — never in the
    # middle of a rollback.
    if [[ -e "$rolling_mark" ]]; then
      printf 'openledger: a rollback did not finish: the node stays stopped; run openledger rollback again\n' >&2
      exit 0
    fi
    if [[ -e "$restoring_mark" ]]; then
      printf 'openledger: a restore did not finish (%s): the node stays stopped; run openledger restore again\n' "$(restoring_what)" >&2
      exit 0
    fi
    [[ -e "$stopped_mark" ]] || exit 0
    docker start openledger-node >/dev/null || fail "the node did not start: docker logs openledger-node"
    rm -f "$stopped_mark"
    printf 'openledger: started the node a backup or restore had stopped when the server went down\n' >&2 ;;
  upgrade)
    version="" binary="" installer=""
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --version|--binary|--installer)
          [[ $# -ge 2 ]] || fail "$1 needs a value"
          case "$1" in --version) version=$2 ;; --binary) binary=$2 ;; --installer) installer=$2 ;; esac
          shift 2 ;;
        *) fail "unknown upgrade option $1" ;;
      esac
    done
    [[ -n "$version" || -n "$binary" ]] || fail "upgrade needs --version X.Y.Z or --binary FILE"
    [[ -z "$version" || -z "$binary" ]] || fail "give --version or --binary, not both"
    [[ -z "$version" || "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail "--version must be X.Y.Z"
    unfinished_rollback
    unfinished_restore
    compose_is_ours \
      || fail "/opt/openledger/compose.yml differs from what the installer last wrote: an upgrade would not change the image it names; undo the edit (or, if you took compose.yml.new, run the installer once more), then try again"
    installer_args
    work=$(mktemp -d)
    trap 'rm -rf "$work"' EXIT
    if [[ -z "$installer" ]]; then
      if [[ -n "$version" ]]; then
        # The release's own installer, checked against its SHA256SUMS.
        base="https://github.com/accounting-app/p2pgl/releases/download/v$version"
        curl --proto '=https' --tlsv1.2 -fsSL "$base/SHA256SUMS" -o "$work/SHA256SUMS" \
          || fail "could not fetch $base/SHA256SUMS: is $version released, with its files attached?"
        curl --proto '=https' --tlsv1.2 -fsSL "$base/install.sh" -o "$work/install.sh" \
          || fail "could not fetch $base/install.sh"
        grep -E '^[0-9a-f]{64}  install\.sh$' "$work/SHA256SUMS" > "$work/sum" \
          || fail "the release's SHA256SUMS lists no install.sh"
        (cd "$work" && sha256sum -c --quiet sum) || fail "install.sh does not match the release's SHA256SUMS"
        installer="$work/install.sh"
      else
        installer=/opt/openledger/install.sh
      fi
    fi
    [[ -f "$installer" ]] || fail "no installer at $installer"
    [[ -f /opt/openledger/install.sh ]] \
      || fail "no /opt/openledger/install.sh (the installer never ran to the end here): run it once more by hand, then upgrade"
    image=$(image_now) || fail "no openledger-node container: run the installer"
    # The release in use, from its image: the node need not be running.
    before=$(docker run --rm "$image" --version) || fail "the node's image does not run: $image"
    backup=$(backup_now) || fail "the backup before the upgrade failed: nothing was changed"
    if [[ -e "$previous/pending" ]]; then
      # An upgrade that did not finish: a rollback still goes back to what ran
      # before it, with its backup.
      # shellcheck disable=SC1091
      VERSION=""; . "$previous/info"
      printf 'The last upgrade did not finish: a rollback still goes back to %s, and its backup\n' "$VERSION" >&2
      printf '%s (writes since then would be lost by a rollback; this one is in %s).\n' "$(rollback_backup)" "$backup" >&2
    else
      # What a rollback needs: the backup, and the binary, image and installer
      # in use — the binary from the node's own container, so it is the one
      # that ran, whatever the installer last wrote.
      rm -rf "$previous.new" && install -d -m 0700 "$previous.new"
      docker cp openledger-node:/usr/local/bin/gl-node "$previous.new/gl-node" >/dev/null \
        || fail "could not copy the node's binary out of its container: nothing was changed"
      chmod 0755 "$previous.new/gl-node"
      install -m 0700 /opt/openledger/install.sh "$previous.new/install.sh"
      # Sourced by rollback: quoted for the shell.
      printf 'BACKUP=%q\nVERSION=%q\nIMAGE=%q\n' "$backup" "$before" "$image" > "$previous.new/info"
      : > "$previous.new/pending"
      rm -rf "$previous" && mv "$previous.new" "$previous"
    fi
    if [[ -n "$version" ]]; then args+=(--version "$version"); else args+=(--binary "$binary"); fi
    bash "$installer" "${args[@]}" \
      || fail "the upgrade failed; the node is $(where_node) (before the upgrade: $image). Fix the cause above and run it again, or go back: openledger rollback"
    rm -f "$previous/pending"
    [[ "$(image_now)" != "$image" ]] \
      || printf 'note: the node runs the image it ran before (%s): the same binary?\n' "$image" >&2
    printf '\nUpgraded: %s → %s. The books were backed up first (%s); openledger rollback goes back.\n' \
      "$before" "$(node --version)" "$(rollback_backup)" ;;
  rollback)
    [[ $# -eq 0 ]] || fail "rollback takes no arguments"
    [[ -f "$previous/info" ]] || fail "no upgrade to roll back (nothing in $previous)"
    compose_is_ours \
      || fail "/opt/openledger/compose.yml differs from what the installer last wrote: a rollback would not change the image it names; undo the edit, then try again"
    installer_args
    # shellcheck disable=SC1091
    BACKUP="" VERSION="" IMAGE=""; . "$previous/info"
    if [[ -e "$restored_mark" && ! -e "$restoring_mark" ]]; then
      printf 'Going on with the rollback to %s: the books are restored already (%s).\n' "$VERSION" "$BACKUP" >&2
    else
      if [[ -e "$rolling_mark" ]]; then
        printf 'Going on with the rollback to %s: its restore did not finish, so it is done again (%s).\n' "$VERSION" "$BACKUP" >&2
      else
        printf 'Rolling back to %s: the books as the backup before the upgrade has them (%s).\n' "$VERSION" "$BACKUP" >&2
        printf 'Writes made since the upgrade are not in it: list them before going on.\n' >&2
        if [[ -t 0 ]]; then
          read -r -p 'Type rollback to go on: ' answer
          [[ "$answer" == rollback ]] || fail "not rolled back"
        fi
        check_backup "$BACKUP"
        : > "$rolling_mark" || fail "cannot write $rolling_mark"
        # A restore that fails before it changes the books (or that puts them
        # back) leaves no rollback unfinished: the newer release runs on its
        # own books, as before.
        books_touched=""
        trap '[[ -n "$books_touched" ]] || rm -f "$rolling_mark"' EXIT
      fi
      # Kept stopped: the previous release starts on the restored books, never
      # the newer one, which may change them as it boots.
      restore_from "$BACKUP"
      : > "$restored_mark"
      trap - EXIT
    fi
    OPENLEDGER_ROLLBACK=1 bash "$previous/install.sh" "${args[@]}" --binary "$previous/gl-node" \
      || fail "the previous release did not install: the books are restored, the node is $(where_node) (no backup or boot starts it); fix the cause above, then run openledger rollback again — it goes on from here"
    if [[ -n "$IMAGE" && "$(image_now)" != "$IMAGE" ]]; then
      docker stop -t 60 openledger-node >/dev/null 2>&1 || true
      fail "the node runs $(image_now), not $IMAGE as before the upgrade: it is stopped; see docker compose -f /opt/openledger/compose.yml config"
    fi
    mv "$previous" "$previous.rolled-back-$(date -u +%Y%m%dT%H%M%SZ)"
    printf '\nRolled back to %s, on the books of %s.\n' "$(node --version)" "$BACKUP"
    mesh_rule ;;
  key)
    key=$(sed -n 's/^GL_NODE_API_KEY=//p' /opt/openledger/env)
    [[ -n "$key" ]] || fail "no GL_NODE_API_KEY in /opt/openledger/env"
    printf '%s\n' "$key" ;;
  status)
    docker compose -f /opt/openledger/compose.yml ps --format '  {{.Name}}: {{.Status}}'
    printf '  node: %s\n' "$(node --version 2>/dev/null || printf 'NOT RUNNING')"
    running || status=1
    tls=()
    if [[ -n "${TEST_TLS:-}" ]]; then
      tls=(--cacert /var/lib/openledger/caddy/data/caddy/pki/authorities/local/root.crt
           --resolve "$DOMAIN:443:127.0.0.1")
    fi
    if health=$(curl -fsS --max-time 10 "${tls[@]}" "https://$DOMAIN/health" 2>&1); then
      printf '  https://%s/health: %s\n' "$DOMAIN" "$health"
    else
      printf '  https://%s/health: FAILED (%s)\n' "$DOMAIN" "$health"
      status=1
    fi
    printf '  data: %s\n' "$(du -sh /var/lib/openledger/data | cut -f1)"
    if [[ -e "$rolling_mark" ]]; then
      printf '  ROLLBACK NOT FINISHED: the node %s; run openledger rollback again\n' "$(where_node)"
      status=1
    elif [[ -e "$restoring_mark" ]]; then
      printf '  RESTORE NOT FINISHED (%s): the data may be partial; run openledger restore again\n' "$(restoring_what)"
      status=1
    elif [[ -e "$previous/pending" ]]; then
      printf '  UPGRADE NOT FINISHED: the node %s; run openledger upgrade again (or the installer), or openledger rollback\n' "$(where_node)"
      status=1
    fi
    # The newest backup, and a warning (and a non-zero exit) past two days:
    # a nightly backup that fails says so nowhere else.
    newest=$(ls -1 "$backups"/openledger-*.tar.gz 2>/dev/null | LC_ALL=C sort | tail -n 1 || true)
    if [[ -z "$newest" ]]; then
      printf '  last backup: none yet (openledger backup takes one)\n'
    else
      age=$(( ($(date +%s) - $(stat -c %Y "$newest")) / 3600 ))
      if (( age >= 48 )); then
        printf '  last backup: %s, %sh ago: OLD — journalctl -u openledger-backup\n' "$newest" "$age"
        status=1
      else
        printf '  last backup: %s, %sh ago\n' "$newest" "$age"
      fi
    fi
    printf '\n'
    node ledger list || status=1
    exit "${status:-0}" ;;
  -h|--help|help) printf '%s\n' "$usage" ;;
  *) fail "unknown command $what
$usage" ;;
esac
COMMAND

step "nightly backups"
put /etc/systemd/system/openledger-backup.service 0644 <<'EOF'
# Written by the openledger installer: `openledger backup`, run by its timer.
[Unit]
Description=openledger backup (the node stops for seconds)
Requires=docker.service
After=docker.service openledger-resume.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/openledger backup
EOF
units_changed=$put_changed
put /etc/systemd/system/openledger-backup.timer 0644 <<'EOF'
# Written by the openledger installer: a backup every night (a missed one runs
# at the next boot); `openledger backups` lists them, 14 are kept.
[Unit]
Description=nightly openledger backup

[Timer]
OnCalendar=*-*-* 03:00:00
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
EOF
units_changed=$units_changed$put_changed
# At boot: the node started again when the server went down while a backup
# or a restore had it stopped (Docker leaves a container it was told to stop).
put /etc/systemd/system/openledger-resume.service 0644 <<'EOF'
# Written by the openledger installer: at boot, `openledger resume` starts the
# node if a backup or a restore had stopped it when the server went down.
[Unit]
Description=openledger: start the node a backup or restore left stopped
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/openledger resume

[Install]
WantedBy=multi-user.target
EOF
units_changed=$units_changed$put_changed
[[ -z "$units_changed" ]] || systemctl daemon-reload
systemctl is-enabled --quiet openledger-resume.service 2>/dev/null \
  || { systemctl enable openledger-resume.service >/dev/null 2>&1 \
         || fail "could not enable openledger-resume.service"; did "openledger-resume.service enabled (at boot)"; }
if systemctl is-enabled --quiet openledger-backup.timer 2>/dev/null \
    && systemctl is-active --quiet openledger-backup.timer; then
  same "timer openledger-backup.timer (nightly, into /var/lib/openledger/backups)"
else
  systemctl enable --now openledger-backup.timer >/dev/null 2>&1 \
    || fail "the backup timer did not start: systemctl status openledger-backup.timer"
  did "timer openledger-backup.timer: a backup every night into /var/lib/openledger/backups"
fi

# ── The firewall ──────────────────────────────────────────────────────────────
step "firewall"
if [[ -z "$firewall" ]]; then
  say "  left alone (--no-firewall): admit SSH, 80/tcp, 443/tcp and udp, and $LEDGER_UDP_PORTS/udp yourself"
else
  command -v ufw >/dev/null || { apt_install ufw; did "installed ufw"; }
  # Every port SSH listens on, so the firewall never locks you out: sshd's
  # own settings, its listening sockets, and systemd's ssh.socket (Ubuntu's
  # default, which may listen where sshd's settings do not say).
  ssh_ports="$ssh_port_given"
  if [[ -z "$ssh_ports" ]]; then
    ssh_ports=$({
      sshd -T 2>/dev/null | awk '$1 == "port" { print $2 }' || true
      ss -Htlnp 2>/dev/null | awk '/"sshd"/ { n = split($4, part, ":"); print part[n] }' || true
      systemctl show -p Listen --value ssh.socket 2>/dev/null \
        | sed -n 's/.*:\([0-9][0-9]*\) (Stream).*/\1/p' || true
    } | grep -E '^[0-9]+$' | sort -un | tr '\n' ' ' || true)
  fi
  ssh_ports=${ssh_ports% }
  [[ -n "$ssh_ports" ]] \
    || fail "cannot tell which port SSH listens on, and the firewall must not shut you out: pass --ssh-port PORT (or --no-firewall)"
  before=$(ufw status verbose 2>/dev/null || true)
  ufw default deny incoming >/dev/null
  ufw default allow outgoing >/dev/null
  for port in $ssh_ports; do ufw allow "$port/tcp" >/dev/null; done
  # 443/udp: HTTP/3, which Caddy serves beside HTTP/1 and 2.
  for rule in 80/tcp 443/tcp 443/udp "$LEDGER_UDP_PORTS/udp"; do
    ufw allow "$rule" >/dev/null
  done
  ufw --force enable >/dev/null
  admitted="SSH (${ssh_ports// //}/tcp), 80/tcp, 443/tcp+udp, $LEDGER_UDP_PORTS/udp"
  if [[ "$(ufw status verbose)" == "$before" ]]; then
    same "ufw: $admitted"
  else
    did "ufw: $admitted; everything else refused (but rules it already had)"
  fi
fi

# ── Start, and check it from the outside in ───────────────────────────────────
step "start"
if [[ -z "$test_tls" ]]; then
  addresses=$(getent ahosts "$domain" | awk '{ print $1 }' | sort -u | tr '\n' ' ' || true)
  [[ -n "$addresses" ]] \
    || fail "$domain does not resolve: point its DNS (an A or AAAA record) at this server, then run this again"
  local_addresses=" $(hostname -I 2>/dev/null || true) "
  here=""
  for address in $addresses; do
    [[ "$local_addresses" == *" $address "* ]] && here=1
  done
  [[ -n "$here" ]] || say "  note: $domain resolves to $addresses, none of them this server's own; fine behind NAT, otherwise fix its DNS"
fi
state() { docker compose -f "$ETC/compose.yml" ps --format '{{.Name}} {{.Image}} {{.State}}' 2>/dev/null | sort || true; }
running_before=$(state)
docker compose -f "$ETC/compose.yml" up -d --quiet-pull >/dev/null 2>&1 \
  || { docker compose -f "$ETC/compose.yml" up -d; fail "the services did not start"; }
if [[ -n "$caddyfile_changed" && -n "$running_before" ]]; then
  docker compose -f "$ETC/compose.yml" restart caddy >/dev/null 2>&1 \
    || fail "Caddy did not restart with its new Caddyfile"
  did "restarted openledger-caddy with its new Caddyfile"
fi
running_after=$(state)
[[ -n "$running_after" ]] || fail "the services are not running: docker compose -f $ETC/compose.yml ps"
if [[ "$running_after" == "$running_before" ]]; then
  same "openledger-node and openledger-caddy running"
else
  did "started openledger-node and openledger-caddy"
fi

# The node itself, then the API through HTTPS as a client sees it.
healthy=""
for _ in $(seq 60); do
  docker exec openledger-node gl-node --health-check >/dev/null 2>&1 && { healthy=1; break; }
  sleep 1
done
[[ -n "$healthy" ]] || fail "the node did not become healthy: docker logs openledger-node"
curl_tls=()
if [[ -n "$test_tls" ]]; then
  root="$CADDY_DATA/data/caddy/pki/authorities/local/root.crt"
  for _ in $(seq 60); do [[ -s "$root" ]] && break; sleep 1; done
  [[ -s "$root" ]] || fail "Caddy made no local certificate authority: docker logs openledger-caddy"
  curl_tls=(--cacert "$root" --resolve "$domain:443:127.0.0.1")
fi
health=""
for _ in $(seq 90); do
  health=$(curl -fsS --max-time 5 "${curl_tls[@]}" "https://$domain/health" 2>/dev/null) && break
  sleep 2
done
[[ "$health" == '{"status":"ok"}' ]] \
  || fail "https://$domain/health did not answer with a valid certificate (got: ${health:-nothing}): docker logs openledger-caddy"
say "  https://$domain/health: $health"
# This installer, once it has run to the end: what `openledger upgrade
# --binary` runs, and what an upgrade keeps for a rollback — never one that
# failed halfway.
put "$ETC/install.sh" 0700 < "$self"
# An upgrade this run completes (`openledger upgrade`, or the installer run
# again by hand after one failed) is finished.
rm -f "$ETC/previous/pending"

step "done"
if [[ $changes -eq 0 ]]; then
  say "Nothing to change: openledger is set up and running at https://$domain"
else
  say "openledger is running at https://$domain"
fi
# The key on a terminal only: output kept in a log (cloud-init, automation)
# gets where it is instead.
if [[ -n "$new_key" && -t 1 ]]; then
  cat <<EOF

  Operator key: $new_key

  It is shown this once; it is kept in $env_file, which only root reads. It is
  the node's own key — admin of every company ledger. Keep it to yourself and
  give each person a key of their own.
EOF
else
  say "
  Operator key: in $env_file (root only): sudo sed -n 's/^GL_NODE_API_KEY=//p' $env_file"
fi
cat <<EOF

  Manage:   sudo openledger company add NAME; sudo openledger person add NAME …;
            sudo openledger status (sudo openledger help for the rest)
  Settings: $ETC   Data: $DATA
  Backups:  nightly into /var/lib/openledger/backups (14 kept): copy them off
            the server, encrypted — they hold the node's keys (OPERATIONS)
  Logs:     docker logs openledger-node, docker logs openledger-caddy
EOF
