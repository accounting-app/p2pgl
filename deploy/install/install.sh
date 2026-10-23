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
#   - restarts on failure and on boot, and rotated logs.
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
  label=local
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
  label=$version
fi
digest=$(sha256sum "$work/gl-node" | cut -c1-12)
tag="openledger/gl-node:$label-$digest-u$node_uid"
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
# Written by the openledger installer: what the openledger command needs.
DOMAIN=$domain
TEST_TLS=$test_tls
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
  openledger key                     the operator key
  openledger status                  the services, the node and HTTPS as a client sees it"
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
  key)
    key=$(sed -n 's/^GL_NODE_API_KEY=//p' /opt/openledger/env)
    [[ -n "$key" ]] || fail "no GL_NODE_API_KEY in /opt/openledger/env"
    printf '%s\n' "$key" ;;
  status)
    docker compose -f /opt/openledger/compose.yml ps --format '  {{.Name}}: {{.Status}}'
    printf '  node: %s\n' "$(node --version)"
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
    printf '\n'
    node ledger list
    exit "${status:-0}" ;;
  -h|--help|help) printf '%s\n' "$usage" ;;
  *) fail "unknown command $what
$usage" ;;
esac
COMMAND

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
  Settings: $ETC   Data: $DATA (back it up; OPERATIONS, Backups)
  Logs:     docker logs openledger-node, docker logs openledger-caddy
EOF
