#!/usr/bin/env bash
# Prepare the three-node compose stack (deploy/docker-compose.yml) as a mesh
# that replicates over direct addresses on the Docker network, with nothing
# going to n0 (docs/build-log/001-peer-discovery).
#
#   deploy/mesh-init.sh            # once, before the first `up`
#   docker compose -f deploy/docker-compose.yml up -d    # or docker-compose
#   deploy/mesh-init.sh --ledger acme   # later, stack up: one more company
#                                       # (its own mesh; see "--ledger" below)
#
# It
#   1. creates deploy/.env with a fresh API key per node, if there is none;
#   2. picks a fresh meshId and swarmTopic for this mesh — unless MESH_ID is
#      given (below);
#   3. asks each node for its EndpointId (`gl-node --node-id`, which creates the
#      node key in the node's volume and starts nothing);
#   4. writes deploy/mesh/node-{0,1,2}.json: relayMode "custom" with no relay,
#      listenPort 4433, and each peer's id in bootstrapEndpointIds with its
#      address "node-N:4433" in peerAddresses.
#
# EXISTING HISTORY. A node's records are signed under its mesh's meshId, and a
# different meshId makes every one of them fail verification. So if any node's
# volume already holds a ledger, this script refuses unless MESH_ID names the
# meshId that history was signed under — for stacks from before this script,
#
#   MESH_ID=openledger/docker-dev deploy/mesh-init.sh
#
# (SWARM_TOPIC may be given too.) Never `down -v` a stack whose history you
# want: that deletes the volumes, and the history with them.
#
# deploy/mesh/ and deploy/.env are gitignored: they belong to this installation.
# The mesh configs are written 0644 so the container's user can read them; they
# hold the mesh's swarmTopic (with one member's id, enough to join its gossip
# overlay), so keep the deploy/ directory to yourself.
set -euo pipefail
cd "$(dirname "$0")"

fail() { printf 'mesh-init: %s\n' "$*" >&2; exit 1; }

if docker compose version >/dev/null 2>&1; then
  compose=(docker compose -f docker-compose.yml)
elif command -v docker-compose >/dev/null 2>&1; then
  compose=(docker-compose -f docker-compose.yml)
else
  fail "neither 'docker compose' nor 'docker-compose' is available"
fi
command -v jq >/dev/null || fail "jq is required (to write the mesh configs)"
command -v openssl >/dev/null || fail "openssl is required (to generate the API keys)"

# A random (version 4) UUID from openssl, which is already required: `uuidgen`
# can fall back to a time-based UUID, and the swarm topic must not be guessed.
new_uuid() {
  local hex
  hex=$(openssl rand -hex 16)
  [[ "$hex" =~ ^[0-9a-f]{32}$ ]] || fail "openssl did not produce random bytes"
  printf '%s-%s-4%s-%x%s-%s\n' "${hex:0:8}" "${hex:8:4}" "${hex:13:3}" \
    $(( (0x${hex:16:1} & 3) | 8 )) "${hex:17:3}" "${hex:20:12}"
}

# ── --ledger NAME: one more company on the running stack (003) ───────────────
# Adds ledger NAME to every node, in a mesh of its own: a fresh meshId and
# swarmTopic (MESH_ID and SWARM_TOPIC to choose), signing and P2P on, a UDP
# port of its own — the next above every port the nodes' ledgers use, the same
# on every node (LEDGER_PORT to choose) — and the other nodes' ids with their
# addresses "node-N:<port>". Each node makes the ledger's key as it adds it
# (`gl-node ledger add`, which prints the id); once every id is known, each
# node's ledger.json gets its peers and the ledger restarts with them
# (`gl-node ledger restart`). A failure part way removes the ledger again from
# the nodes it reached (to ledgersDir/.removed/; nothing is deleted).
if [[ "${1:-}" == "--ledger" ]]; then
  [[ $# -eq 2 ]] || fail "usage: deploy/mesh-init.sh --ledger NAME"
  name=$2
  [[ "$name" =~ ^[a-z0-9][a-z0-9-]{0,39}$ && "$name" != default ]] \
    || fail "\"$name\" is not a ledger name: 1 to 40 of a-z, 0-9 and -, not starting with -, and not \"default\""
  on() {  # node, command…: run in that node's container, as the node's user
    local node=$1
    shift
    "${compose[@]}" exec -T "node-$node" "$@"
  }
  # The node's ledgersDir as the container sees it (stacks set up before it
  # was in gl-node.docker.json use the default, under the image's /data).
  ledgers_dir() {
    local dir
    dir=$(jq -r '.ledgersDir // "./data/ledgers"' "mesh/node-$1.json") \
      || fail "cannot read deploy/mesh/node-$1.json"
    if [[ "$dir" == /* ]]; then echo "$dir"; else echo "/data/${dir#./}"; fi
  }
  for node in 0 1 2; do
    on "$node" true >/dev/null 2>&1 \
      || fail "node-$node is not running: set up and start the stack first (deploy/mesh-init.sh, then ${compose[*]} up -d)"
  done

  if [[ -n "${LEDGER_PORT:-}" ]]; then
    # No leading zero: bash would read it as octal, jq as decimal.
    [[ "$LEDGER_PORT" =~ ^[1-9][0-9]{0,4}$ ]] && (( LEDGER_PORT < 65536 )) \
      || fail "LEDGER_PORT must be a UDP port number, 1 to 65535"
    port=$LEDGER_PORT
  else
    used=4433  # the config file's ledger (gl-node.docker.json)
    for node in 0 1 2; do
      highest=$(on "$node" sh -c 'cat "$1"/*/ledger.json 2>/dev/null; true' sh "$(ledgers_dir "$node")" \
        | jq -s '[.[] | .p2p.listenPort? // 0] | max // 0') \
        || fail "could not read the ledgers' settings on node-$node"
      if (( highest > used )); then used=$highest; fi
    done
    port=$((used + 1))
  fi
  mesh_id=${MESH_ID:-$(new_uuid)}
  swarm_topic=${SWARM_TOPIC:-"openledger/$(new_uuid)"}

  settings() {  # peers-json: {"<EndpointId>": <node>, …} ("{}" for none)
    # No peers yet (the key step): "custom" with nothing to reach is refused.
    jq -n --argjson peers "$1" --arg mesh "$mesh_id" --arg topic "$swarm_topic" \
      --argjson port "$port" '{
        signing: { enabled: true },
        p2p: {
          enabled: true,
          meshId: $mesh,
          swarmTopic: $topic,
          relayMode: (if ($peers | length) > 0 then "custom" else "disabled" end),
          listenPort: $port,
          bootstrapEndpointIds: ($peers | keys),
          peerAddresses: ($peers | with_entries(.value = ["node-\(.value):\($port)"]))
        }
      }'
  }

  added=()
  undo() {
    [[ $? -eq 0 ]] && return
    for node in ${added[@]+"${added[@]}"}; do
      if on "$node" gl-node ledger remove "$name" >/dev/null 2>&1; then
        echo "mesh-init: took $name off node-$node again (its folder is in ledgersDir/.removed/)" >&2
      else
        echo "mesh-init: node-$node still has $name; remove it there: ${compose[*]} exec node-$node gl-node ledger remove $name" >&2
      fi
    done
  }
  trap undo EXIT

  declare -a ids
  for node in 0 1 2; do
    # The settings go in through stdin to a file only the node's user reads.
    out=$(settings '{}' | on "$node" sh -c \
      'f=$(mktemp) && cat > "$f" && gl-node ledger add "$1" --settings "$f"; s=$?; rm -f "$f"; exit $s' \
      sh "$name") || fail "node-$node did not add $name (its answer is above)"
    added+=("$node")
    id=$(printf '%s\n' "$out" | sed -n 's/^ *node id: *\([0-9a-f]\{64\}\)$/\1/p')
    [[ "$id" =~ ^[0-9a-f]{64}$ ]] || fail "node-$node did not report $name's node id (got: $out)"
    ids[$node]=$id
    echo "node-$node  $name  $id"
  done

  for node in 0 1 2; do
    peers=$(for peer in 0 1 2; do
      [[ $peer == "$node" ]] || printf '%s %s\n' "${ids[$peer]}" "$peer"
    done | jq -cRn '[inputs | split(" ") | {(.[0]): (.[1] | tonumber)}] | add')
    # Written beside the old file and renamed over it: a restart reads all of
    # it or none, and refused settings leave the ledger serving as it was.
    settings "$peers" | on "$node" sh -c \
      'umask 077 && cat > "$1/$2/.ledger.json.new" && mv "$1/$2/.ledger.json.new" "$1/$2/ledger.json"' \
      sh "$(ledgers_dir "$node")" "$name" || fail "node-$node: could not write $name's settings"
    on "$node" gl-node ledger restart "$name" >/dev/null \
      || fail "node-$node did not restart $name with its peers (its answer is above)"
  done
  # Done on every node: nothing below takes it off again.
  trap - EXIT

  cat <<EOM

Ledger $name is on node-0, node-1 and node-2, in a mesh of its own (meshId $mesh_id, UDP $port).
APIs:    http://127.0.0.1:4000/ledgers/$name/graphql (node-0), :4001 (node-1), :4002 (node-2)
People:  ${compose[*]} exec node-0 gl-node user --ledger $name add --name "…" --role admin
EOM
  exit 0
fi

if [[ -e mesh ]]; then
  if [[ -d mesh/node-0.json || -d mesh/node-1.json || -d mesh/node-2.json ]]; then
    fail "deploy/mesh/ holds directories where configs belong — made by a compose 'up' run before this script. Remove deploy/mesh/ (on Linux it is root-owned: sudo rm -r deploy/mesh) and run this again."
  fi
  fail "deploy/mesh/ exists: this mesh is already initialised. To replace it with a NEW mesh and no history: docker compose down -v, remove deploy/mesh/, run this again. To keep the history: remove deploy/mesh/ only, keep the volumes, and run this again with MESH_ID set (see the header)."
fi

if [[ ! -f .env ]]; then
  keys=()
  for node in 0 1 2; do
    key=$(openssl rand -hex 32)
    [[ "$key" =~ ^[0-9a-f]{64}$ ]] || fail "openssl did not produce a key"
    keys+=("$key")
  done
  (
    umask 077  # the keys file only
    {
      echo "# Per-node API keys, generated by deploy/mesh-init.sh. Never commit this file."
      for node in 0 1 2; do echo "GL_NODE_${node}_API_KEY=${keys[$node]}"; done
    } > .env
  )
  echo "created deploy/.env with a fresh API key per node"
fi

"${compose[@]}" build --quiet

mesh_id=${MESH_ID:-$(new_uuid)}
swarm_topic=${SWARM_TOPIC:-"openledger/$(new_uuid)"}

# From here on files are written: a failure removes the partial mesh, so the
# script can simply be run again.
mkdir mesh
trap '[[ $? -eq 0 ]] || rm -rf mesh' EXIT

# One config per node from gl-node.docker.json: the identity first (no peers
# yet — they are not known), then the full config once every id is.
write_config() {  # node, peers-json: {"<EndpointId>": <node>, …} ("{}" for none)
  local path="mesh/node-$1.json"
  # No peers yet (the identity step): nothing to reach, and "custom" with
  # neither a relay nor an address is refused at boot.
  jq --indent 4 --argjson peers "$2" --arg mesh "$mesh_id" --arg topic "$swarm_topic" '
    .p2p += {
      meshId: $mesh,
      swarmTopic: $topic,
      relayMode: (if ($peers | length) > 0 then "custom" else "disabled" end),
      listenPort: 4433,
      bootstrapEndpointIds: ($peers | keys),
      peerAddresses: ($peers | with_entries(.value = ["node-\(.value):4433"]))
    }' gl-node.docker.json > "$path"
  chmod 644 "$path"  # the container's user must read it (see the header)
}

# Identity configs first: every container below mounts deploy/mesh/node-N.json,
# and a mount of a missing file makes Docker create a directory in its place.
for node in 0 1 2; do
  write_config "$node" '{}'
done

# Refuse a fresh meshId over existing history (see the header).
if [[ -z "${MESH_ID:-}" ]]; then
  for node in 0 1 2; do
    if "${compose[@]}" run --rm --no-deps --entrypoint sh "node-$node" \
         -c 'test -s /data/ledger.bean' >/dev/null 2>&1; then
      fail "node-$node's volume already holds a ledger, signed under an earlier meshId; a fresh one would make all of it fail verification. Run again with MESH_ID=<that meshId> (stacks from before this script: MESH_ID=openledger/docker-dev)."
    fi
  done
fi

declare -a ids
for node in 0 1 2; do
  id=$("${compose[@]}" run --rm --no-deps --entrypoint gl-node "node-$node" --node-id | tr -d '\r' | tail -1)
  [[ "$id" =~ ^[0-9a-f]{64}$ ]] || fail "node-$node did not report an EndpointId (got: $id)"
  ids[$node]=$id
  echo "node-$node  $id"
done

for node in 0 1 2; do
  peers=$(for peer in 0 1 2; do
    [[ $peer == "$node" ]] || printf '%s %s\n' "${ids[$peer]}" "$peer"
  done | jq -cRn '[inputs | split(" ") | {(.[0]): (.[1] | tonumber)}] | add')
  write_config "$node" "$peers"
done

cat <<EOF

The mesh is ready: deploy/mesh/node-{0,1,2}.json (meshId $mesh_id).
Start it:   ${compose[*]} up -d
APIs:       http://127.0.0.1:4000 (node-0), :4001 (node-1), :4002 (node-2) — keys in deploy/.env
EOF
