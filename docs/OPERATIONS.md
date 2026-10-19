# Operating a gl-node

How to set up, back up, upgrade, roll back and watch a node. The README is the
reference for every config option; this page is the procedure.

## The production template

[`deploy/gl-node.production.json`](../deploy/gl-node.production.json) is a
config for the **Docker image**: its paths are under `/data` (the image's
working directory — a node refuses a `ledgerPath` outside its working
directory), and it binds `0.0.0.0` inside the container, which is safe only
because the container's port is published on the host's loopback interface
(`-p 127.0.0.1:4000:4000`, README *Docker*). The node's other companies'
ledgers go in `/data/ledgers` (`ledgersDir`), in the same volume
(*Adding a company*). For a node run directly on a host,
change `bindAddress` to `127.0.0.1`, put the HTTPS terminator on the same host,
and make the paths relative to the directory the node runs in.

On any bind other than loopback the node must sit behind an HTTPS terminator (a
reverse proxy); it does not serve TLS itself (`tls.mode: "terminated"`). Only the
terminator listens publicly.

### Before the first boot

As shipped, the template **refuses to boot** until these are set — the refusal
names what is missing:

| Setting | What to put there |
|---|---|
| `p2p.swarmTopic` | A topic of your own for this mesh, e.g. `openledger/<uuid>`; the public default is refused. The same value on every node of the mesh. |
| `p2p.meshId` | **New mesh:** a fresh random UUID (`uuidgen`), the same on every node. **Existing mesh:** its current `swarmTopic`, copied byte for byte (README, *Mesh identity*). Never reuse a value from this repository or another mesh. |
| `GL_NODE_API_KEY` (environment) | `openssl rand -hex 32`, a different key per node. Keep it out of the config file and out of shell history (a `.env` file only the node's user can read). |
| `p2p.relayUrl` **or** `p2p.peerAddresses` | How the nodes find each other — the template runs `relayMode: "custom"`, which never uses n0 and refuses to boot with neither. **`relayUrl`**: `https://<your relay>` (see *Running a relay*), the same on every node; nodes behind routers reach each other through it. **`peerAddresses`**: each peer's `host:port`, for nodes with reachable addresses — and then a fixed `p2p.listenPort` (UDP) on every node, open in its firewall. Both together is fine. |

These **boot without being set, but the node is not ready** until they are:

| Setting | If left as shipped |
|---|---|
| `allowedHosts` | `ledger.example.com` matches no real request: every API call gets `403`. Set the host name clients use through the terminator. |
| `trustedProxies` | Every client behind the terminator shares one rate-limit bucket (boot warns). Set the exact IP address the terminator connects from. |
| `p2p.bootstrapEndpointIds` | Empty: the node accepts writes but **takes no records from any peer** — it is a mesh of one, and boot only says so at INFO. List the EndpointIds of the other nodes: run `gl-node --node-id` on each (same config and key path as the node; it creates the key on first use and starts nothing). |

## Running a relay

A mesh whose nodes sit behind routers (offices, laptops) needs a relay: a
small server with a public address that every node connects out to, and that
passes their traffic when they cannot reach each other directly. It is the
official `iroh-relay` server; `deploy/iroh-relay/` builds it at the version the
nodes use. Traffic through it stays end-to-end encrypted — the relay sees which
nodes talk to each other and when, never ledger data — and it is yours, so n0
sees nothing.

1. **A server and a name.** Any small Linux server with a public IP. Point a
   DNS name at it (`relay.example.com`), and open TCP 443 and 80 and UDP 7842.
   Port 443 must reach the relay directly — no proxy that terminates TLS in
   front of it: the relay serves its own HTTPS, and Let's Encrypt validates it
   on that port.
2. **The config.** Copy `deploy/iroh-relay/relay.toml.example` to `relay.toml`
   and fill in the hostname, a contact address for Let's Encrypt, and the
   allowlist: the EndpointId of **every node of the mesh** (`gl-node --node-id`
   on each). The relay obtains and renews its certificate from Let's Encrypt
   by itself. Nodes accept only a certificate from a public authority; a relay
   with a company's own certificates is planned (`relayCaCert`), not supported
   yet.
3. **Run it.**
   ```bash
   docker build -t openledger/iroh-relay:1.0.3 deploy/iroh-relay
   docker run -d --restart unless-stopped --name iroh-relay \
     -p 80:80 -p 443:443 -p 7842:7842/udp \
     -v "$(pwd)/relay.toml:/etc/iroh-relay/relay.toml:ro" \
     -v iroh-relay-certs:/var/lib/iroh-relay \
     openledger/iroh-relay:1.0.3
   ```
4. **The nodes.** Each sets `"relayMode": "custom"` and
   `"relayUrl": "https://relay.example.com"` — one relay per mesh, the same URL
   on every node. A node's boot log then says `p2p.relayMode is custom — the
   mesh's own relay and direct addresses only; nothing goes to n0`.
5. **Adding or removing a node:** edit the allowlist and restart the relay
   (`docker restart iroh-relay`); nodes reconnect on their own. The image
   refuses to start without `relay.toml` mounted, rather than run open. A node not on
   the allowlist is refused outright — it never comes online at the relay.

**One relay per mesh.** A node registers at exactly one relay, and that is
where its peers look for it. If the relay is down, nodes that can reach each
other directly (same network, or `peerAddresses`) keep syncing; the rest wait
until it is back. Watch it like any service: that the container is running
and `https://relay.example.com/` answers, and its log (`docker logs
iroh-relay`) — a node it refuses shows as a `not authorized` warning, which
does not name the node, so compare the allowlist with the nodes' ids when one
cannot connect.

For a **hosted relay serving many customers**, the example config shows an HTTP
check instead of the allowlist: the relay asks your service about each
connecting node, so admitting or removing one needs no restart.

## What a node keeps

| File | What it is | Back it up? |
|---|---|---|
| `ledger.bean` | The ledger, in Beancount format | **Yes** |
| `ledger.bean.journal` | Writes not yet folded into the `.bean` (the commit journal); a clean stop folds it in | **Yes**, together with the `.bean`, when present |
| `ledger.bean.journal.torn-*` | A journal set aside after a crash cut a record short; no boot reads it | Keep it with the backup for diagnosis |
| `iroh.secret` (`p2p.secretKeyPath`) | The node's key: its network identity **and** its signing key | **Yes**, separately and offline — see below |
| the config file | The node's settings | Yes |
| the API key | Wherever `GL_NODE_API_KEY` comes from (or `data/api.key` on a loopback node with no proxy in front) | Yes, as a secret |
| `ledger.bean.lock` | A lock held while the node runs | No |
| `ledgersDir/<name>/` (`data/ledgers/…`) | Each other ledger's folder: its `ledger.json`, `.bean`, journal and `iroh.secret`, the same files as above | **Yes**, every folder, its key apart like the node's |
| `ledgersDir/.removed/` | Removed ledgers' folders, whole (*Adding a company*) | Yes, for as long as you must keep a former client's books |

**The node key** is the node's identity on the mesh and the key its records are
signed with. Lose it and the node must rejoin under a new identity (every peer's
`bootstrapEndpointIds` changes). Leak it and anyone can write as that node: it
is a private key. Keep its backup encrypted and apart from the ledger backups.

## Backups

1. Stop the node (`SIGTERM`, and wait for the process to exit; it exits 0).
2. Copy `ledger.bean` and, if present, `ledger.bean.journal` together, plus the
   config. On a node with several ledgers, copy every folder in `ledgersDir`
   too, `.removed/` included; each restores on its own, like a node of one.
3. Start the node again.

Back up while the node is stopped: a copy taken while it runs can pair a `.bean`
with a journal from a different moment, and that has not been tested. On a mesh
the other nodes keep serving meanwhile, and this one catches up on restart.

Keep backups off the machine and encrypted, and **test a restore** — a backup
nobody has restored is not yet a backup.

## Restoring a backup

1. Stop the node.
2. **Delete `ledger.bean` and `ledger.bean.journal`**, then copy the backup's
   files in. Boot reads the `.bean` and the journal together, so a journal left
   behind from after the backup would be merged into the "restored" ledger.
3. Start the node and check `{ verify { ok quarantined } }` — `ok` is `true` **and** `quarantined` is empty — and a balance you know.
4. **On a mesh, make no write on this node until it has caught up.** Its own
   records written after the backup now exist only on its peers; a write made
   before they come back can re-issue sequence numbers (lamport) this node has
   already signed — the duplicate the audits' M-18 fix exists to prevent. Wait
   until `{ verify { nodesChecked } }` on this node equals a
   peer's, then resume writes.

## Upgrading

Upgrade **every node of a mesh**, one at a time, to the same release. A node
left on an older release may refuse records a newer one writes.

1. Read the CHANGELOG from your version up, *Breaking* first.
2. Stop the node and take a backup (above).
3. Replace the binary or image. Config keys added by the new release can be set
   now — an older binary refuses a config with keys it does not know.
4. Start it and check:
   - `GET /health` reports the new `version`;
   - `{ verify { ok quarantined } }`: `ok` is `true` and `quarantined` is empty
     (`ok` judges only the records the node serves, so it stays `true` while
     records are held back);
   - a balance you know is unchanged;
   - a record written on another node after this one restarted arrives here,
     and one written here arrives there;
   - the boot log has no line listed under *What to watch*.
5. Move to the next node.

## Rolling back

1. Before anything else, **list the writes made since the upgrade** (on every
   node): a rollback restores backups, and they will need entering again.
2. Stop the node.
3. Put back the previous binary or image, **and restore the backup taken before
   the upgrade** (*Restoring a backup*, above, including step 4). The previous
   release may not read what the new one wrote.
4. Remove config keys the previous release does not know.
5. Start it and run the same checks as after an upgrade.

Roll back every node of the mesh, as you upgraded every node.
Every release rehearses this upgrade and rollback from the previous release's
binary, on one machine (`docs/RELEASE.md`).

### To 0.2.0, the release with several ledgers (from 0.1.0)

- **At the swap:** a `ledgerPath` inside `./data/ledgers` (the default of the
  new `ledgersDir`) is refused at boot. Such a node sets `ledgersDir`
  elsewhere in the same step (step 3 of *Upgrading*), or moves its ledger
  first. The other new keys — `ledgersDir`, `maxLedgers`,
  `http.maxRequestsPerLedger` — are each node's own and can be set at its
  swap too; the production template sets `ledgersDir: "/data/ledgers"`.
- **After:** nothing changes until a folder appears in `ledgersDir`; the
  config file's ledger is `default`, at `/graphql` as before. Give a
  container `stop_grace_period: 60s` (*Sizing a node with several ledgers*);
  the compose stack has it. `gl-node ledger`, `gl-node user` and
  `gl-node --node-id` are new in this release.
- **Rolling back with companies added:** 0.1.0 serves the config file's ledger
  only, and refuses a config with keys it does not know: remove the keys above.
  The folders in `ledgersDir` are left as they are, not served, and served
  again once the node is upgraded again; their other nodes keep their books
  meanwhile.

## People and keys

Each person who uses the API gets a key of their own, with a role: `read`,
`write` or `admin` (README, *Using Auth* and *People and keys*). Grants live in
the ledger and replicate, so a key issued on one node works on every node of
the mesh. Keep the operator key (`GL_NODE_API_KEY`) to yourself; give people
their own.

**Before the first grant.** People's keys need signing on (every mesh signs)
and auth on. To keep grants on chosen nodes only, list them in
`auth.adminNodes` (their EndpointIds, the same list on every node): grants
written on any other node then count nowhere, and that node refuses them with
`NOT_AN_ADMIN_NODE`.

**Commands.** On an admin node, as the node's user (in Docker,
`docker exec <container> gl-node …`):

| Task | Command |
|---|---|
| Give someone access | `gl-node user add --name "Ana Ruiz" --role write [--expires 2026-12-31]` |
| See who has access | `gl-node user list` |
| Change a role, or replace a lost or leaked key | `gl-node user add --user <id> --role <role>`: a new key; the old one stops working |
| Fix a name | `gl-node user rename <id> --name "…"` |
| End someone's access | `gl-node user revoke <id>` |

`user add` prints the key **once**; the node keeps only its hash. Hand it over
on a channel you trust, never in the same message as the node's address. If
`user add` gives no answer (a timeout), run `user list` before trying again: a
second `add --name` makes a second person.

**Expiry** is checked by each node on its own clock: the key works through
the expiry day (UTC) and not after. An auditor's or a contractor's key should
have one.

**Revocation is final.** A revoked user id never comes back, even through a
key rotation another node made at the same time; give the person a new
`user add` if they return. A revoke reaches each node as fast as replication
does — seconds on a healthy mesh. **A node cut off from the mesh honours a
revoked key until it hears of the revoke.** For a leaked admin key, revoke it
and check that every node is replicating (*What to watch*, *Replication*);
stop any node you cannot reach until it has caught up.

**What the books show.** Access records are part of the ledger: anyone given
the `.bean` (an auditor, an export, a backup) sees user ids, names, roles,
expiry dates and key hashes, never a key. Every transaction, `open` and
`close` a person enters carries their user id (`entered-by`), and the journal
shows who entered each entry by name. Writes made with the operator key carry
none, and an entry typed into the `.bean` may not carry one (it is refused).

## Adding a company

Each company is a ledger of its own (README, *Several ledgers*), added and
removed while the node runs, as the node's user:

1. **Its settings.** Write the company's `ledger.json`: a fresh `meshId`
   (`uuidgen`) and `swarmTopic`, the mesh's relay, and the other nodes of its
   mesh in `bootstrapEndpointIds` (empty for the first node).
2. **Add it:** `gl-node ledger add acme --settings acme.json`. It prints the
   ledger's node id; give it to the other nodes of the company's mesh for their
   `bootstrapEndpointIds`, and back up `data/ledgers/acme/iroh.secret` apart,
   as you do the node's key.
3. **Its people:** `gl-node user --ledger acme add --name "…" --role admin`.
   Clients use `/ledgers/acme/graphql`.

To change a company's settings, edit its `ledger.json` and run `gl-node
ledger restart acme`; settings that are refused leave it serving as it was.
`gl-node ledger list` shows every ledger, and why one is not served.

**When a company leaves**, `gl-node ledger remove acme` stops its ledger —
requests already running finish, the journal is folded in — and moves its
folder to `data/ledgers/.removed/acme-<UTC time>/`. Its books and key stay
there; nothing is deleted. Keep the folder (and its backups) for as long as
your retention rules require, then delete it yourself. On the company's other
nodes, take this node's id out of `bootstrapEndpointIds`. To bring a company
back, move its folder back into `data/ledgers/` and run `gl-node ledger
restart <name>`.

If a command gives no answer (a timeout, `http.requestTimeoutSeconds`), the
change still runs to the end on the node: run `gl-node ledger list` before
trying again. A node that crashed in the middle of an add can leave a
`data/ledgers/.adding-<name>-…` folder; it was never served, no boot reads
it, and it can be deleted.

## Sizing a node with several ledgers

A node can serve up to 100 ledgers (README, *Several ledgers*). What limits it
is memory: every ledger's history lives in memory while the node runs.

| Per ledger | Memory |
|---|---|
| Empty | about 1 MiB |
| 10,000 entries | about 45 MiB |
| 100,000 entries | about 450 MiB (estimated from the above) |

Booting adds memory that stays with the process: ledgers start in parallel, up
to one per core, and each start uses about as much again as its ledger. On a
2-core server that is about two ledgers' worth; on 10 cores, ten. A 2-core,
2 GiB server holds about 35 ledgers of 10,000 entries. These are measurements
of one build on one machine
(`docs/build-log/003-multi-ledger-node/notes/measurements.md`); check yours
with `scripts/measure_ledgers.sh`.

- **Open files:** allow at least 4,096 (`ulimit -n`; systemd `LimitNOFILE`).
  A ledger with P2P uses about 5, and every HTTP connection one more.
- **Boot:** the config file's ledger starts first, then the others in
  parallel; 30 ledgers of 10,000 entries each served all of them 5 s after
  start on 10 cores. Give a container's health check a start period of at
  least 30 s, more for a large node on few cores.
- **Stop:** every ledger compacts its journal on the way out, all at once —
  about a second for 30 busy ledgers on 10 cores. A large node on few cores
  can need longer than `docker stop`'s 10 s: set `stop_grace_period: 60s`.
  If the stop is cut short, nothing is lost: the journal is intact and the
  next boot folds it in.
- **A busy ledger** answers `503 LEDGER_BUSY` (with `Retry-After: 1`) past
  `http.maxRequestsPerLedger` requests at once (default 64); the node's other
  ledgers are not slowed. A slot is taken only after the key check, so only
  that ledger's own callers can fill its slots — a person with a read key
  among them, until the request timeout. Clients should retry; each retry
  still counts against the rate limit below.
- **The rate limit is per client and ledger** (60 GraphQL requests a minute
  for each ledger a client uses): an accountant's app working across forty
  companies has forty budgets. Requests naming a ledger the node does not
  serve, and any request without a key that ledger accepts, share one
  strangers' budget per client, so trying made-up names gains nothing.
  `/health` keeps one node-wide budget per client (120 a minute). A flood from
  more than 8,192 addresses at one ledger in a minute leaves that ledger's new
  clients sharing one budget until it ends (the log says which ledger); its
  known clients are not affected.

## What to watch

`GET /health` answers liveness (the Docker image's `HEALTHCHECK` runs
`gl-node --health-check`). Beyond it, alert on these log lines; each needs a
person, and each warning says what to do.

**The ledger:**

| Log line starts with | Meaning |
|---|---|
| `this node booted with ledger records quarantined` | Records in the file are held out of the ledger (not served, in no balance). The per-record warnings before it give each one's reason and repair. |
| `ledger records QUARANTINED` / `quarantining a ledger record` | The same, from the signature check or the served-set rule. |
| `EVERY signature this node checked failed` | Almost always a wrong `p2p.meshId` or node key, not damage. API writes are refused until it is fixed; fix the config or key first and repair nothing. |
| `the ledger history carries a lamport gap` / `the ledger history has no single lamport gap` | A new node may not be able to join this mesh by normal sync; the warning names the join procedure (`p2p.joinFrom`). |

**Replication** — a node that has stopped exchanging with its peers still
answers `/health` and serves its own writes:

| Log line starts with | Meaning |
|---|---|
| `anti-entropy connect failed` | This node cannot reach a peer. Once is a blip; every interval for one peer means that peer is down or unreachable. |
| `rejected ALPN supply: signature` / `rejected ALPN supply: author not allowlisted` | A peer sent records this node refuses — a `meshId` or allowlist mismatch between the two, or a misbehaving peer. |
| `orphan buffer full` | Records arrive faster than their parents, or a peer floods; replication from it is stalling. |
| `failed to persist ALPN supply batch` | Records from a peer could not be written to disk (disk full, permissions). |

Any `ERROR` line, and a node that restarts repeatedly, need a person too. Set
`RUST_LOG` only if you keep `iroh::protocol=error` in it (README, *Log volume on
a public bind*), and rotate logs.
