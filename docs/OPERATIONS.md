# Operating a gl-node

How to set up, back up, upgrade, roll back and watch a node. The README is the
reference for every config option; this page is the procedure.

## The production template

[`deploy/gl-node.production.json`](../deploy/gl-node.production.json) is a
config for the **Docker image**: its paths are under `/data` (the image's
working directory — a node refuses a `ledgerPath` outside its working
directory), and it binds `0.0.0.0` inside the container, which is safe only
because the container's port is published on the host's loopback interface
(`-p 127.0.0.1:4000:4000`, README *Docker*). For a node run directly on a host,
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

These **boot without being set, but the node is not ready** until they are:

| Setting | If left as shipped |
|---|---|
| `allowedHosts` | `ledger.example.com` matches no real request: every API call gets `403`. Set the host name clients use through the terminator. |
| `trustedProxies` | Every client behind the terminator shares one rate-limit bucket (boot warns). Set the exact IP address the terminator connects from. |
| `p2p.bootstrapEndpointIds` | Empty: the node accepts writes but **takes no records from any peer** — it is a mesh of one, and boot only says so at INFO. List the EndpointIds of the other nodes (each logs its own at boot: `Iroh endpoint bound node_id=…`). |
| `p2p.relayMode` | `"n0"`, the only mode in which nodes reach each other today: n0's public discovery and relays connect them, and see each node's IP address, its peers and its traffic timing — not ledger data. With `"disabled"` a node reaches **no peer at all**, on any machine, because nothing yet tells it where its peers are (CHANGELOG, *Known limits*). |

## What a node keeps

| File | What it is | Back it up? |
|---|---|---|
| `ledger.bean` | The ledger, in Beancount format | **Yes** |
| `ledger.bean.journal` | Writes not yet folded into the `.bean` (the commit journal); a clean stop folds it in | **Yes**, together with the `.bean`, when present |
| `ledger.bean.journal.torn-*` | A journal set aside after a crash cut a record short; no boot reads it | Keep it with the backup for diagnosis |
| `iroh.secret` (`p2p.secretKeyPath`) | The node's key: its network identity **and** its signing key | **Yes**, separately and offline — see below |
| the config file | The node's settings | Yes |
| the API key | Wherever `GL_NODE_API_KEY` comes from (or `data/api.key` on a loopback node) | Yes, as a secret |
| `ledger.bean.lock` | A lock held while the node runs | No |

**The node key** is the node's identity on the mesh and the key its records are
signed with. Lose it and the node must rejoin under a new identity (every peer's
`bootstrapEndpointIds` changes). Leak it and anyone can write as that node: it
is a private key. Keep its backup encrypted and apart from the ledger backups.

## Backups

1. Stop the node (`SIGTERM`, and wait for the process to exit; it exits 0).
2. Copy `ledger.bean` and, if present, `ledger.bean.journal` together, plus the
   config.
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
