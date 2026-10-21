# Changelog

All notable changes to this project are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/) — below 1.0, a minor version may
break compatibility.

## [Unreleased]

### Breaking

- **`tls.mode: "terminated"`, or a `trustedProxies` entry, makes a node public
  whatever its bind**
  (`docs/build-log/005-installer`, step 2). A loopback node behind a TLS proxy
  on the same host — declared by `tls.mode: "terminated"` or by naming the
  proxy in `trustedProxies` — is held to every rule a non-loopback node is: GraphiQL off,
  auth on, an `auth.apiKey` (or `GL_NODE_API_KEY`) rather than the generated
  key file, and a non-empty `allowedHosts`. Such a config that breaks one of
  them is now refused at boot, naming the rule; set the key in the
  environment and the proxy's host name in `allowedHosts`.

### Security

- **`/health` behind a proxy on the same host tells strangers `ok` and nothing
  else** (L-09, 005 step 2): a loopback node decided its `/health` detail by
  its bind, so a proxy on its own host served its version, heads and peer
  count to the internet. The detail is now for keys only on every public
  node (`NodeConfig::is_public`).

### Added

- **`accounts`, the chart of accounts over GraphQL** (`docs/build-log/006-list-accounts`,
  README *List Accounts*): every account with an `open`, sorted by name,
  whether or not it holds a posting, with `openedOn` (its earliest `open`),
  `closedOn` (while its last `open` or `close` by date is a `close`) and
  `currencies` (the union over its `open`s, which a transaction dated on or
  after the latest one may use; empty means any). A read key may call it. It
  carries the reports' complexity weight, so one request holds at most eight
  copies, and `verify` plus the four reports already fill a request.
- **`openledger`, the server's day-to-day command** (005 step 4, OPERATIONS
  *Installing on a server*), written by the installer to
  `/usr/local/sbin/openledger`: `company add | list | restart | remove`,
  `person add | list | rename | revoke`, `key`, `status` (the services, the
  node's version, `https://DOMAIN/health` as a client sees it, the
  companies). It runs the node's own commands in its container.
- **`gl-node ledger add NAME --new-mesh FROM-TO`** (`addLedger(newMeshPorts:)`,
  005 step 4): the node composes the company's `ledger.json` — signing and P2P
  on, a fresh `meshId` and `swarmTopic`, `relayMode: "disabled"` until it has
  peers (never n0), and the lowest UDP port in the range that no ledger has and
  nothing on the host holds. `gl-node ledger list` shows each ledger's port.
- **`deploy/install/install.sh`** (005 step 3, README and OPERATIONS
  *Installing on a server*): one command on a fresh Ubuntu or Debian server
  installs Docker (key checked by fingerprint), the release's `gl-node`
  (checked against `SHA256SUMS`, or `--binary`) in an image on the project's
  pinned base, its config (`gl-node init`) and operator key (root only), Caddy
  (pinned) for HTTPS with automatic certificates as the only public listener,
  a firewall (SSH, 80, 443, the companies' UDP ports), restarts and log
  rotation; a second run changes nothing. `scripts/rehearse_install.sh` runs
  it on fresh Lima VMs and checks the result from inside; `release.sh`
  refuses a release whose installer names another version or base.
- **`gl-node init --domain DOMAIN`** (005 step 2, README *Behind an HTTPS
  proxy on the same host*): writes the config of a node served through a TLS
  proxy on its own host — loopback bind, the proxy and the domain trusted,
  auth on with the key from the environment — never replacing an existing
  file, and checks it loads.

## [0.2.0] — 2026-10-19

Companies and accountants on one node: several company ledgers, each its own
mesh, people and keys, added and removed while the node runs; a key and a role
per person, and who entered each entry; nodes that find each other through the
mesh's own relay or their addresses, with nothing going to n0
(`p2p.relayMode: "custom"` or `"disabled"`; the default stays `"n0"`).

**Status: pilot,** as 0.1.0: its tests run nodes on one machine (and three in
Docker); it has not yet run across real networks. Run it beside your existing
books before relying on it.

**Upgrading from 0.1.0:** `docs/OPERATIONS.md`, *Upgrading* and *To 0.2.0*.

**Known limits.**

- No TLS in the node: on any non-loopback bind the API must sit behind an HTTPS
  terminator (`tls.mode: "terminated"`).
- `p2p.relayMode` still defaults to `"n0"`, so a config that does not set it
  keeps using n0's public relays and discovery (n0 sees each node's IP
  address, its peers and its traffic timing). The production template sets
  `"custom"`.
- A node built before Format v2 can neither read v2 records nor speak the v2
  wire; every node of a mesh runs the same release (OPERATIONS, *Upgrading*).
- Every ledger's history is held in memory: OPERATIONS *Sizing a node with
  several ledgers* gives the budget (about 45 MiB per 10,000 entries); at most
  100 ledgers a node.
- A backup is taken with the node stopped (seconds; the mesh's other nodes
  serve meanwhile).
- Pad synthesis is not wired in: a `pad` directive is kept and replicated but
  changes no balance.
- Linux binaries for amd64 and arm64; the one not native to the release
  machine is cross-compiled, and booted under emulation where the release's
  Docker host emulates it (`RELEASE-INFO.txt` says).

### Breaking

What can stop a 0.1.0 deployment from starting, or change what it does;
OPERATIONS *To 0.2.0* has the order to do it in.

- **`deploy/mesh-init.sh` needs `jq` instead of `python3`**
  (`docs/build-log/004-no-python`): the project's tools no longer use Python.
  The revert checks and the measurements are `scripts/revert_check.sh` and
  `scripts/measure_ledgers.sh` (Rust, `cargo xtask …`).
- **`ledgerPath` inside `ledgersDir` is refused at boot** (003): that folder
  holds the node's other ledgers, and the default `ledgersDir` is
  `./data/ledgers` — a `ledgerPath` such as `./data/ledgers/x.bean` must move.
- **`deploy/gl-node.production.json` uses `relayMode: "custom"`** and so
  refuses to boot until the mesh's own relay (`p2p.relayUrl`) or the peers'
  addresses (`p2p.peerAddresses`) are set; it no longer runs on n0's public
  servers by default. The node's own default stays `"n0"`, so existing configs
  are unchanged.
- **The compose stack mounts `deploy/mesh/node-N.json`** (written by
  `deploy/mesh-init.sh`) instead of the shared `gl-node.docker.json`. A stack
  with history keeps its signatures by running
  `MESH_ID=openledger/docker-dev deploy/mesh-init.sh`.

### Changed

- **The image's configs keep the other ledgers in `/data/ledgers`** (003 step
  5): `deploy/gl-node.production.json` and `gl-node.docker.json` set
  `ledgersDir`; the compose stack waits 60 s for a node to stop
  (`stop_grace_period`) and gives its health check a 30 s start period.
  `deploy/mesh-init.sh --ledger NAME` adds a company to the running stack in
  a mesh of its own. OPERATIONS has the upgrade and rollback notes.
- **A ledger's log lines no longer appear inside another ledger's P2P
  endpoint span** (003 step 5): iroh 1.0.3 keeps its `endpoint` span entered
  across an await while an endpoint binds, so on Linux the tasks a runtime
  thread ran meanwhile — another ledger's start, its requests — logged under
  that endpoint, and kept doing so. The node now binds each endpoint on a
  thread of its own.

### Security

- **rustls 0.23.46** (from 0.23.45), the TLS library under the P2P transport,
  relay and DNS clients: RUSTSEC-2026-0346 (`Debug` output of a client
  session exposed TLS secrets — medium), 0347, 0348 and 0349 (low).
- **Every GraphQL request passes a role check before anything runs**
  (`docs/build-log/002-users-and-roles`): queries need *read*, every mutation
  *write*, by operation type — so a mutation added later is closed to read-only
  keys without being guarded by hand — judged across every operation, alias
  and fragment in the request. A request that reaches the schema without an
  authenticated caller is refused. The node's key (`auth.apiKey`,
  `GL_NODE_API_KEY`, the generated key file) is the *operator* and may do
  everything, so nothing changes for existing setups; per-person keys and roles
  come next.

### Fixed

- The 0.1.0 known limit "nodes on different machines find each other only
  through n0" no longer holds: a mesh can use its own relay
  (`relayMode: "custom"`) or direct addresses (`p2p.peerAddresses`), with
  nothing going to n0 (`docs/build-log/001-peer-discovery`).

### Added

- **Several ledgers on one node** (`docs/build-log/003-multi-ledger-node`,
  README *Several ledgers*): beside the config file's ledger (`default`, at
  `/graphql` as before), every folder in **`ledgersDir`** (default
  `./data/ledgers`) is a ledger of its own — its `ledger.json` (the ledger's
  `signing`, `format`, `p2p`, `watchLedgerFile`, `auth.adminNodes`), its
  `.bean`, its node key and mesh, its people — served at
  `/ledgers/<name>/graphql`. Keys are per ledger; the operator key works on
  all. A ledger that does not load is logged and skipped while the rest
  serve. `gl-node user` and `gl-node --node-id` take `--ledger`.
  **`maxLedgers`** (default 100). Ledgers boot and stop in parallel; a busy
  ledger answers `503 LEDGER_BUSY` past **`http.maxRequestsPerLedger`**
  requests at once (default 64) without slowing the others; and a client's
  GraphQL rate limit (60 a minute) is per ledger, so one client working across
  many companies is not throttled by the total. OPERATIONS *Sizing a node with
  several ledgers* gives the memory budget. Nothing
  changes for a node with no ledger folders.
- **Ledgers added, removed and restarted while the node runs** (003 step 4,
  README *Adding and removing ledgers while the node runs*, OPERATIONS *Adding
  a company*): `gl-node ledger add NAME [--settings FILE] | list | restart
  NAME | remove NAME`, a client of the new operator-only node endpoint
  **`/node/graphql`** (`ledgers`, `addLedger`, `removeLedger`,
  `restartLedger`). `add` writes the folder under a temporary name and renames
  it into place, makes the ledger's node key and prints its id; `remove` waits
  for the ledger's requests in flight, stops it — every task it started, its
  journal folded in — and moves its folder to `ledgersDir/.removed/`, deleting
  nothing; `restart` picks up an edited `ledger.json`, or serves a folder that
  was refused at boot once fixed. The `default` ledger changes only with the
  node.
- **People's keys, from the ledger** (`docs/build-log/002-users-and-roles`):
  besides the operator key, the node accepts each person's key from the
  ledger's access records — `event "openledger-access"` grants and
  revocations, replicated to every node like any record, with a role (read,
  write, admin) and an optional expiry. Every node folds the same records in
  the same order to the same list, so a key works on every node of the mesh,
  and a revocation takes effect on each node as soon as it arrives there. Only
  the key's SHA-256 is stored, compared in constant time; every access record
  carries a random `record` value, so no two are ever the same record. People's
  keys are honoured **only on a node that signs** (`signing.enabled`; every
  mesh does): without signatures nothing proves who wrote a record, so a node
  with signing off accepts its operator key alone, and says so at boot. An
  access record typed into the `.bean` without an envelope is refused, and one
  with a made-up envelope fails its signature check. **`auth.adminNodes`**
  (optional; needs signing) limits whose access records count. `/health` shows
  its detail to any valid key, a person's included.
- **Managing people: the admin API and `gl-node user`**
  (`docs/build-log/002-users-and-roles`, README *People and keys*): an admin
  key can `grantAccess` (a new person, or a new role, expiry and key for one
  already on the list), `revokeAccess`, `renameUser` and list everyone
  (`accessList`). `gl-node user add | list | rename | revoke` does the same
  from the node's machine, with the operator key. A person's key is 32 random
  bytes, returned once; access records carry the person's name and the admin
  who made the change (`by`). A revocation is final: a user id once revoked is
  never granted again, so a key rotation that raced it loses. A node with auth
  or signing off keeps no access list and refuses the admin API
  (`NO_ACCESS_LIST`).
- **Who entered each write** (README *People and keys*, OPERATIONS *People
  and keys*): a transaction, `open` or `close` made with a person's key
  carries their user id (`entered-by: "u_…"`), part of the record and its
  signature. The journal's `Transaction` (and the `appendTransaction`
  payload) gains `enteredBy` and `enteredByName` — the person's latest name,
  kept after their access ends. Writes made with the operator key carry
  nothing new, so existing setups write exactly the records they did. One
  person entering the same entry twice through one node is still one record;
  two people entering it are two. An entry typed into the `.bean` with
  `entered-by` is refused.
- **`p2p.peerAddresses`** — where each allowlisted peer listens,
  `{ "<EndpointId>": ["host:port", …] }`. Host names are resolved at boot and
  every five minutes (every 10 s while an address has never resolved). With `relayMode: "disabled"` a node now reaches the peers
  listed here, with no third party involved; before, it reached no peer at
  all. An address is accepted only for a peer in `bootstrapEndpointIds`. An
  older binary refuses a config with this key
  (`docs/build-log/001-peer-discovery`).
- **`relayMode: "custom"` and `p2p.relayUrl`** — the mesh's own relay (an
  `iroh-relay` server) instead of n0's: nodes behind routers reach each other
  through it, and nothing goes to n0 — no n0 relay, no n0 discovery. One relay
  per mesh, `https` only. `relayUrl` with another mode, and `"custom"` with
  neither a relay nor `peerAddresses`, are refused at boot.
- **`gl-node --node-id`** — prints the node's EndpointId (creating its key on
  first use, by the same rule as boot) and exits without serving. Peers list
  this id in `bootstrapEndpointIds` and `peerAddresses`, and a relay in its
  allowlist — before the node ever starts.
- **The mesh's own relay, packaged** — `deploy/iroh-relay/`: the official
  `iroh-relay` 1.0.3 as a pinned image, with an example config (Let's Encrypt,
  an allowlist of the mesh's EndpointIds, the HTTP check for a hosted relay
  commented). `docs/OPERATIONS.md` *Running a relay* walks through it.
- **The compose stack replicates** — `deploy/mesh-init.sh` gives the three
  nodes a fresh mesh, their peers' ids and addresses on the Docker network;
  before, they ran side by side without syncing.
- **`p2p.listenPort`** — the UDP port the P2P endpoint listens on, so other
  nodes can list it in their `peerAddresses`. The default, `0`, keeps today's
  behaviour: a random port at every boot. A port already in use stops boot.

## [0.1.0] — 2026-10-07

The first release: a peer-to-peer, append-only, double-entry ledger in the
Beancount format, with a GraphQL API over HTTP and replication over Iroh QUIC.

**Status: pilot.** Its tests run nodes on one machine, over loopback; it has
not yet run across real networks. Run it beside your existing books
before relying on it.

**Security.** Every finding of the security audits (`docs/audits/`, from
`CLAUDE_SECURITY_AUDIT_0820.md` to `SECURITY_AUDIT_0927.md`) is closed: fixed,
or — for the few limits this release keeps — accepted with its reason in
[docs/audits/RESIDUALS.md](docs/audits/RESIDUALS.md).

**Known limits.**

- No TLS in the node: on any non-loopback bind the API must sit behind an HTTPS
  terminator (`tls.mode: "terminated"`).
- A node built before Format v2 can neither read v2 records nor speak the v2
  wire; every node of a mesh runs this release or later.
- Nodes on different machines find each other only through n0's public
  discovery and relay service (`p2p.relayMode: "n0"`, the default). Ledger
  traffic stays end-to-end encrypted, but n0 sees each node's IP address, its
  peers and its traffic timing. With `"disabled"` there is no way yet to give a
  node its peers' addresses, so it reaches no peer at all — on another machine,
  the same host or a Docker bridge.
- Pad synthesis is not wired in: a `pad` directive is kept and replicated but
  changes no balance.

> **First release:** the *Breaking* entries below describe changes from
> pre-release builds. A fresh install can skip them; anyone who ran a
> pre-release build reads them first.

The entries below were written as the work landed, starting with the two
audits:
[SECURITY_AUDIT_0922.md](docs/audits/SECURITY_AUDIT_0922.md), tracked in
[docs/audits/OUTSTANDING_TASKS_09_22.md](docs/audits/OUTSTANDING_TASKS_09_22.md) (T46–T60),
and [SECURITY_AUDIT_0922-v2.md](docs/audits/SECURITY_AUDIT_0922-v2.md), tracked in
[docs/audits/OUTSTANDING_TASKS_09_22_v2.md](docs/audits/OUTSTANDING_TASKS_09_22_v2.md)
(T61–T71); the later audits are tracked in `docs/audits/OUTSTANDING_TASKS_09_23.md`
to `OUTSTANDING_TASKS_09_27.md`. Each entry names its finding ID and task. For
the detail and any known residuals, see that task's "Done" note in the tracker.

> **Upgrading:** read *Breaking* first. Config files are parsed with
> `deny_unknown_fields`, so an **older binary refuses a config that uses any key
> added here**. Upgrade the binary before you edit the config. To roll back,
> remove the new keys first.

### Breaking

**Configuration**

- **`format.wire2` and `format.idv2` default to `true` (Format v2, T45).** A node writes its new records in Format v2 (an id that covers the author — M-10 — signed over a length-prefixed message — L-06) and dials and gossips in the wire-v2 encoding. Every node on this build accepts both formats and keeps verifying its v1 history; a node on a build from before Format v2 reads neither, so upgrade every node, or set both to `false` everywhere until you have.
- **`p2p.meshId` is required when `signing.enabled` is true (L-23).** A signing node without it refuses to boot; before, its signature domain fell back to `p2p.swarmTopic` with a warning. On an existing mesh set `meshId` to your current `swarmTopic`, byte for byte, on every node — that keeps every signature verifying, and can be done one node at a time. A new mesh should use a random value (`uuidgen`).
- **`auth.enabled` defaults to `true` (H-01).** A config with no `auth` section now requires `X-Api-Key` on `/graphql`. On a loopback bind with no key configured, the first boot generates one into `auth.apiKeyPath` (default `./data/api.key`, mode 0600) and later boots reuse it; clients must send it. To keep the old behaviour, set `"auth": { "enabled": false }` — loopback only, and boot WARNs every time. A public bind still needs a key you set.
- `externalFileEdits` is removed, and a config that still carries it is refused at boot by name. It only ever gated the file watcher, so use `watchLedgerFile: true` for that. Hand edits are always adopted (M-19, T52).
- Older binaries reject every new key listed under *Added* (`deny_unknown_fields`). That includes `watchLedgerFile`, `http.maxConnectionsPerIp` and the eight `p2p.antiEntropy*` keys (R-13).
- `auth.apiKey`, from the file or `GL_NODE_API_KEY`, must be printable ASCII with no surrounding whitespace. Boot refuses any other key and does not echo it. A key like that could never match an `X-Api-Key` header, so every request got `401` (L-50, T55).
- `"null"` in `cors.allowedOrigins` is refused at boot, and the guard refuses `Origin: null` whatever the config says (L-52, T55).
- `p2p.swarmTopic` now follows the `meshId` rules: non-empty, no surrounding whitespace, only ASCII letters, digits and `- _ . : /`, and at most 128 bytes. A topic containing a space or `|` no longer boots (M-31, T57).
- `allowedHosts` entries with a port, IPv6 brackets or a trailing dot are refused at boot, and the error names the spelling to use. Such entries never matched a request, so every request got `403` (0922-v2 §5, T71).
- The config file must be a regular file (a symlink to one is followed) of at most 1 MiB. A FIFO, directory, device or dangling link at `GL_NODE_CONFIG` is refused at once instead of hanging boot and `--health-check` (L-73, T77).

**HTTP**

- The node serves HTTP/1.1 only. Cleartext HTTP/2 (h2c, the `PRI * HTTP/2.0` preface) and HTTP upgrades are gone (M-22, T55).
- A request head over 64 KiB gets `431`. Because of buffer growth, a head that arrives in one burst can reach about 112 KiB before the check (M-41, T66).
- `/health` now sits behind the Host guard: an unlisted `Host` gets `403`. It also has its own limit of 120 requests a minute, with `429` past it (H-01 residual, L-42, T55).
- One IPv4 address or IPv6 /64 may hold at most `http.maxConnectionsPerIp` connections (default 64). Over-cap connections are closed before anything is read. Clients behind an unlisted proxy share one allowance, and so do Docker host-published ports. List the proxy in `trustedProxies` (M-33, T55).
- A connection that sends no request head within `http.headerReadTimeoutSeconds` of accept is dropped (T55).
- Under `tls.mode: "terminated"`, a plain `http://` `Origin` is no longer same-origin, except for loopback names (L-51, T55).

**Ledger files**

- A `.bean` that does not parse blocks every write with `PARSE_ERROR` until it is repaired. The node records nothing about the broken file (H-14, T61).
- Directives in the `.bean` with no envelope are adopted at boot as operator input. This covers hand-typed records and `open`/`close` lines from very old builds. They get this node's author, lamport and parents and are signed before the startup compaction. Entries that fail validation are quarantined, never dropped (H-13, T61).
- A block that starts with U+FEFF in the middle of the file is refused (L-62, T61). The parser refuses trailing tokens it cannot read instead of silently dropping them (M-25, T52).
- If the `.bean` is missing but a `.journal` exists beside it, boot refuses (H-15, T62).
- A FIFO, socket, device, directory or dangling symlink at the `.bean` or journal path refuses boot. A symlinked `.bean` created by the node's own user is followed: the node reads, journals, locks and compacts at the target, and the link is kept. Before T82 the target's journal was never read and the first compaction replaced the link with a regular file. A link owned by another user refuses boot (M-36, T67; L-84, T82). Since T87 the link is followed only from a directory the node's user owns and group and others cannot write — the ownership check and the follow were two path walks, and an account able to write the directory could swap the link between them — and only one link deep (a link to a link refuses boot; a directory link in the path is followed); a journal left beside the link, which the node would never read, refuses boot naming the remedy (M-60, M-61, T87).
- The journal, `.lock` and key file must be regular files owned by the node's uid, with a single link. The lock and key must be `0600`, and the journal appender requires an existing journal to have no group or other permission bits (0600 or stricter). A journal readable but not writable by others still loads at boot with a warning and is compacted away; one writable by others refuses boot. A key file over 4 KiB is refused (M-36, L-58, L-59, T67; L-49, T60).
- Damage anywhere in the journal except its final record refuses boot, and the error names the byte offset. A record length above the journal budget also refuses boot (M-43, T68).
- Every amount that is summed into a balance (posting units, cost, price, and the resolved elided leg) must have magnitude at most 10^21 (`MAX_AMOUNT_MAGNITUDE`), at any precision. The limit is inclusive, and trailing zeros no longer count against it. It is enforced identically by the API, the GraphQL scalar, peers, the journal and the file. A directive past it that is already on disk is quarantined at boot. `balance` and `price` directive amounts are not capped. More than 28 fractional digits are still refused instead of rounded (H-17, T65; M-50, T76).
- A directive a T65–T75 build quarantined for the old 21-significant-digit cap (for example `1.00000000 BTC @ 100000.00000000 USD`, or a `10^21` posting) loads again. It keeps the same content id and envelope, its children's parents resolve, and `verify` no longer reports `MissingParent`. Upgraded peers accept it (M-50, T76).
- Boot verifies the signature of every directive in the `.bean` that carries an envelope: with this node's own key for its own records as soon as the signer is installed, and with the author's key for everyone's once signing is enabled. A record whose signature does not verify — or that carries an author and lamport but no signature — is quarantined, never dropped: it stays in the file, out of the DAG and out of every balance, and the banner names it. A history this node wrote before enabling signing is quarantined the same way at its first signing boot; delete the `openledger-*` lines from those blocks to re-adopt them as signed operator input (H-20, T73).
- A signing node's author id is its key's public half whenever `signing.enabled`, P2P on or off; before T80 it was set only when P2P booted, so a node that signed with P2P off wrote `openledger-author: "local"` under a real signature, its own hand edits were quarantined for one process lifetime, and turning P2P on quarantined its entire history at every boot. Records carrying `"local"` whose signature verifies under the node's own key are re-attributed at boot (and on a live reconcile), keeping their signature; the next compaction writes the real author. No operator action (M-53, L-82, T80).
- A directive with only one of `openledger-author` / `openledger-lamport` is operator input on both file paths, not history: the lamport is re-stamped, this node's author is stamped when absent, a hand-typed signature is discarded and a new one made. A line whose `openledger-author` names **another node** is refused: quarantined as written at boot (at finalisation, once the node's identity is known) and rejected by the live reconcile. It used to be adopted unsigned with a warning, and then became the parent of this node's next write, so every later write was refused by every peer (M-47, T73; M-54, T79).
- A hand-typed `openledger-parents` line must name records this node serves; one naming a parent that exists nowhere, or one held only in the quarantine (which is never served), is quarantined at boot and rejected by the live reconcile (L-75, T73; H-22, T79). Hand lines that spell their own parents are adopted after the rest of the edit, parent before child, so two such lines in one edit are adopted in one boot whatever their order in the file (L-108, T89).
- Fixing a node-written record and appending lines in the same stop → edit → start is safe. When the boot signature check quarantines a record, every line of operator input not yet signed has its parents chosen again from what survives, and a line that cannot stand without the quarantined record (its hand-typed parent, or the `open` of its account) is quarantined as written with it. A reload after a failed commit runs the signature check before it signs operator input (H-22, T79). The new lines' lamports are stamped only after the signature check has settled the clock, so an edited lamport line beside them no longer lifts them past what peers accept (M-57, T84).
- A hand-typed `open` of an account that is already open is refused on both file paths exactly as the API refuses it (L-77, T73). "Already open" is judged against what the node serves, after the boot signature check: a hand `open` of an account whose own `open` is held (edited) is adopted on both paths — the remedy the quarantine warning names. T85 had refused it while the node-written `open` was held (L-110); since T91 a second `open` the mesh re-supplies changes no verdict, and the refusal made the warning's own remedy fail (L-121, L-125, T92). A complete-envelope record pasted into the file whose parent this node does not serve is held in the quarantine by the live reconcile, as boot holds it, instead of being adopted with a dangling parent (M-56, T85).
- A record no fresh replica could hold is no longer served: at boot, and again after the signature check, every transaction whose parent this node does not serve (the parent was edited, deleted, restated, or is held as unparsable text), or that the accounts it serves do not admit on its date and in its currencies, is quarantined together with what descends from it, each named in the log with its reason, and kept in the file. It used to be served — as a head this node's next write named, so every later write was refused by every peer — with a WARN at most. On a mesh these records come back once a peer re-supplies the missing parent and holds them too (one only this node held stays held until a restart); otherwise restore it, or strip the `openledger-*` lines of an envelope-edited record so it is re-adopted under the same id. Restating a record (a larger unit, a corrected body) gives it a new id, so its descendants stay quarantined (H-23, T84).
- An unparsable block that follows a parsed block with no blank line between them is held together with that block as raw text, and a salvaged transaction that does not balance is quarantined; a split node-written transaction is never loaded truncated. The boot banner no longer says "nothing is lost" for a held block (H-20 door (b), T73).
- An `open` this node authors — through the local API or a hand edit — may list at most 64 currencies (`MAX_CURRENCIES_PER_OPEN`); longer lists are refused with `RESOURCE_LIMIT_EXCEEDED` (L-78, T75). History — a peer's record, or an enveloped record in the file — is held to 4,096 (`MAX_CURRENCIES_PER_OPEN_LEGACY`), so a longer `open` an older build wrote replicates instead of cutting every replica that lacks it off from the account (M-51, T81).
- A transaction this node authors may carry at most 100 posting metadata keys in total (`MAX_POSTING_METADATA_KEYS_PER_TRANSACTION`); history is held to 4,096 (`MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY`). The local API never writes posting metadata, so the lower cap affects only hand edits (M-48, T75; M-51, T81).
- History over a 4,096 ceiling, with an amount past 10^21 (a ledger written before T65 in base units), or with a body over the wire's 1 MiB cap (a file written before L-02), is quarantined at boot together with every record that depends on it: its descendants, and every transaction the accounts this node serves do not admit. Everything stays in the file and is named in the log; the node serves only what a fresh replica can hold. A copy of a held record is adopted — from a peer or a live reconcile — only when it names parents this node serves, so a chain restated on one node reaches every node that holds the old copies; before T90 the wire refused such a copy by its id, for good (H-24, T90). A past-10^21 block is now named by its content id, not reported as a Unicode account name (M-51, M-52, T81; L-101, T85). Transactions on an account whose `open` was refused are judged after the hand edits in the file are adopted, with the peers' own check, so a hand `open` of the account dated no later than them and listing their currencies frees them in the same boot; before T85 they were held by account name alone and freed one restart later, whatever the `open`'s date (M-56, T85).
- A hand-typed entry's metadata keys are counted as the record will be stored, signature included: at most 96 body keys on a transaction and 97 on other kinds, since a node-written transaction carries four envelope keys and anything else three. One more used to be adopted, signed, and refused by every peer, and every later write of this node named it as a parent (M-55, T81).
- **A `balance` needs its account's `open` (R-15).** A `balance` assertion in the history whose account no `open` dated on or before it opens is now held in the file and not served, where before it was served; a hand-typed one is refused (dropped by a live reconcile, quarantined at boot) where before it was adopted. Add the missing `open`, dated no later than the assertion, and restart.

**Replication**

- A lamport value of `2^53−1` is refused everywhere, and the largest value the node stamps is `CEILING−2`. `LAMPORT_CEILING` errors name the author and the mesh-wide remedy (H-12, T63; H-07, T46).
- A directive that would advance this node's clock by `2^32` or more in one step is refused with the new error `LAMPORT_ADVANCE`. The refusal is retried, not cached (H-12, T63). Since T72 the id is not re-fetched from the same peer until this node's clock has reached the point where the verdict can change (L-69). The message no longer promises acceptance "once the intervening directives have arrived": that never happens when the gap was made by a directive this node refuses (H-19).
- **The per-author unmerged-head bound is removed** and the error code `UNMERGED_HEAD_LIMIT` is gone: a peer's transaction is never refused for the number of heads its author holds on this node. That bound was judged against this replica's heads, so two replicas served disjoint 256-subsets of one 257-transaction flood held permanently different DAGs (H-21, T72; decision (2) of 2026-09-23). A local append still names at most 256 parents (`MAX_PARENTS`), which alone closes H-16's brick (T64).
- Removing an author from the allowlist while its directives are in the history means every **later** joiner, and every node rebuilt from an empty disk, must be joined by bootstrap — copy a current peer's compacted `.bean` and boot it under the joiner's own key — because anti-entropy alone cannot cross the lamport gap such a directive leaves, and anything authored on top of a removed author's transaction is refused for a missing parent. The ratchet itself is unchanged. README §Mesh identity, "Joining a mesh / removing a peer" (H-19, T72; decision (1) of 2026-09-23, revised).
- The server closes an inbound anti-entropy connection after `p2p.antiEntropySessionSeconds` (default 300 s) with close code 5, `session-deadline` (M-40, T70).
- Each peer has an inbound accept rate: a burst of 8, then one connection per 2 s. Refused connections close with code 6, `accept-rate-limit` (M-40, T70).
- A Supply entry with a malformed id is refused before it is parsed (H-18, T66).

**Rust API (`gl-node` modules; it is a binary crate, so this affects forks and in-tree code only)**

- `ConnectionLimiter::should_log_refusal` takes a `RefusalSource` (`Peer(EndpointId, Refusal)` or `NotAllowlisted`), and `Refusal` derives `Hash`. `drain_orphans` no longer takes a `TransactionBroadcast`: it takes a `&mut DrainBudget` and returns `DrainOutcome` (was `DrainRefusals`), whose `announce` the caller publishes after its commit. `ledger::journal::FileTrust` has a new variant, `OperatorConfig` (T77).
- `ConnectionLimiter::try_acquire` returns `Result<ConnectionGuard, Refusal>` instead of an `Option`, and `pub enum Refusal { Global, PerPeer, AcceptRate }` is new; `Refusal::close_code()` gives the QUIC close code (M-16, M-40, T70).
- `AntiEntropyHandler` has a new public field, `supply_backoff: SupplyBackoff` (T69), and `AntiEntropyTimeouts` has `supply_backoff: Duration` (T71). Struct literals without `..Default::default()` must add them.

### Changed

- A node whose boot finds that every signature in its history fails — the wrong `p2p.meshId` or node key — refuses API writes with `EVERY_SIGNATURE_FAILED` until it is restarted correctly, and holds lines typed into the `.bean` in the file, unsigned, until then. Before, the warning only advised against writing, and one write made anyway was signed under the wrong domain and hid the warning at the next boot (L-114). `signing.allowWritesWhenEverySignatureFails: true` restores the old behaviour.
- `verify.errors` has one entry per offending node, capped at the first 1,000. The new `truncated` field counts the rest (L-63, T69).
- `journal` query complexity now scales with `limit` and the selection: `max(512, (limit/100) × (1 + child))`. Large aliased requests may be refused (M-45, T69). `verify` weighs 2048, and a request may contain at most 2 (M-23, T54).
- A local write whose journal record cannot fit under the 64 MiB cap is refused before staging with `RESOURCE_LIMIT_EXCEEDED` ("refused before staging, nothing changed"). It no longer stages, reloads and holds every other writer behind the reload (L-71, T77).
- The Supply size check uses the exact journal record, not a per-entry wire estimate that over-counted ~150–190 B, so the last ~40 KB below the cap are usable. Orphans a batch frees are staged only while they fit; the rest wait, and the peer is backed off with one warning. Any cap-refused prepare or commit also backs the peer off (L-70, T77).
- GraphQL subscribers hear about a transaction supplied by a peer only after it is durable (L-70, T77).
- A `Supply` frame whose parsed directives weigh more than 16 MiB is applied in several chunks, one journal record each, so phase 1 never holds more than 16 MiB of them. A pushed `Supply` also charges that weight to the inbound byte budget. The densest frame inside every cap peaked at 12.8× the frame and now peaks at 2.7× (T75 residual, T77).
- The default log filter is `info,iroh::protocol=error`; an explicit `RUST_LOG` replaces it (L-72, T77).
- Refused anti-entropy connections are logged once per 10 s per `(peer, reason)`, and not-allowlisted dialers once per 10 s as one class, closed with `Ok` so iroh logs nothing more. Guard refusals are logged once per 10 s per client address. What a window swallowed is reported when it closes, not only by the next refusal (M-40, M-41, L-72, T77).
- The "failed to persist ALPN supply batch" warning says whether the batch was rolled back or stays staged (T77).
- A peer batch that would not fit under the 64 MiB ledger cap is deferred without staging. That peer's Supply is then paused for `p2p.antiEntropySupplyBackoffSeconds` (default 60 s), with one warning (M-39, T69).
- At most `p2p.antiEntropyMaxConcurrentExchanges` outbound exchanges run at once (default 8). Other peers queue in order (R-5, T69).
- An outbound session is capped at 300 s, 512 advert pages and 64 MiB of advertised ids. A 64-hex id form is required (H-10, M-26, M-27, M-28, T49).
- Each peer may have 32 MiB of inbound frame bodies in flight, and all peers together 256 MiB. Excess is refused, not queued (L-39, T58).
- The byte-budget note now gives measured multiples: honest maximal `Supply` frames are about 6× their size in memory while being applied, and the densest frames inside every cap about 13×, so size hosts for about 2–3.5 GiB under the 256 MiB default (L-65, T75).
- Content-determined peer refusals are cached per `(peer, id)` for 10 minutes (L-34, T58).
- The file watcher re-reads the `.bean` only when its stat changes, or every 10 s. It runs off the async runtime (M-42, T69).
- A failed prepare reloads the ledger off the write lock (M-39, L-43, T69, T59).
- Boot quarantines what it refuses instead of dropping it. The boot banner lists all four quarantine reasons (H-08, T47; R-12, T55).
- A reconcile that rejects any entry forces the canonical rewrite, so refused lines do not stay on disk (M-37, T61).
- Canonical order breaks ties by content id. A file with same-date ties may be reordered once, at its first rewrite (M-24, T53).
- A mixed-scale balance may print with different trailing zeros than before (H-17, T65).
- `journal` and `transaction` agree on a boot-adopted hand record's envelope immediately after boot; the finalised copy is re-indexed instead of waiting for a restart (L-74, T73).
- The boot cycle quarantine keeps the enveloped spelling of a record when the file also holds an envelope-less copy of it, so the compaction writes the signed copy back and the next boot does not re-author it (L-76, T73).
- GraphQL `VerifyResult` gains `quarantined: [String!]!` (the ids this node holds in its quarantine, sorted) and `unparsableBlocks: Int!` (T81). Since T88 `quarantined` lists at most the first 1,000, like `errors`, and the new `quarantinedTotal: Int!` counts them all (L-103, T88).
- `ledger::service::ResourceRule`, `enforce_resource_limits_for`, `enforce_resource_limits_as_stored`, `ledger::parse::ParseLimits::{WIRE, IDENTIFY}` and its new `amount_cap` field (struct literals need it), `LedgerDag::children_awaiting`, and the constants `MAX_CURRENCIES_PER_OPEN_LEGACY` and `MAX_POSTING_METADATA_KEYS_PER_TRANSACTION_LEGACY` are new. The wire's `validate_supply_entry` now parses under `ParseLimits::WIRE` (T81).
- `LedgerService` gains `set_verifier(DirectiveVerifier)` and `verify_own_history()`; `gl-node` installs the verifier right after the signer when signing is enabled and runs the pass before the startup compaction (T73).
- `gl-node` sets the ledger author from the node key right after loading it, whenever signing is enabled, and installs the signer only with signing enabled; with P2P on it checks the endpoint id equals that author and aborts otherwise. The boot banner for records quarantined at signature verification counts every pass (`LedgerService::signature_quarantined_total`, new); it used to count only the last one, which is 0 once the signer and verifier installs had quarantined. When every signature checked fails, a WARN says to check `p2p.meshId` and the node key. `ledger::service::PLACEHOLDER_AUTHOR` is new (T80). Since T89 the "every signature failed" WARN is judged once, over every pass (the signer's pass alone used to fire it when this node's own records were edited), says not to author until the domain or key is fixed, and the clock is not released while every checked signature has failed (L-98, L-99, T89). Records authored `"local"` outside the ledger (quarantined or held as text) count as this node's in every clock and diagnostic lookup (L-96, T89).
- `set_author_id` warns when this node's own records outside the ledger (quarantined, or held as unparsable text) carry the clock to within one adoption step of the Lamport ceiling, naming the node's own file as the source; the ceiling refusal can name such a record's author (L-91, T80).
- A local append's parents are chosen for author diversity: at most `max(1, 256 / distinct head authors)` heads per author, smallest id first, then the remaining slots by smallest id. Still a pure function of the head set, so every replica holding the same heads names the same parents. Smallest-id-only let a peer that grinds content ids keep every honest head unmerged forever (L-68, T72).
- Boot, and any adoption that opens one, logs a WARN when the history holds a lamport gap of at least 2^28 between two consecutive values (`LAMPORT_GAP_WARN`) — a jump no honest mesh makes — naming the author of the directive at the top of the gap and the bootstrap join (H-19, T72). Until T83 it was judged on the clock against the directive count (`4 × count + 1024`), which fired on an honest mesh after about a dozen fresh joins, and on the first honest adoption after a signing boot quarantined this node's own history (L-94, L-83, T83). Since T89 the check runs on the history the node serves (after the signature check and the quarantines), the line names the author at the top of the gap as the jumper *or* the first honest record above a removed one, and only a gap of 2^32 or more prescribes the bootstrap join — a smaller one is crossed by anti-entropy (L-100, L-111, L-113, T89).
- A record quarantined at boot because its signature does not verify no longer leaves the clock where its (edited) lamport put it: the clock resumes above what remains (L-87, T83). Since T84 an edited record's own lamport still counts unless it lies 2^28 or more above what remains, so a narration fix never lets the next write re-issue the lamport the original was signed at (L-97, T84).
- A node-written record carrying a directive-level `openledger-*` key that is not one of the four envelope keys loads without that key, with a warning, and the next compaction writes it without it; the key is outside the content hash and the signature and no peer ever received it. It used to be served locally and written back by every compaction (L-89, T83). Since T89 posting-level `openledger-*` keys are dropped too, and the live reconcile strips a pasted node-written record the same way instead of refusing it and deleting it from the file (L-109, L-112, T89).
- An amount spelling with too many digits for a stored amount — more than 28 fractional digits, or more than the 96-bit mantissa holds, trailing zeros included (10^21 admits at most 7 decimal places) — is refused with a message that says so, by the GraphQL scalar and the `.bean` parser, instead of "Invalid decimal string" / "Invalid number" (L-92, T83).
- A peer that has used its whole inbound byte budget no longer turns each `Supply` frame into one commit per directive: phase 1 flushes on its 16 MiB weight budget only, and what the byte budget cannot cover is held uncharged within it (L-90, T83). Since T88 at most 1 MiB of parsed weight per connection is held uncharged, so such a frame is committed per ~1 MiB of weight (64 commits for the 256-directive test frame, against 4 with the budget free and 256 before T83), and a peer's uncharged memory is bounded by `max(1 MiB, one directive)` per connection — about 2 MiB, so ~60 MiB per peer and ~480 MiB across the connection cap — instead of up to 512 MiB (M-62, T88; the figure corrected by T95, L-132). A frame the wire admits parses at up to ~211 MB (`decode_memory` pins 224 MiB).
- A fresh node catching up a chain longer than the per-peer orphan buffer (1,000 entries) asks for ancestors before descendants: the orphan buffer keeps the parent links of what it had to drop, and the next round's Want is ordered by them, so the chain arrives parent before child. A 1,300-transaction chain catches up in 2 rounds over loopback, a 3,000-chain in 3 (it took 30 rounds, and more). A peer that ignores the Want's order is not helped (L-95, T83). Since T88 each peer's refused orphans may hold at most a quarter of the parent-link table, and expired links are swept with the orphans, so one peer can no longer fill it and slow every other peer's chain join back to the old crawl (L-107, T88). A buffered directive that can only wait on one this peer served and this node refused for good is no longer asked for again every round, for the refusal's 10-minute lifetime (L-106, T88).
- A dangling symbolic link at the `.bean` or config path is refused as "a dangling symbolic link"; the message used to say symbolic links are refused, which they are not. The `--health-check` probe reads at most 64 KiB of the reply (0924 §5, T83).
- `LAMPORT_CEILING` errors and the boot ceiling warnings name the highest-lamport author **other than this node** when one exists; after the victim had authored on top of the poison they named the victim (T72).
- The "rejected remote directive from ALPN" warning is logged at most once per 10 s per peer, with `suppressed=N` on the next line (L-69, T72).
- A torn journal tail is kept as `<ledger>.journal.torn-<unix-seconds>`, never deleted. A zero-filled final record is torn, not corrupt (M-43, M-44, T68).
- A failed commit's recovery reload no longer installs a rebuild that lacks any record this node had already written. Only records staged since the last commit may be missing: a line adopted from the file is stamped at adoption and is this node's record from then on (the signed ones since T82, L-93; every stamped one since T86, so a signing-off node's hand line is kept too, and its deletion from the file is no longer a retraction — L-104; T93 removed the "not yet stamped" exemption, which no line could meet, L-124). A rebuild in which a record this node committed names a parent the rebuild lacks is refused as well; memory is kept and the next commit writes both (M-59, T86). Since T93 a line adopted from the file never takes a write staged in the same commit as its parent, so a failed commit's staged write is rolled back as its error says rather than kept and written later (M-65). A backup copied over the live `.bean` followed by a failed write keeps every acknowledged record, and the next write puts the union on disk; a record the backup spells raw keeps the envelope this node already committed instead of being re-stamped (L-81, T82). The install log reports `discarded_staged` and `discarded_file_adopted` separately (M-46, T74).
- After a recovery reload that fails, the next commit is always a full rewrite, and the journal is kept as `<ledger>.journal.torn-<unix-seconds>` instead of being deleted. A refused reload that saw a torn journal renames it the same way (M-49, T74).
- `LedgerService::uncommitted_count()` counts only directives this node staged. Directives adopted from the `.bean` (boot's operator input, a live reconcile) are not counted, so it is 0 right after any boot. `LedgerDag::ids()` is new (ledger crate API; M-46, T74).
- Temporary files are named `<name>.tmp.<pid>.<nonce>`, and stale ones are swept at start (L-57, T67).
- Log echoes of attacker-supplied values are bounded. Guard refusals are logged at most once per 10 s, with `suppressed=N` (M-41, T66). The swarm topic is logged redacted (M-32, T57).
- A padded `swarmTopic` or `meshId` boot error shows the length, prefix and whitespace offset, never the value (L-56, T71).
- A signing node with `p2p.meshId` unset logs a WARN whose remedy is to set it to the current `swarmTopic` verbatim. `meshId` becomes required in a later release (R-9, T71).
- `GL_NODE_API_KEY` set while `auth.enabled: false` logs a boot warning without the key (0922-v2 §5, T71).
- The GraphiQL page loads only pinned assets, each with a Subresource Integrity hash (`integrity="sha384-…"`, `crossorigin="anonymous"`): graphiql 4.1.2 (js and css) and React/React-DOM 18.3.1 production builds from `unpkg.com`, replacing the floating `react@18` development builds. The `https://graphql.org/favicon.ico` link, a third origin the page contacted on every load, is removed. A CDN that serves other bytes is refused by the browser (L-66, T71, T78).
- A journal whose final record is complete but fails its checksum is treated as a torn tail when no intact record starts inside it. This is the ext4 `data=writeback` crash shape: stale block contents, no NUL. The node boots with the torn-record warning and the journal is kept as `<ledger>.journal.torn-<unix-seconds>`. A checksum failure before the last record, or a damaged length that swallows later records — intact ones, or a torn one behind a record whose own bytes still verify, including one torn inside the first bytes of its header — still refuses boot (0923 §5, T78; L-85, T82; L-105, T86).
- The startup sweep removes only the reserved temporary names `<name>.tmp` and `<name>.tmp.<pid>.<16 hex digits>`. Other `<name>.tmp.*` files, such as `ledger.bean.tmp.backup`, are left alone (0923 §5, T78).
- A node that boots under a placeholder author and learns its id afterwards (every `gl-node` with P2P on) now resumes its lamport clock above its own quarantined records when the id is set. Operator input adopted at that boot gets the same lamport a restart or recovery reload would give it. Records written by this node and held as unparsable text now count toward the boot clock too (L-67, T78).
- Boot logs a WARN naming both sizes and the remedy when the ledger's canonical form (what every compaction writes) is larger than the 64 MiB file cap although the file on disk is not; every write to such a ledger fails until it is made smaller. Since T82 the node refuses those writes before staging them — mutations with `RESOURCE_LIMIT_EXCEEDED`, peer batches deferred with the backoff — instead of staging, failing at the write and reloading each time (L-64, T78; L-80, T82). Since T86 that holds after the startup compaction too: its refusal no longer triggers a reload, and every reload measures the rebuilt ledger again — before, the reload that followed the refused startup compaction lost the over-cap fact whenever the file held hand-typed lines, and every write after it staged, failed and reloaded for tens of seconds with the write lock held (M-58, T86).
- A dangling symlink at the journal path beside a missing `.bean` refuses boot without first creating an empty `.bean` (0923 §5, T78).
- ALPN: a `Supply` answering a `Want` is filtered to the ids that were asked for. Unsolicited entries are dropped before any parse, with a WARN. Refusals of entries a peer pushed on its own are never recorded against its refusal quota (L-60, T66).
- `deploy/gl-node.docker.json` sets `"meshId": "openledger/docker-dev"`, its own `swarmTopic`, so the stack's signed history stays valid (R-9, T71).
- Balances are exact sums, in any arrival order. A figure that does not fit a `Decimal` at its usual scale is rounded once, half to even, instead of at each scale. This is reachable only through amounts at widely different scales, such as `1000` plus `0.0000000000000000000000000001`. Such figures print up to one unit in the last place differently from before (L-79, T76).
- `balance` assertions and `verify` compare against the exact sum. A claim that matches only the rounded figure now fails (L-79, T76).
- The balance sheet's `Equity:Net-Income` prints `0.00` instead of `-0.00` for a currency whose net is exactly zero (T76).
- Internal: `ledger::service` is split from one 25,000-line file into a module per concern (boot, the history checks, the quarantine, authoring, commit, recovery, reconcile, peer ingest, access, and the shared rules and file I/O). Every public path is unchanged and no behaviour changes. Its unit tests are split the same way, into `service/tests/`.

### Added

- `auth.apiKeyPath` (default `./data/api.key`): where a loopback node with no `auth.apiKey` keeps the key it generates on its first boot (H-01).
- Format v2 (T45; `docs/FORMAT_V2_DESIGN.md`), on by default (see *Breaking*) and accepted always. `format.wire2`: the anti-entropy and gossip frames in an externally tagged encoding, on the `openledger/anti-entropy/2` protocol (served beside v1) and the `<swarmTopic>/2` topic. `format.idv2`: API writes carry `openledger-format: "2"`, their id covers their author (another peer can no longer take a record's id by publishing its body first — M-10) and they are signed over a length-prefixed message (L-06). Lines typed into the `.bean` keep v1 identity, so the file's repairs keep their ids.
- `p2p.joinFrom`: a node that has written nothing can join a mesh whose history carries a lamport gap by naming a current peer — its history is adopted past the adoption ratchet until the node holds all of it, then the ratchet applies to it like any peer. Before, such a node could only join by copying a peer's `.bean` (H-19). A removed author's transaction still needs the copy.
- `watchLedgerFile` (default `false`): poll the `.bean` every 250 ms and fold hand edits in promptly (M-19, T52).
- `http.maxConnectionsPerIp` (default 64, range `8`–`65536`, clamped to `maxConnections`; M-33, T55).
- `p2p.antiEntropySessionSeconds` (300, `30`–`3600`), `p2p.antiEntropyMaxAdvertPages` (512, `256`–`1024`), `p2p.antiEntropyMaxAdvertIdBytes` (64 MiB, 16–64 MiB) and `p2p.antiEntropyMaxSessionFrames` (100000, `10000`–`1000000`) (R-7, T70).
- `p2p.antiEntropyAcceptBurst` (8, `2`–`256`) and `p2p.antiEntropyAcceptRefillMilliseconds` (2000, `100`–`30000`) (M-40, R-7, T70).
- `p2p.antiEntropyMaxConcurrentExchanges` (8, `1`–`64`) and `p2p.antiEntropySupplyBackoffSeconds` (60, `5`–`3600`) (R-5, M-39, T71).
- GraphQL `exact: Boolean!` on `AccountBalance`, `TrialBalanceRow`, `TrialBalance`, `BalanceSheet` and `IncomeStatement`, and `actualExact: Boolean!` on `BalanceAssertionFailure`: `false` when the figure was rounded (L-79, T76).
- GraphQL `VerifyResult.truncated` (L-63, T69), and the error code `LAMPORT_ADVANCE` (T63). (`UNMERGED_HEAD_LIMIT`, added by T64, was removed again by T72 before any release.)
- `ledger::service::select_parents` and `BOOTSTRAP_JOIN_REMEDY` (T72); `largest_lamport_gap`, `LAMPORT_GAP_WARN` and `LedgerService::lamport_gap` (T83), which replace T72's `clock_is_far_above_history` and `CLOCK_HISTORY_WARN_*` constants before any release. `ledger::validate::explain_unrepresentable_amount`, `p2p::anti_entropy::order_want_ancestors_first`, `OrphanBuffer::known_missing_parents` and `p2p::orphan_buffer::MAX_PARENT_HINT_IDS` (T83).
- `.cargo/audit.toml`, which ignores exactly one advisory (`RUSTSEC-2026-0235`, `rkyv`, not compiled) and records the evidence (M-34, T56).
- This changelog (R-13, T71).

### Removed

- The `externalFileEdits` config key (M-19, T52).
- h2c and HTTP upgrade handling on the GraphQL port (M-22, T55).
- `graphql::query::domain_txn_to_graphql`. Callers pass the txid instead of re-hashing each row (M-45, T69).
- The hand-written `unsafe extern "C"` `geteuid` declaration. `libc` is now a direct dependency of `ledger` (R-17, T67).
- `ledger::service::MAX_UNMERGED_HEADS_PER_AUTHOR`, `ServiceError::UnmergedHeadLimit`, `LedgerDag::heads_authored_by` and the `UNMERGED_HEAD_LIMIT` error code (H-21, T72).

### Security

- **R-15:** a `balance` assertion is accepted only on an account an `open` has opened by its date — from a peer (it waits for the account, as a transaction does), from the file (a typed one is refused), and in what a node serves (a history assertion on an unopened account is held in the file, not served). Before, a peer could add any number of assertions on accounts the ledger never had (`docs/audits/RESIDUALS.md`).
- **Residual close-out:** boot now warns when one author's lamport steps add up past 2^32 though no single gap does — a joiner cannot cross them once that author is removed (B14); a block typed beside a record the node already serves is logged when it is dropped (C8); the quarantine banner defers to each record's own warning (C25); the parent-hint expiry queue is compacted at twice the live hint maximum, not four times (D6). Every other residual the audits recorded has a final disposition in `docs/audits/RESIDUALS.md`.
- **L-23:** a signing node must name its mesh, so a swarm topic two meshes happen to share no longer makes them accept each other's signed records (once each has its own `meshId`).
- **H-01:** the API is authenticated by default on a loopback bind too, with a generated key in a node-private file read under the node's secret-key rules (no symlink, owned by the node's user, mode 0600, one link). Before, any program or account on the machine — or a page past the browser checks — could write the ledger.
- **H-07 / H-12:** one lamport-ceiling rule on every path, plus a `2^32` adoption ratchet. One peer directive can no longer make a node author records nobody accepts, or brick it on restart (T46, T63).
- **H-08:** a lossy boot no longer reaches a rewrite. Refused records are quarantined, and compaction keeps them (T47).
- **H-09 / H-18:** Supply decoding and validation are bounded. A 1 MiB hostile entry costs 136 B of error text instead of 195 MB and a 55 MB log line (T48, T66).
- **H-10 / M-40 / M-06:** anti-entropy sessions have deadlines on both sides and a per-peer accept rate. A few peers can no longer pin every slot (T49, T70).
- **H-11:** a cancelled mutation no longer wedges every write path (T50).
- **H-13 / H-14 / M-37 / M-38:** the stop → edit → start workflow produces signed records. A failed reconcile no longer overwrites the operator's edit (T61).
- **H-15 / M-35:** removing the `.bean` under a running node, or crashing mid-compaction, can no longer install an emptier ledger or brick boot (T62).
- **M-46 / M-49:** a live file replacement plus one failed commit can no longer drop acknowledged records, and a failed recovery reload can no longer leave the next commit appending behind a torn journal tail, which bricked the next boot (T74).
- **L-70 / L-71 / L-72 / L-73:** near-cap writes and peer batches no longer pay a ledger reload per attempt, a public QUIC bind no longer turns every refused handshake into unthrottled log lines, and the config file no longer hangs boot or loads without bound (T77).
- **M-48 / L-78:** peer `Supply` entries are held to the §3.12 caps while they are parsed and again right after, before a batch can queue them. A 1 MiB body of 41,941 postings used to peak at 42× its size and be refused only at stage; a 15 MiB frame of them held 546 MB. Both now peak under 0.1× and nothing is queued (T75).
- **H-16:** an allowlisted peer can no longer inflate the head set until this node's own appends are refused everywhere (T64).
- **H-19 / H-21 / L-68 / L-69:** replication rules are stated on the content, not on the replica. The per-replica head bound that let one peer's split delivery leave two honest replicas with permanently different committed DAGs is gone; parent choice can no longer be gamed to starve honest heads; the one bound that remains relative to this node's clock (the ratchet) is diagnosed at boot and on adoption instead of partitioning later joiners silently, with the bootstrap join documented and pinned by the convergence harness; and manufactured ratchet refusals cost one fetch per clock step, not one per tick (T72).
- **H-17:** balances are exact and independent of arrival order, so replicas, `verify` and reboots agree (T65).
- **M-50 / L-79:** balances are exact integer sums that no ingress can overflow, a history written before T65 loads whole again and a fresh replica can sync it, and `balance` assertions compare against the exact sum (T76).
- **L-83 / L-87 / L-89 / L-90 / L-94 / L-95:** the H-19 warning is judged on the history, not on the clock, so it no longer fires on an honest mesh; an edited lamport no longer carries this node's clock; a stray envelope key is dropped instead of loaded; an exhausted byte budget no longer multiplies commits; and a long chain joins in a few rounds (T83).
- **L-80 / L-81 / L-84 / L-85 / L-93:** an over-cap ledger no longer pays a reload per write attempt; a restored backup plus a failed commit no longer re-stamps an acknowledged record or drops a signed hand line; a symlinked `.bean` no longer hides its target's journal; and a damaged length over a torn later append no longer drops an acknowledged record (T82).
- **M-51 / M-52 / M-55:** history an older build wrote over a T75 cap replicates; a record no peer can accept (past 10^21, or past a 4,096 ceiling) is quarantined with everything that depends on it instead of being served; and a hand-typed entry can no longer pass the metadata cap here and fail it at every peer (T81).
- **M-53 / L-82 / L-91:** a node that signs with P2P off writes its real author id, so its hand edits verify and turning P2P on no longer quarantines its history; an older node's `"local"`-signed history is re-attributed in place (T80).
- **L-96 / L-98 / L-99 / L-100 / L-108 / L-109 / L-111 / L-112 / L-113:** the pre-T80 placeholder author is this node in every clock and diagnostic lookup, so its records outside the ledger can no longer have their lamports re-issued or be blamed on a peer (once the key loads, a pre-signing record at the Lamport ceiling is named as this node's own, with the repair-the-file remedy); the total-signature-failure warning is judged over every pass and no longer walks the clock; the lamport-gap warning is judged on the served history, names the author at the top of the gap without accusing it, and prescribes the bootstrap join only for a gap anti-entropy cannot cross; hand lines that name each other are adopted in one boot whatever their order; and a stray `openledger-*` key is stripped from a node's record at both levels, on the live path as at boot, instead of the block being deleted (T89).
- **M-62 / L-106 / L-107 / L-102 / L-103:** an allowlisted peer at its inbound byte budget can no longer make this node hold up to 16 MiB of parsed directives uncharged per connection; nor make it re-fetch and re-verify the subtree under a record it refused, every round; nor take the whole parent-link table from other peers' chain joins; the memory test's budget states the densest frame the wire admits; and `verify`'s quarantine list is bounded (T88).
- **M-60 / M-61:** the symlinked-ledger guard can no longer be raced or bypassed by a second link — the link must sit in a directory only the node's user can write and is followed one hop — and converting a ledger to a link after an unclean stop can no longer hide its journal's acknowledged records (T87).
- **M-58 / M-59 / L-104 / L-105:** the L-80 refusal holds on gl-node's real boot path (no reload after the refused startup compaction, the fact re-measured after every reload); a failed commit's recovery can no longer install a record naming a parent that exists nowhere; a signing-off node's stamped hand lines are kept like a signing node's; and a damaged journal length over an append torn inside its header fails closed (T86).
- **M-70:** checking a transaction's currency no longer walks its account's whole `open`/`close` history. Since T91 the check computed, for every posting, the union of every `open` dated before it, so the cost grew with (postings × lifecycle events) — at boot, in the served-set rule and on every peer transaction. An allowlisted peer's run of `close`/`open` pairs on a busy account slowed every replica: 10,000 pairs took a 150,000-transaction boot from 3.7 s to 120 s. Each account now records, per currency, the earliest `open` that lists it, and the check is two lookups (3.96 s at 10,000 pairs); which transactions are accepted is unchanged (T97).
- **L-123 / L-127 / L-135 / L-136:** the lamport-gap warning now also measures the gap without the named author's records — two consecutive sub-2^32 jumps by one author, each crossable, are together uncrossable once that author is removed, and the warning now prescribes the bootstrap join for them — and calls a gap of exactly 2^32 crossable, as it is. CI's toolchain action is pinned to a `master` commit, which is not regenerated. The boot fuzzer's every sweep checks that a fresh peer adopts exactly what the node serves; the log-capturing tests no longer lose a line to a callsite another test registered first. The texts of the held-record promise, the backup warning after a failed rewrite, the `verify` fields and the restate remedy on a currency-constrained account say what the code does (T96).
- **M-66 / M-67 / L-130 / L-132 / L-133 / L-134:** what a peer is asked for no longer depends on other peers' copies or on stale bookkeeping. An id is left out of a peer's Want as doomed only by a copy that peer itself delivered — an author's second envelope of its own record could keep an honest peer's copy, and everything written on top of it, out of a replica — and never on a parent this node already holds. The filter is one pass instead of a fixpoint (a child-first advert of ~9,000 ids cost 10–15 s per exchange under the orphan-buffer lock). A record this peer already served and this node holds buffered is not asked for again unless its missing parent is in the same exchange. Expired parent hints are popped in insertion order instead of by a full sweep. The anti-entropy advert's id list is built once while a line waits for its rewrite. The documented uncharged-memory bound is corrected (T95).
- **M-68 / L-118 / L-119 / L-120:** a symlinked `.bean` is checked and followed through one open handle on the link's directory: an account able to write a directory above it can no longer swap that directory between the check and the follow and point the node at another file (the target is opened relative to the handle and must be the same file as the resolved path). A link whose target differs from the file's name only in letter case or Unicode normalisation now resolves instead of being refused as a chain; on macOS a link directory carrying an access control list is refused; stale temporary files an older build left beside the link are now removed on gl-node, not only by library callers (T94).
- **M-65 / L-115 / L-116 / L-117 / L-122 / L-124:** a failed commit's recovery reload rolls back what failed. A hand edit adopted during a write no longer takes that write as its parent, so the write whose call failed is rolled back instead of being kept, counted and served; at the size cap every mutation is refused before staging (until T100, only while the over-cap fact was already set). The reload never lowers the clock below a lamport this node issued to a write it discards, so the next write in the same process cannot re-issue its `(author, lamport)` pair (after a restart it can, and since T100 no peer was offered the discarded write). A line adopted from the `.bean` is not served until its canonical rewrite succeeds, so a restart after a failed rewrite cannot give it a second envelope on the mesh. The reload works at the path the node started with and refuses one that has become a symbolic link since. A damaged record length over an append torn inside its first header bytes fails closed in both of the journal's length checks (T93).
- **M-74 / L-147 / L-148 / L-149 / L-154:** near the size cap, a write is judged against the rewrite it will take: while a line adopted from the file awaits its canonical spelling, the rewrite carries this node's envelopes for it, and a write whose record fitted the file's size but not the rewrite passed the pre-write check, failed as an "internal storage error" and cost a full reload — each mutation and each peer batch, over and over. Such a write is now refused before staging, as a resource limit, and a rewrite over the cap is refused before it is written (M-74). When a recovery after a failed commit keeps memory instead of reinstalling it — the ledger path became a link, the files lost records, a kept line names a missing parent, or the reload itself failed — the write whose call failed is rolled back; before it was counted, served, and written by the next commit (L-147). A write is not offered to peers until its commit succeeds, and neither is a record that descends from a line awaiting its rewrite (L-148, L-154). Choosing the parents of a large hand edit beside a large staged batch costs their sum, not their product (L-149) (T100).
- **M-71 / L-137 / L-138 / L-139:** the symlinked-`.bean` check now binds the path the node uses, not only the file: it must be the file the link names in the directory the link names. An account able to write a directory above the link's could swap that directory while the node started and have it handed a hard link of the ledger inside a directory the account controls, which the node then read, journalled and compacted (M-71). On macOS, a link directory's access control list refuses the link only when an entry lets another account add or remove entries in it; any ACL at all was refused, the home folders' own `deny delete` included, and the printed `chmod -N` remedy removed that protection (L-137). A FIFO put where the link's directory was can no longer hang boot (L-138). The startup sweep of temporaries beside a link never removes the link's own target, which an operator may have named like one; it did, and the node started an empty ledger (L-139). A link whose target is missing is refused when the node starts, before the lock (T101).
- **M-76 / L-150 / L-151 / L-152:** a record waiting for its parent is held once per peer that sent it, and each peer is asked for records in the order its own copies give. An allowlisted peer could sign its own envelopes of another peer's records naming other parents: its copy took the one slot, the honest copy was dropped as a duplicate, and the honest peer's Want was put in the wrong order, so a replica catching up from it gained one record per exchange (M-76). A parent hint recorded at the moment the hint queue was compacted never expired (L-150). A record buffered from its only peer is asked for again once its parent arrives through the `.bean` (L-151); it waited up to an hour. The Want filters walk the peer's own buffered and hinted records instead of every id it advertises, and hold the ledger's lock only to look up those records' parents (L-152) (T102).
- **M-73 / L-140 / L-141:** the restate remedy says to restate on **one** node: every node's log names the same held records, and before this each told its operator to restate them, so two operators who both did restated one deposit twice — two records every replica served and counted. The warnings, the startup banner and the README now say to restate on one node, without the restated record's own `openledger-*` lines, and that every other node adopts the restatement and must not restate; once a node holds nothing that descends from an over-cap block, its boot says to delete that block if the restatement is served. The banner also says that when every signature failed, the fix is `p2p.meshId` or the key, not the records (M-73). A pasted record whose lamport is more than 2^32 above this node's clock is still refused by the running node and dropped from the file, while boot loads the same bytes: the refusal now says so and how to keep the record (stop, put it back, start), and the README documents it (L-140). A record of this node's own that the running node holds in the file now moves the clock past its lamport, as boot does, so the node never stamps the same (author, lamport) pair again (L-141) (T103).
- A history record in the `.bean` whose posting has no amount is held at boot, with what descends from it, instead of served: every peer refuses a transaction that does not write every amount, so the node served a record no fresh replica could hold whenever it could not check the record's signature. The boot warning names the record and says to write the amount back or restore it.
- **M-64 / M-69 / L-114 / L-121 / L-125 / L-128 / L-129 / L-131:** every remedy the node prints works, and the served-set rule leaves nothing served over a held parent. The rule runs until nothing more is held — a hand-edited half envelope whose parent it held, and a hand line refused at the lamport ceiling, no longer leave a signed record served over them. gl-node's boot banner no longer tells the operator to delete an edited block and append a reversing entry (which held its descendants and counted the entry twice). The "every signature failed — check `meshId`, do not author" warning is no longer hidden by a hand line in the same boot. The quarantine warning's "add the missing open" is adopted at boot and under a running node, and so is the "delete its openledger-* lines" remedy. A hand child of a hand parent with an elided posting is adopted in the same boot, and hand-parented lines are ordered in linear time (20,000 in reverse order booted in 58 s, now under 1 s). A block retyped by hand beside a held record of the same body is adopted as the node's own instead of being dropped from the file (T92).
- **M-63 / M-09:** a later `open` no longer narrows an account's lifecycle verdicts. A transaction's currency may be listed by any `open` of its account dated no later than it (before T91, only the latest such `open`), so a peer's second `open` of an account with another currency list can no longer make every node stop serving history it had accepted — and everything written on top of it — at its next restart. An ingested `close` is refused only when it would close the account on the date of a transaction this node holds; before T91 a transaction after a later re-open counted against it too, so a replica that received the re-open and the transaction first (anti-entropy asks for the newest records first) refused an honest `close` for good and from then on disagreed with every other replica about the account (T91). The `close` rule was still order-dependent and is replaced by T98 below.
- **H-25 / M-09 / M-75 / L-153:** a `close` a peer sends or the `.bean` holds is data: it is always accepted, and it never refuses a transaction from a peer or the file — such a transaction is accepted whenever an `open` of its account is dated on or before it. Until now a `close` was refused when this node held a posting in the stretch it closed, and a posting after a `close` was refused, so which of the two a replica kept depended on which arrived first: one allowlisted peer's `close` and posting, or two operators on either side of a partition, left replicas apart for good, and since T91 a `close` that arrived before its own re-open was refused and cached as refused for good (H-25). A `close` held only on this node could also be accepted over a record this node alone held, which the printed "restore the original line" remedy could then never bring back (M-75), and a hand `close` typed before a hand re-open was held at one boot and served at the next (L-153). A `close` still stops this node's own API writes after it — unless a transaction dated after it (before the next `open`) is already held, which it no longer stops — and `closeAccount` still refuses to close over a later transaction. Upgrade every node: an older one refuses records this build accepts (T98).
- **M-72 / L-142 / L-143 / L-144 / L-145 / L-146:** when the file spells a record twice, boot keeps both copies until it has judged them, and serves the one every peer can adopt. Before, it chose once, before the closure, the signature check and the served-set rule had spoken, so after a crash a held chain re-entered through the API in date order, one adopted from a peer that restated it, or an API re-entry of a record whose file copy was edited, were held again — the records the node had acknowledged, and everything written on top of them — and the startup compaction deleted the copy that would have been served (M-72); the choice is now one linear pass (its descendant walk made a crafted file boot in quadratic time, L-142). A block retyped by hand beside a held record is adopted whichever check holds the record — before, only when the record descended from a refused one; beside a record the signature check or the rule held, the typed block was dropped silently, and "add the missing open" typed with the held `open`'s own id did nothing at boot (L-143). A record held only because its parent was held comes back in the same boot once a retyped copy of that parent is adopted (L-144). A typed copy refused when it is finalised stays in the file beside the node's own copy, as the warning says, and the record stays held back on the wire until then (L-145). The served-set rule runs as a loop that reaches its end in one round on any file — it recursed once per round, so a crafted chain of hand-parented lines cost a full rebuild per link and a failed commit's recovery could abort the process with a stack overflow (L-146) (T99).
- **H-24 / L-126:** what this node holds back is judged on each copy's parents, not by content id, on the wire and on the live file path: a copy of a held record naming parents this node serves is adopted, so the "restate the chain" remedy applied on one node no longer leaves every other node refusing the restated records for good; when the file and the journal hold two copies of one record (an API re-entry of a held record, then a crash), boot serves the copy whose parents it holds; and the live reconcile keeps in the file, in the quarantine, a pasted node-written record it refuses for a reason boot would hold it for, where it used to delete it (T90).
- **M-56 / L-101 / L-110:** the file path, the wire and every boot now agree on what this node holds back: a record every peer refuses — including one over the 1 MiB body cap — and what descends from it are refused by the wire as well as quarantined at boot; transactions on an account whose `open` was refused are judged with the peers' own check after the hand edits are adopted; and a hand re-`open` cannot give an account two `open`s mesh-wide (T85).
- **H-23 / M-57 / L-97:** a record no peer could adopt — its parent edited, deleted, restated or unparsable, or its account not open for it — is quarantined with its descendants instead of served, so no hand line or API write is signed over it; a hand line appended beside an edited lamport is stamped after the clock is settled; an edited record's lamport is never re-issued (T84).
- **H-22 / M-54:** fixing a signed record and appending a line in one edit, a hand parent that is only in the quarantine, or a pasted half envelope naming another node can no longer produce a signed record no peer can resolve, which orphaned everything the node wrote afterwards (T79).
- **H-20 / M-47 / L-74 / L-75 / L-76 / L-77:** boot verifies what it loads. An edited or split node-written record, a half envelope, a dangling hand-typed parent or a re-open can no longer be served under a signature no peer accepts and become the parent of everything the node authors afterwards (T73).
- **M-36 / M-43 / M-44:** ledger-side opens enforce file-type discipline, and journal policy fails closed (T67, T68).
- **Known residuals** remain listed in the trackers. They include the IPv6 /48 reach of the per-IP cap (L-61).
