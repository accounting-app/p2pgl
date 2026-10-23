# Log: a one-command production install

Status: in progress (step 5 of 7).

One entry per commit-sized unit, newest last, written when the unit is ready
to commit. The commit hash is filled in once the maintainer has committed.

## 2026-10-19 — Step 1: release 0.2.0 (the tooling, the version, the notes)

- **What changed:** the workspace is version 0.2.0; the CHANGELOG's
  `[Unreleased]` entries are `[0.2.0] — 2026-10-19`, with a summary, the
  status (pilot) and the known limits (the n0 limit of 0.1.0 is gone: entry
  001); a misleading *Changed* line about `--node-id` is dropped (it is new
  since 0.1.0, under *Added*). `scripts/release.sh` now also ships the Linux
  architecture the Docker host is not — on this Mac, linux-amd64, which most
  servers are — cross-compiled by **`Dockerfile.cross`** from the same pinned
  Rust image (Debian trixie's `gcc-<arch>-linux-gnu` and `libc6-dev-<arch>-cross`,
  glibc 2.41 headers, for `ring`'s C; the build refuses a binary that needs a
  glibc symbol newer than bookworm's 2.36, the runtime base), and, where the Docker host emulates it, boots that binary from
  an empty directory and waits for its own `--health-check`; `RELEASE-INFO.txt`
  says whether it ran. RELEASE.md *Platforms*; README's sample output and
  OPERATIONS' upgrade heading name 0.2.0.
- **Tried here:** the cross build (6.5 min, nothing cached) gave an x86-64 ELF
  that, under Colima's emulation, reported `gl-node 0.2.0`, booted and passed
  its health check in 2 s. The first build failed: `--no-install-recommends`
  left out `libc6-dev-amd64-cross`, so `ring` found no target headers; it is
  installed by name. A bind mount from outside the home directory reaches
  Colima's VM as an empty directory — `release.sh` mounts from the repository.
- **The release itself** runs on the committed tree (`release.sh` refuses a
  dirty one): after this commit, `scripts/release.sh --previous
  <0.1.0 darwin-arm64 binary>`, then the maintainer tags `v0.2.0` and attaches
  the files.
- **Gate:** `scripts/gate.sh` — 1,618 passed, 0 failed, 0 ignored (7 min 47 s).
- **Revert checks:** none: no new mechanism in the node; the release run
  exercises the script.
- **Review round** (reviewer subagent). *Important:* with Docker's classic
  image store, the emulated check's pull of the other platform's base would
  re-point the pinned digest, and the next classic build would put the native
  binary on that platform's base — named, from the image's metadata, as the
  other architecture, with every check still passing. Not so here (containerd
  store: `debian:bookworm-slim@…` stays arm64), but each Linux binary is now
  named by its ELF header and must match its image. *Important:* the Rust
  image is trixie (glibc 2.41), not bookworm as first written: the binary ran
  on bookworm only because it uses no symbol past 2.34; `Dockerfile.cross` now
  checks (`objdump -T`, no emulation needed) — 2.34 passes, and
  `MAX_GLIBC=33` refuses it, rerunning only that layer. Also: a *Breaking*
  section for what can stop a 0.1.0 deployment (moved from *Changed*); the
  summary and known limits say `relayMode` still defaults to `"n0"`; the
  Format v2 line restated; the emulation wording qualified; an empty runtime
  base or a failed pull fails with its own reason instead of "no emulation";
  the throwaway key goes through the environment, not the command line; a
  failed `docker create`/`cp` stops with a reason; RELEASE.md says Colima
  shares only the home directory.
- **Departures from the plan:** the other architecture is a cross-compiled
  binary (`Dockerfile.cross`), not an emulated image build; the upgrade
  rehearsal from 0.1.0 runs with the release itself (`plan.md` step 1, *As
  built*).
- **Commit:** d6a4abb

## 2026-10-19 — Step 1, continued: rustls 0.23.46

- **What changed:** the release stopped at `cargo audit`: four advisories
  published 2026-10-14 against `rustls` 0.23.45 (RUSTSEC-2026-0346, medium:
  a client session's `Debug` output exposed TLS secrets; 0347–0349, low),
  which iroh, its relay and DNS clients, and noq use. `cargo update -p rustls`
  moves only it, to 0.23.46; the audit is clean but for the allowed `paste`
  warning. CHANGELOG 0.2.0 *Security*.
- **Gate:** `scripts/gate.sh` — 1,618 passed, 0 failed, 0 ignored (8 min 9 s).
- **Revert checks:** none (a dependency update).
- **Departures from the plan:** none; the release runs after this commit.
- **Commit:** d6a4abb

## 2026-10-19 — Step 2: the node behind a proxy

- **Release 0.2.0** (step 1) was built and checked at d6a4abb after the
  rustls commit: gate, audit, MSRV 1.91, the shipped-binary tests with the
  upgrade and rollback from 0.1.0 (8 passed), the image, linux-arm64, and
  linux-amd64 cross-compiled and booted to a passing health check under
  emulation (`target/release-dist/0.2.0/`, kept beside 0.1.0's). Tag and
  publish: the maintainer.
- **What changed:** **`NodeConfig::is_public`** — a non-loopback bind, *or*
  `tls.mode: "terminated"`, *or* a `trustedProxies` entry — is what every
  public-node rule keys on: L-09's
  minimal `/health`, M-2's auth on, no GraphiQL, H-01's key given on purpose
  and a non-empty `allowedHosts` (one message for where they apply). Before,
  they keyed on the bind, so a loopback node behind a proxy on its own host —
  the installer's design — would have served GraphiQL, no auth, a generated
  key or the full `/health` to the internet. Only "a non-loopback bind must
  be terminated" keys on the bind. **`gl-node init --domain D [--data-dir]
  [--output]`** (`node_init.rs`) writes that node's config: `127.0.0.1:4000`,
  `trustedProxies: ["127.0.0.1"]`, `allowedHosts: [D]` (a DNS name, lower
  cased; no scheme, port, path or IP), `tls.mode: "terminated"`, auth on with
  no key in the file, GraphiQL off, `ledgersDir` under the data directory,
  signing and P2P off for its own ledger — created 0600 and never replacing a
  file, then loaded as the node loads it (with a throwaway key) and removed if
  it does not. README (the *public node* wording throughout, *Behind an HTTPS
  proxy on the same host*), CHANGELOG (*Breaking*, *Security*, *Added*).
- **Tests:** a loopback node behind a proxy is refused for each public rule
  and loads with all kept, a plain loopback node keeps its leeway; `init`
  writes a public node behind its proxy (0600, no key, loads); never replaces
  a config; leaves no config that does not load; takes a domain name only;
  on the shipped binary, a node set up by `init` boots and is public behind
  its proxy (`/health` is `{"status":"ok"}` without a key, the version with
  it; GraphQL without a key 401), and a second `init` exits 1. The L-51
  request-guard fixture (loopback, terminated, no key) now gives its key.
- **Gate:** `scripts/gate.sh` — 1,624 passed, 0 failed, 0 ignored (6 min 55 s).
- **Review round** (reviewer subagent; nothing Important). A loopback node
  that names its proxy in `trustedProxies` but leaves `tls.mode` at
  `"disabled"` has a proxy in front all the same, and escaped every public
  rule; `is_public` now counts it (the maintainer's call to confirm; I-R12),
  and the trusted-proxies fixture gives its key and host. `init` serializes
  before the file exists (an early return would have left an empty file every
  re-run refuses) and syncs the directory as well as the file; its refusal
  says an international name goes in its `xn--` form. The README's Health
  Check section, the handler's and the config fields' docs, and the L-37
  comment said "the bind"; they say "public" now, and the README says to run
  `init` where the node runs (its paths are checked from `init`'s working
  directory). `init`'s 0600, GraphiQL off and auth on are pinned (I-R13–I-R15).
  For step 3: the Caddyfile must pass `Host` through unchanged (L-51's port
  match and `allowedHosts`), and `company add` must write `relayMode:
  "custom"` (a folder's default is `"n0"`).
- **Revert checks:** `installer.json` — 15 of 15 bite: `/health` by the bind
  (I-R1, shipped binary), `tls.mode` not making a node public (I-R2), each
  rule by the bind (I-R3–I-R6), `init` replacing a config (I-R7), binding every
  interface (I-R8), trusting no proxy (I-R9), any domain (I-R10), keeping a
  config that does not load (I-R11), a trusted proxy not making a node public
  (I-R12), `init`'s file readable by others (I-R13), GraphiQL on (I-R14), auth
  off (I-R15). `h01_l23.json` H01-R5 re-anchored on
  `is_public` (still bites).
- **Departures from the plan:** recorded in `plan.md` step 2 (*As built*).
- **Commit:** a15d133

## 2026-10-20 — Step 3: the installer

- **What changed:** **`deploy/install/install.sh`** (shell, run as root on a
  fresh Ubuntu ≥ 22.04 or Debian ≥ 12, amd64 or arm64). It installs Docker
  from Docker's apt repository, its signing key checked by fingerprint
  (`9DC8…CD88`); fetches the release's Linux `gl-node` and `SHA256SUMS` and
  checks one against the other (or takes `--binary FILE`), and builds the
  node's image from it on the Dockerfile's pinned runtime base, tagged by
  version and the binary's hash; writes the config with `gl-node init`
  (in the image, as uid 1000, under `/var/lib/openledger/data`) and the
  operator key (32 bytes from `/dev/urandom`, `/opt/openledger/env`, 0600
  root); the Caddyfile (HTTPS for the domain — Let's Encrypt, or `tls
  internal` with `--test-tls` — forwarding `/graphql`, `/ledgers/*` and
  `/health` with `Host` unchanged, 404 for anything else) and the compose
  file (node and Caddy `caddy:2.10.2@sha256:c3d7…`, host network, restart
  unless stopped, 60 s stop grace, rotated logs); the firewall (ufw: the port
  `sshd -T` reports, 80, 443, 4433–4532/udp; `--no-firewall` to skip); checks
  the domain resolves (and says so if not to this server); starts, waits for
  the node's health check and then `https://DOMAIN/health` with a valid
  certificate. Each part says changed or unchanged; a second run ends
  "Nothing to change"; a file it wrote and you edited is kept and its
  version written as `FILE.new`; a config for another domain stops it. The
  key is printed on the run that makes it, and every run says where it is.
  `scripts/release.sh` now refuses a release whose installer names another
  default version (`RELEASE_VERSION`) or another node base. RELEASE.md,
  README and OPERATIONS (*Installing on a server*), CHANGELOG.
- **`scripts/rehearse_install.sh`** builds the node from the working tree and,
  per template (default `ubuntu-24.04 debian-12`), installs it on a new Lima
  VM with `--test-tls`, checks it from inside as a client, runs the installer
  again and reboots the VM.
- **Rehearsal:** both pass, from fresh VMs (10 min, after the review's
  changes; 18 checks each). As first written (14 min): a stranger's `/health` is `{"status":"ok"}`, the
  operator's has the version; GraphQL without a key 401, with it answers;
  `/` 404; port 4000 unreachable on the VM's address; ufw active with 443 and
  4433:4532/udp; the key file `600 root`; a second run "Nothing to change",
  the key not shown again (where it is, shown); after a reboot it serves.
  On Debian ufw is not installed by default: the installer installs it.
  Added after the review: the key is not written into the log when output is
  not a terminal; the VM has an address and the node answers on
  127.0.0.1:4000 (a positive control) while the VM's address:4000 is refused
  (curl exit 7, nothing else); Caddy's admin port 2019 is refused; the data
  directory is `openledger 700` and `gl-node` runs as `openledger`; a run with
  a new e-mail updates the Caddyfile (no `.new`), restarts Caddy, and it
  serves after.
- **Found by the rehearsals and fixed:** the firewall step ended the
  installer silently — `sshd -T | awk '… exit'` stopped reading, `sshd` died
  of SIGPIPE, and `pipefail` failed the assignment (exit 141); the awk
  programs (this one and the key fingerprint's) now read to the end. And a
  first run that failed after making the key never showed it, since later
  runs found the key file: every run now says where the key is.
- **Review round** (reviewer subagent). *Important:* (1) the DNS check died
  silently — `getent` exits 2 for a name that does not resolve and `pipefail`
  failed the assignment before its message (the rehearsal's `--test-tls`
  skips it); `|| true`. (2) Files the installer wrote were never updated: any
  difference read as "you edited it", so a re-run with another
  `--version`/`--binary`/`--email` kept the old compose file and the old image
  ran on; now the hash of what it last wrote is kept in
  `/opt/openledger/.installed/`, its own files are updated (and Caddy
  restarted — its folder, not the file, is mounted, so it sees the new one),
  and only a file someone edited is kept with a `.new`. (3) Caddy's admin API
  was open on the host's 127.0.0.1:2019 — anything on the machine could
  reroute the API and collect every key: `admin off`. (4) The node ran as uid
  1000, on most servers the first login account, which would own the books
  and could read the key from `/proc/<pid>/environ`: it runs as a system user
  `openledger` (no login), the image built with its uid. Also: Docker's key
  must be exactly one key (`pub` count) with the fingerprint — an appended
  second key would have been trusted; SSH's ports come from `sshd -T`, its
  listening sockets and `ssh.socket`, `--ssh-port` names one, and it refuses
  when it cannot tell (it guessed 22); a release before 0.3.0 (no `init`) is
  refused up front, and `RELEASE_VERSION` is 0.3.0; the key is printed on a
  terminal only; `release.sh` puts `install.sh` in the release and its
  `SHA256SUMS`, and RELEASE.md makes attaching the files required; the docs
  say what the checksum proves (a corrupted or substituted download, not the
  release itself), that the `docker` group can read the key, and that a
  company's `p2p.listenPort` must be set in 4433–4532; `buildx` installed;
  443/udp (HTTP/3) admitted; downloads `--proto =https`; `install -m 0755`
  for the binary; `grep -F` for the domain; `--binary` images tagged `local`;
  clear failures for `docker run` and `ps`; the old rehearsal logs, which
  held throwaway keys, removed (the script starts clean).
- **Gate:** `scripts/gate.sh` — 1,624 passed, 0 failed, 0 ignored (6 min 38 s); the installer and the rehearsal are shell, outside it.
- **Revert checks:** none: the installer is shell, proved by the rehearsal
  (each check above fails on the fault it names; the SIGPIPE one was found
  that way).
- **Departures from the plan:** a rehearsal script beside the installer
  (the plan said Lima, not how); `release.sh`'s two checks.
- **Commit:** 910b0b6

## 2026-10-20 — Step 4: the day-to-day command

- **What changed:** **`gl-node ledger add NAME --new-mesh FROM-TO`**
  (`addLedger(newMeshPorts:)`, `ledger_admin::new_mesh_settings`): the node
  composes a company's `ledger.json` — signing and P2P on, a fresh `meshId`
  (a version 4 UUID from the CSPRNG the keys come from) and `swarmTopic`,
  `relayMode: "disabled"` until it has peers (a folder's default is n0), no
  peers yet, and the lowest UDP port of the range that no served ledger has
  and nothing on the host holds (a bind of `0.0.0.0:port`); none free is
  `LEDGER_CONFLICT`, settings and a new mesh together `INVALID_INPUT`. The
  ledger list and an add report each ledger's fixed port (`listenPort`,
  `gl-node ledger list`'s PORT column). **`openledger`**, written by the
  installer to `/usr/local/sbin/openledger` (0755, root only by its check),
  with `/opt/openledger/settings` (the domain, the test-TLS flag, the port
  range): `company add | list | restart | remove`, `person add | list |
  rename | revoke` (`gl-node user --ledger`), `key`, `status` (the services,
  the node's version, `https://DOMAIN/health` through Caddy — non-zero exit
  if it fails —, the data's size, the companies), each the node's own command
  in its container. README, OPERATIONS (*Day to day*), CHANGELOG.
- **Tests:** a new mesh is a company of its own on a free port (past a
  ledger's port and a held one; fresh `meshId` and topic each time; none free
  refused; it loads as a folder's `ledger.json`; port ranges parse); through
  the endpoint, a new mesh with settings is refused and a range whose only
  port the test holds is refused with nothing written (no P2P endpoint is
  started in the tests: on this machine its port mapper would leave
  loopback); a new mesh takes no port a ledger that is down has (a folder
  copied in and never started, one whose `ledger.json` is refused);
  `--new-mesh` parses and is refused with `--settings` and on other commands.
- **Rehearsal** (`scripts/rehearse_install.sh`, fresh Ubuntu 24.04 and Debian
  12 VMs, 28 checks each; 9.5 min after the review's changes — a first try
  stopped in Lima, its boot scripts not done in 6 min, before the installer
  ran): step 3's, and `openledger company add
  acme` on UDP 4433 and `beta` on 4434, both served on their ports in
  `company list`; `person add acme --name Ana --role write` gives a key that
  works on acme over HTTPS and gets 401 on beta; `person list` shows Ana;
  `status` passes (HTTPS ok); `key` is the operator key; after a reboot
  Ana's key still works on acme.
- **Review round** (reviewer subagent). *Important:* a new mesh counted
  only the served ledgers' ports, so a company that was down — refused at
  boot, stopped by a restart that could not start it again, or a folder
  copied in — lost its port to the next `company add`; at the next boot the
  two conflict and one or neither is served. `taken_ports()` now adds every
  folder's `listenPort` in `ledgersDir`, from its `ledger.json` whether it
  loads or not (I-R20). Also: the name is checked before the port (a used
  name said "no free port"); `newMeshPorts` is sent only with `--new-mesh`,
  so a plain add works against an older node; `openledger` runs
  `docker exec` without `-i`, which swallowed a script's stdin; the add
  output names `openledger person add` too; the README and module docs list
  `newMeshPorts` and `listenPort`; the UUID's bytes are zeroized;
  `openledger key` fails when there is no key line.
- **Gate:** `scripts/gate.sh` — 1,627 passed, 0 failed, 0 ignored (6 min 57 s).
- **Revert checks:** `installer.json` — I-R16 (a new mesh without its
  `relayMode`), I-R17 (a ledger's port taken), I-R18 (a held port taken),
  I-R19 (settings and a new mesh together), I-R20 (a down ledger's port given
  away) bite. The `openledger` command is
  shell, proved by the rehearsal.
- **Departures from the plan:** the new mesh's settings are composed by the
  node (Rust, tested) rather than the shell command; `openledger key`.
- **Commit:** a81a03e

## 2026-10-23 — Step 5: joining a second server

- **What changed:** **`mesh_invite.rs`** — the one-line invitation and reply
  (`openledger-invite-v1.` / `openledger-reply-v1.` and URL-safe base64 of a
  small JSON: the company's ledger name, `meshId`, the invitation's
  `swarmTopic`, the sender's node id and `host:port`), refused by prefix where
  the other belongs, and when cut short, changed, over 4 KiB, or carrying a
  name, node id or address a node would not take (`PeerAddresses`' own
  rules); `joined_settings` (the invitation's mesh on this node's own port,
  the inviter its one peer with its address, `joinFrom` it, signing and P2P
  on, `relayMode: "disabled"`); `with_peer` (the replying node added once to
  `bootstrapEndpointIds`, its address replacing an older one, nothing else
  touched; a reply from another mesh `LEDGER_CONFLICT`, to a ledger without
  P2P `INVALID_INPUT`). **The node endpoint:** `inviteLedger(name, address)`
  (a served company that signs, on a fixed port), `joinLedger(invitation,
  address, newMeshPorts)` (the company added under `busy` with its port
  chosen as step 4's are; refused for a line this node wrote) returning the
  ledger and the reply, and `acceptLedger(reply)` (its `ledger.json` written
  aside and renamed, the company restarted under the same lock; settings the
  restart refuses put the old file back). **The CLI:** `gl-node ledger invite
  NAME --address HOST`, `join LINE --address HOST --new-mesh FROM-TO`,
  `accept LINE`, each printing the next step. **`openledger invite | join |
  accept`** pass the server's domain and port range. OPERATIONS (*Joining a
  second server*), README, CHANGELOG; the Insomnia collection and curl pages
  carry the three requests. Also the 005 step 4 and 006 commits recorded
  (a81a03e, 54b4454).
- **Tests:** an invitation and a reply are one line each and only what they
  say; a joining node is in the mesh with the inviter as its peer (it loads as
  a folder's `ledger.json`); accepting a reply adds its node and nothing else;
  an address is a host and the ledger's port (IPv6 in brackets); through the
  endpoint, invitations, joins and accepts the node refuses change nothing;
  the CLI's new commands parse and refuse what does not apply; a third
  server takes every server of the mesh and its rules; `accept` writes
  through no link; **on the shipped binary, three nodes on loopback** — A adds
  acme with `--new-mesh`, invites B, B joins, A accepts; B invites C, C joins,
  A (its reply on stdin) and B accept — and an entry written on any reaches
  the other two, all verifying (14 s).
- **Rehearsal** (`scripts/rehearse_join.sh`, two fresh Ubuntu 24.04 VMs on
  Lima's vzNAT network, each installed by `install.sh` with its own domain):
  passes, 16 checks (22 min, Lima's first boot of each VM included): A writes
  an invitation, B joins and writes a reply, A accepts it; Ana's key, issued on
  A, works on B (the access list replicated); her entry on A reaches B and
  hers on B reaches A; with A's node stopped B serves, takes an entry, and A,
  back, catches up; both verify with nothing quarantined. Lima's boot scripts
  outran its 10-min default twice on this Mac: both rehearsal scripts give it
  20 (`--timeout=20m`). After the review's changes, again from fresh VMs (27 min): all
  16, A's `accept` reading the reply from stdin and naming the node it admitted. The first run found that Apple's NAT network isolates
  its VMs from each other (the host reaches both; neither resolves the
  other: ARP incomplete), so every dial timed out; through the gateway — a
  route per VM, in the script — they reach each other, and replication began
  on its own, with no restart (Ana's grant on A reached B's access list).
- **Review round** (reviewer subagent). *Important:* (1) a third server
  would have split the replicas — an invitation named its inviter alone, so a
  server invited by A knew only A, and a node takes records only from the
  peers it lists (H-14): it refused every record B wrote, and B everything it
  wrote, while OPERATIONS said the others "learn of it on their next accept".
  The invitation now names every server of the mesh (with its addresses), the
  joiner lists them all, and every server already in the mesh accepts the
  reply — `join` says so and names them; the shipped test runs three nodes.
  (2) A joiner dropped `auth.adminNodes` and `format`: its access list would
  take grants the others refuse. The invitation carries them, and the mesh's
  relay (a joiner of a relay mesh had only direct addresses). (3) The lines
  were called "no secret", but an invitation carries the gossip topic, which
  the node elsewhere treats as a credential (T41): the docs and the CLI now
  say to keep it like a password; `-` reads a line from stdin, and
  `openledger join | accept` take it from the terminal and hand it to the
  node on stdin, out of `ps` and shell history. (4) `accept` read
  `ledger.json` without the checked reader and wrote aside with `create` +
  `truncate`, which a planted link would follow: it reads through
  `read_config_file`, refuses a linked `ledger.json` (renaming over it would
  cut the operator's link), and removes a stale aside file, then opens it
  `create_new`. Also: join and accept print the node ids they now trust, for
  the operators to compare; `serde_json`'s `preserve_order` is asked for,
  not borrowed; the three test ports are held together; the J-R5
  `Bug-catch:` says what the revert does. The first gate of this unit also
  failed on a clippy lint in a test and a stale I-R19 anchor (step 4's match
  arm, reshaped here): both fixed.
- **Gate:** `scripts/gate.sh` — 1,642 passed, 0 failed, 0 ignored (6 min 57 s), on the final tree; the run before it failed on one more clippy lint in a new test (`get().is_none()`), fixed.
- **Revert checks:** `join.json` — J-R1 (an accepted node not made a peer),
  J-R2 (a join without `joinFrom`), J-R3 (a line decoded whatever its prefix),
  J-R4 (a reply from another mesh accepted), J-R5 (a reply accepted for a
  ledger without P2P), J-R6 (a joiner drops the admin nodes), J-R7 (the aside
  file opened over a planted link — the removal and `create_new` together:
  reverting `create_new` alone does not bite, the removal already clears the
  link), J-R8 (a linked `ledger.json` accepted), J-R9 (an invitation without
  the mesh's other servers, on the shipped binary's three nodes) bite;
  `installer.json` I-R19 re-anchored (still bites).
- **Departures from the plan:** the reply goes to `accept`, not to `join` on
  the first server, so a line given to the wrong command is refused by its
  prefix; direct addresses only (a relay for servers without a public address
  remains plan question 6).
- **Commit:** <hash>
