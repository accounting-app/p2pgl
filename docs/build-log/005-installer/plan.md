# Plan: a one-command production install (from intent.md, 2026-10-19; approved 2026-10-19)

## Design

**What runs on the server.** The installer is a shell script (no Python,
entry 004); the logic worth testing lives in `gl-node` itself, in Rust, where
the gate and revert checks reach it. Everything goes under `/opt/openledger`
(config, compose file, env file 0600 root) and `/var/lib/openledger` (the
node's data and backups), so a re-run and an uninstall know what is theirs.

- **Two containers, host networking.** `gl-node` binds `127.0.0.1:4000`, and
  Caddy (pinned by digest) is the only public HTTP listener (80, 443), with
  automatic certificates for the operator's domain, forwarding `/graphql`,
  `/ledgers/*` and `/health` to the node. Host networking because a company
  added at runtime gets a UDP port of its own, and a published container port
  cannot be added without recreating the container; on the host network the
  node opens it and the firewall (`ufw`) admits it. `trustedProxies:
  ["127.0.0.1"]`, `allowedHosts: [domain]`, `tls.mode: "terminated"`.
- **`/health` behind a proxy on the same host** (a node change): today a
  loopback bind serves the full `/health` to anyone (L-09), which through
  Caddy is everyone. A node with `tls.mode: "terminated"` is treated as public
  whatever its bind: the minimal body without a key.
- **The image** is the release's Linux binary, verified against its
  `SHA256SUMS`, in a small image the installer builds `FROM` the same pinned
  Debian base as our `Dockerfile` — no compiling, no registry account; a
  private repository needs only a download token. (Publishing to a registry
  stays possible later.)
- **`gl-node init`** (new, Rust): writes the production config for a domain —
  fresh `meshId` and topic, `relayMode: "custom"` with the relay or none, the
  proxy settings above, `ledgersDir` — and refuses to overwrite one. The
  installer calls it once; tests pin what it writes.
- **Joining a second server** (Rust): `gl-node ledger invite acme` prints a
  one-line invitation — the company's `meshId`, topic, port, and this node's
  id and public address, no secret — and `gl-node ledger join <invitation>`
  on the other server adds the ledger with this node as its peer and prints
  its own reply line, which `gl-node ledger join` on the first server takes
  to add the second as a peer (restarting the ledger, step-4 style).
- **The day-2 command** `openledger` (shell, on the host): `company
  add|list|remove`, `person add|list|revoke`, `invite`, `join`, `backup`,
  `restore`, `upgrade`, `rollback`, `status` — each a `docker exec` of the
  `gl-node` command, or the OPERATIONS procedure scripted.
- **Backups:** a systemd timer, nightly, keeps 14 in
  `/var/lib/openledger/backups`, each the stop-copy-start of OPERATIONS
  (seconds; the mesh's other nodes serve meanwhile), and says how to copy
  them off the machine; `restore` follows *Restoring a backup*, including its
  wait on a mesh. `upgrade` backs up first and keeps the previous image for
  `rollback`.

## Order of work

1. **Release 0.2.0** (002–004 are unreleased): `scripts/release.sh` builds
   linux-amd64 as well as arm64, CHANGELOG `[0.2.0]`, the upgrade rehearsal
   from 0.1.0. The maintainer tags and publishes; the installer installs it.
   (As built: the other architecture is a binary cross-compiled by
   `Dockerfile.cross`, not an emulated image build — minutes, not hours — with
   an emulated boot as its check; the installer needs the binary only. The
   upgrade rehearsal runs with the release, on the committed tree.)
2. **The node behind a proxy:** `/health` public under `tls.mode:
   "terminated"`; `gl-node init`. README, CHANGELOG.
3. **The installer:** `deploy/install/install.sh` — checks the system,
   installs Docker from Docker's apt repository (key by fingerprint), fetches
   and verifies the release, builds the image, writes config, Caddyfile,
   compose file and env, firewall, starts, waits for `/health` over HTTPS,
   prints the key; a re-run reports nothing to change. Rehearsed on Lima VMs
   (Ubuntu 24.04, Debian 12) with Caddy's internal CA (`--test-tls`).
4. **The day-2 command:** companies and people, `status`.
5. **Joining:** `invite` and `join` in `gl-node`, and in `openledger`.
6. **Backups, restore, upgrade, rollback.**
7. **The real-network rehearsal** (Phase 3): two VMs at a provider, real
   domains and certificates, the intent's checks; OPERATIONS *Installing*,
   README.

## Risks

- **Host networking** exposes whatever the node listens on: its HTTP must
  stay on loopback (refused otherwise by `gl-node init`'s config and checked
  by the installer), and the firewall admits only 22, 80, 443 and the ledgers'
  UDP ports. Docker's own iptables rules bypass `ufw` for published ports —
  another reason nothing is published.
- **A key on a screen:** the operator key is printed once and stored in the
  root-only env file; nothing writes it to a log or a command line.
- **Upgrade and restore** touch the books: both follow OPERATIONS step by
  step, take a backup first and are rehearsed across two nodes.
- **Certificates** need the domain's DNS to point at the server first; the
  installer checks it before asking Caddy, so a failure says why.

## Alternatives rejected

- A registry image (GHCR): needs CI publishing and, for a private repository,
  registry credentials on every server; the binary already ships verified.
- A native package without Docker: per-distribution packaging; the maintainer
  chose Docker.
- Published container ports with a fixed UDP range: 100 forwarded ports per
  node, and a range fixed at install time.
- An online backup inside the node (no stop): a new node mechanism; the
  stop-copy-start is seconds and documented. Later, if the stop hurts.

## Proof

- Rust tests: `/health` minimal for a stranger under `tls.mode:
  "terminated"` on a loopback bind; `gl-node init` writes a config that loads,
  binds loopback, trusts only `127.0.0.1`, has a fresh `meshId`, and refuses
  to overwrite; an invitation round-trips, a join adds the ledger with the
  inviting peer, and a reply adds the joiner; malformed invitations are
  refused. Each with its revert check (`scripts/revert_specs/installer.json`).
- The shell is proved by rehearsal, recorded in `log.md`: Lima VMs per step
  (fresh install, re-run, each `openledger` command), then the real-network
  rehearsal of step 7 with the intent's checks.
- Docs: README (*Installing on a server*), OPERATIONS (*Installing*, the
  day-2 commands, backups off the machine), CHANGELOG per step.

## Decisions for the maintainer

1. **Release 0.2.0 as step 1** — or tag it apart, before this entry.
2. **The rehearsal machines for step 7:** a provider and two small VMs (and
   two domain names); Lima covers steps 3–6 here.
3. **Is the repository private?** Then the installer needs a download token
   for the release (read-only, kept in the env file), and the plan says how
   to make one.
