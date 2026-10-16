# Intent: a one-command production install

Author: Claude, with the maintainer. Status: draft (2026-10-16).

## Problem

Putting a node into production today means following OPERATIONS by hand: a
config from the template with a fresh `meshId` and topic, an operator key kept
out of shell history, an HTTPS terminator with certificates, `allowedHosts`
and `trustedProxies` to match it, a relay or peer addresses, firewall ports,
backups, and an upgrade with a rollback ready. Each step is a way to get it
wrong, and the people we build for — companies and accountants, not only
experts — should not have to know them. Our hosted service is the same
procedure, run by us for many customers.

## Proposed outcome

- **One command on a fresh Linux server** (Ubuntu LTS or Debian, with Docker)
  installs a node ready for real books: it asks for a domain name and an
  e-mail for certificates, sets up the node from a published release
  (checksums verified), an HTTPS proxy with automatic certificates (Caddy)
  as the only public listener, the mesh's own relay if wanted, the firewall,
  restarts on failure, log rotation and scheduled backups, and prints the
  operator key once.
- **Day-2 commands on the server** for what an operator does: add a company
  (`gl-node ledger add`, with a fresh mesh), add a person and hand over their
  key, join a company's mesh from a second server for uptime, back up and
  restore, upgrade with a backup first and a rollback, and see the node's
  health.
- **Running the installer again changes nothing that is set up**, and never
  deletes books, keys or backups; an uninstall leaves the data in place.
- **The hosted service starts as this**: we run the installer on our servers
  and onboard customers with the day-2 commands. Sign-up, billing and
  automatic provisioning are a later entry.
- Day-to-day use stays an app outside this repo calling the GraphQL API with
  each person's key (the maintainer, 2026-10-16); the installer exposes that
  API over HTTPS at `https://<domain>/ledgers/<company>/graphql`.

## Who it is for

A company or accountant self-hosting on a rented server, who can follow
instructions but does not run servers for a living; us, running the hosted
service; and the app developers who need a node to talk to.

## Constraints

- Nothing the audits fixed is loosened: the node binds loopback inside its
  network and is reached only through the HTTPS proxy; auth on; per-node
  operator keys never in a file others can read, a command line or a log;
  `relayMode: "custom"` (nothing to n0); `trustedProxies` and `allowedHosts`
  set to the proxy and the domain.
- Only published release artifacts, verified against the release's
  `SHA256SUMS`; no build on the server.
- No Python (entry 004): shell, and the `gl-node` binary itself.
- A 2 GB, 1–2 core server is enough for a node of a few companies.
- The operator's data is never deleted or overwritten by the installer, an
  upgrade or a rollback; a backup is taken before every upgrade.

## How we will know it worked

On fresh virtual machines (Ubuntu 24.04 and Debian 12):

- One command, two answers: `https://<domain>/health` is `ok` with a valid
  certificate, and the API refuses a request without a key.
- A company added and a person given a key: that person's app, on another
  machine, writes and reads that company's books over HTTPS.
- A second server joins the company's mesh with the day-2 command; an entry
  written on one is on the other, and either can be stopped while the other
  serves.
- A backup restored on a clean server gives the same balances.
- An upgrade to the next release, and a rollback, keep the books (the
  OPERATIONS procedure, run by the command).
- Running the installer again reports nothing to change.

## Open questions

1. **Release first:** the installer installs a release, and 002–004 are
   unreleased; 0.2.0 (with a linux-amd64 build) comes before or as part of
   this entry.
2. **How the image reaches the server:** published to a registry (GitHub
   Container Registry, from the release) or the release's Linux binary in a
   small image the installer builds from a pinned base.
3. **Joining a second server:** how two installs exchange what a mesh needs
   (node ids, addresses, the company's `meshId` and topic) without the
   operator copying 64-character ids by hand.
4. **Backups:** where they go (a local directory, an S3-compatible bucket),
   how often, and the brief stop a consistent backup needs today
   (OPERATIONS, *Backups*).
5. **Where we rehearse:** which provider and machines (this is also the Phase
   3 real-network rehearsal).
6. **The relay:** one per installation, or one we run for every hosted and
   self-hosted mesh.
