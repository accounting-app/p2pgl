# Intent: several company ledgers on one node

Author: Claude, with the maintainer. Status: **approved** (2026-10-13).

## Problem

A node serves one ledger. An accountant with forty client companies, or our
hosted service with many customers, would have to run forty node processes —
forty configs, ports, keys, backups and upgrades — on each machine they use
for uptime. That is too much to operate for the people we are building for,
and it makes a hosted service uneconomic.

## Proposed outcome

- **One node process serves many ledgers**, one per company, each with its
  own `.bean` file, its own mesh (peers, `meshId`, relay settings), its own
  node identity and its own people and roles (entry 002).
- **The ledgers are isolated**: nothing written to one is visible in, counted
  in, replicated to, or able to slow down another; a mesh peer of company A
  learns nothing about company B, not even that the same node serves it.
- **The operator adds and removes ledgers while the node runs**; the other
  ledgers keep serving throughout.
- **Clients choose the ledger in the request**, and a key from one ledger is
  refused by every other.

## Who it is for

Accountants serving many client companies from their own nodes; our hosted
service (entry 004); a company with several legal entities.

## Constraints

- A node configured as today — one ledger — keeps working unchanged after the
  upgrade: same config, same files, same `/graphql`, same keys.
- One ledger's trouble stays its own: a corrupt or quarantined file, a ledger
  at its size cap, a misbehaving peer or a flood of requests affects that
  ledger only. A node boots and serves every healthy ledger even if one
  cannot load.
- Every safeguard a ledger has today it keeps, per ledger: the size cap, the
  rate limits, signing, the access list, the journal, the file watcher.
- Removing a ledger stops serving it and never deletes its files.
- Up to about 100 ledgers per node, within the memory and file handles of an
  ordinary small server.

## How we will know it worked

- Two companies' ledgers on one node: each one's reports show only its own
  entries; a key issued in one is refused by the other; a peer of one cannot
  fetch or announce records into the other.
- Each ledger replicates with its own mesh, under its own node id, and the two
  ids cannot be tied together from either mesh.
- A ledger added at runtime serves within seconds; removing one leaves the
  others answering throughout, and its files untouched.
- A ledger whose file will not load is reported and skipped; the rest serve.
- An existing single-ledger node upgrades with no change and behaves as before.
- A node with 100 small ledgers boots and serves them within the limits above.

## Decisions (maintainer, 2026-10-13)

1. **Node identity:** each ledger has its own node key and P2P endpoint, so
   meshes cannot be linked through a shared node id (the reason for the own
   relay in 001).
2. **People's keys:** one key per person per ledger — each ledger's own access
   list (002) grants its own keys; an accountant on five companies holds five
   keys. The operator key is the node's, admin of every ledger on it.
3. **Adding and removing ledgers:** at runtime, without a restart —
   `gl-node ledger add | list | remove`, and the same for an operator through
   the API (what the hosted service will call).
4. **Scale:** up to about 100 ledgers per node; one P2P endpoint (one UDP
   port) per ledger is acceptable at that size.

## Not in this work

- The hosted service itself: sign-up, billing, provisioning (entry 004).
- Reports across ledgers (consolidation) and moving a ledger between nodes.
- Hundreds or thousands of ledgers per node (shared transport, lazy loading).

## Open questions

For the plan: how a request names its ledger (a URL path such as
`/ledgers/<name>/graphql` is the likely answer — it works through proxies and
in GraphiQL); where a runtime-added ledger's settings and files live and how
they survive a restart; how the existing single-ledger config maps onto the
new shape; and how per-ledger work (watchers, anti-entropy, commits) shares
one process without one ledger starving the others.
