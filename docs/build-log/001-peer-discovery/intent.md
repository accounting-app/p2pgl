# Intent: peer discovery without a third party

Author: Claude, with the maintainer. Status: **approved** (2026-10-08).

## Problem

Nodes on different machines find each other today only through n0's free
public discovery and relay servers. n0 then sees every node's IP address,
which nodes sync with which, and when — for an accountant, that is the list of
its client companies. The service is outside our control and has no agreement
with us. The only alternative, `relayMode: "disabled"`, reaches no peer at all,
because nothing can tell a node where its peers are (`notes/`).

## Proposed outcome

An operator can run a mesh with **no traffic or metadata going to n0**, in
either of two ways, or both together:

1. **Own relay.** The mesh uses relay servers the operator (or we, for hosted
   customers) runs — the official `iroh-relay` server — so nodes behind office
   routers still reach each other. The relay admits only the mesh's own nodes.
2. **Direct addresses.** A node's config lists where each peer can be reached
   (`host:port`), for nodes on servers with fixed addresses; no relay needed.

n0 stays available for a quick trial, and says so at boot.

## Who it is for

- Companies and accountants running their own single-tenant mesh, often
  operated by non-experts: the setting must be simple and fail safe.
- Us, running a hosted relay for hosted customers.
- Anyone running the Phase 3 rehearsal on 2–3 real machines, which this
  unblocks without depending on n0.

## Constraints

- Peers are still identified and admitted by EndpointId
  (`bootstrapEndpointIds` stays the replication allowlist); an address is only
  a hint for reaching a peer, never a reason to trust it.
- Nothing else of the security hardening changes: signatures, mesh id,
  allowlists, the wire format, the HTTP API.
- Existing configs keep working: `relayMode: "n0"` and `"disabled"` mean what
  they mean today. The config stays strict (an unknown key is refused).
- No new network traffic in tests: they stay on loopback (in-process relay).

## How we will know it worked

- Two nodes using only an own relay converge, with **no** connection or DNS
  lookup to any `n0.iroh.link` host — on loopback in the test suite, then on two
  machines on different networks in the Phase 3 rehearsal.
- Two nodes with relays off and each other's direct address converge.
- A node whose EndpointId is not on the relay's allowlist cannot use the relay.
- A misspelled relay URL or peer address is refused at boot with a message
  naming it, not left to fail silently.
- README, the production template and `docs/OPERATIONS.md` explain how to run
  a relay and which setting to choose; the CHANGELOG *Known limits* entry about
  n0 is retired.

## Decisions (maintainer, 2026-10-08)

1. **Production default:** the production template refuses to boot until an
   own relay or peer addresses are set, as it does for `meshId`. n0 works only
   when `relayMode: "n0"` is written explicitly, and boot warns.
2. **Relay packaging:** the official `iroh-relay` server, same version as the
   nodes, as a pinned Docker image and a service in `deploy/docker-compose.yml`,
   with a section in `docs/OPERATIONS.md`. No relay code of our own.
3. **Relay access:** a self-hosted relay admits an allowlist of the mesh's
   EndpointIds (the `bootstrapEndpointIds`); our hosted relay asks an HTTP check
   against our customer records, so admitting or removing a node needs no
   restart.
4. **Host names:** a peer address may be a DNS name (`host:port`), resolved at
   boot and again periodically, as well as an IP address.

## Not in this work

- The service behind the hosted relay's HTTP check (it needs our customer
  records): built with the hosted service. Here the relay is configured to call
  it, and the self-hosted allowlist is complete.
- A discovery service of our own (n0-style name lookup by EndpointId): own
  relays and direct addresses cover the need without one.
- Several ledgers per node, and per-user access: entries of their own.

## Open questions

None for the intent; the plan answers how.
