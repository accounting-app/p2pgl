# Log: peer discovery without a third party

Status: in progress.

One entry per commit-sized unit, newest last, written when the unit is ready
to commit. The commit hash is filled in once the maintainer has committed.

## 2026-10-08 — Step 1: direct peer addresses

- **What changed:** new `p2p.peerAddresses` (`{ "<EndpointId>": ["host:port", …] }`),
  validated at boot (every key in `bootstrapEndpointIds`, 1–16 addresses,
  `host:port` form); `crates/gl-node/src/peer_addresses.rs` resolves them
  (system DNS, 10 s timeout) into an iroh `MemoryLookup` at boot and every
  5 minutes, replacing each peer's entry and keeping the last one when nothing
  resolves; `p2p_service.rs` builds the endpoint through the new
  `endpoint_builder`, which adds the lookup in every relay mode, and warns when
  `"disabled"` has peers but no addresses. README, OPERATIONS.md, CHANGELOG.
- **Review round** (reviewer subagent), all fixed in this unit: a mistyped IPv4
  such as `203.0.113:4433` passed and resolved to another host (203.0.0.113)
  — a name whose last label is numeric is now refused; one failing address
  lost its last socket while the others resolved — each address now keeps its
  last result; `endpoint_builder` now creates the lookup and starts the
  refresh itself, so the two cannot diverge; the "relays off" warning names
  each bootstrap peer without an address; a peer listed twice, a `+port` and
  an IPv6 zone id are refused; docs that still said `"disabled"` reaches no
  peer corrected (OPERATIONS.md, compose comment).
- **Gate:** `scripts/gate.sh` — 1,544 passed, 0 failed, 0 ignored (6 min 14 s).
- **Revert checks:** `scripts/revert_specs/peer_discovery.json` — 8 of 8 bite.
- **Departures from the plan:** `p2p.listenPort` added (plan.md updated): iroh
  listens on a new random port at every boot, so an address given to peers had
  nothing stable to name — found while writing the compose comment, missed by
  the first test, which read the server's port after it bound. The test now
  fixes the port in advance, as an operator does. Learned for step 2: iroh
  keeps one relay URL per peer (`add_endpoint_info` overwrites it), as the
  plan's first risk feared.
- **Commit:** (pending)
