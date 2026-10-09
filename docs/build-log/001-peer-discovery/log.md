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

## 2026-10-08 — Step 2: the mesh's own relay

- **What changed:** `relayMode: "custom"` with `p2p.relayUrl` (one `https`
  relay per mesh): the endpoint is built from `presets::Minimal` plus that one
  relay and the node's own lookup, where every bootstrap peer is entered at
  the relay as well as at its addresses — no n0 relay, no n0 discovery.
  Validation: `relayUrl` only with `"custom"`; `"custom"` needs a relay or
  addresses; the URL is `https://host[:port]` only, and a refusal never repeats
  it (a password or relay token must not reach the log). Tests run a real
  `iroh-relay` in-process on 127.0.0.1 (iroh `test-utils` and `iroh-relay`
  `server` as dev-dependencies: 40 lockfile crates, none in the shipped
  binary, `cargo audit` clean).
- **Review round** (reviewer subagent), all fixed: a refused relay URL echoed
  its user info or token into the boot log — now only `scheme://host[:port]`
  or a redaction; `"custom"` without a relay now gets the unreachable-peer
  warning too; the allowlist test passed for the wrong reason (an admitted
  stranger had not synced within its window either — PD-R15 did not bite) and
  now asserts the relay's refusal itself (the stranger never comes online);
  README states the relay needs a public-CA certificate; CHANGELOG retires the
  0.1.0 "only through n0" limit.
- **Gate:** `scripts/gate.sh` — 1,547 passed, 0 failed, 0 ignored (6 min 23 s).
- **Revert checks:** `scripts/revert_specs/peer_discovery.json` — 15 of 15 bite
  (steps 1 and 2).
- **Departures from the plan:** one `relayUrl` instead of a `relayUrls` list
  (plan.md updated): a node registers at one relay and iroh's lookup holds one
  relay per peer. No plain-`http` exception for tests: they trust the test
  relay's certificate in test code only. The plan's "relay map names no n0
  host" check is covered by PD-R9 (an n0 preset adds lookups) rather than a
  relay-map assertion.
- **Commit:** (pending)
