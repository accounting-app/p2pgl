# Log: peer discovery without a third party

Status: done (2026-10-09, last commit 45ff4e2).

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
- **Commit:** ffc4269

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
- **Commit:** 7219ea7

## 2026-10-09 — Step 3: packaging and docs

- **What changed:** `gl-node --node-id` prints the node's EndpointId (key
  created on first use, by boot's rule) without serving; the production
  template runs `relayMode: "custom"` and refuses to boot until a relay or
  addresses are set; `deploy/iroh-relay/` builds the official `iroh-relay`
  1.0.3 (pinned, `--locked` on the crate's own lockfile) with an example
  config (Let's Encrypt, allowlist; the hosted HTTP check commented);
  `deploy/mesh-init.sh` turns the compose stack into a mesh over direct
  addresses (fresh meshId, each node's id via `--node-id`, peers'
  `node-N:4433`), `MESH_ID=` keeping an existing stack's signatures; addresses
  that have never resolved are retried every 10 s, not 5 min. OPERATIONS.md
  *Running a relay*, README, CHANGELOG (*Added*, *Changed*).
- **Checked by hand:** the relay image built (2 min) and served with a config
  derived from the example (allowlist of two real ids; TLS swapped for local
  HTTP); `mesh-init.sh` + `up` on this Mac: a transaction written on node-0
  was on node-1 and node-2 at the first poll, and one written on node-2 on
  node-0 at the first poll; every node logged "nothing goes to n0". The first
  `mesh-init.sh` run was refused by the template rule ("custom" with no peers
  yet) — the identity step now uses "disabled". The test stack, its volumes,
  `deploy/mesh/` and `deploy/.env` were removed afterwards.
- **Review round** (reviewer subagent), all fixed: `mesh-init.sh` gave an
  existing stack a fresh meshId (every signed record would fail verification)
  and its "start over" advice deleted the volumes — it now refuses when any
  node's volume holds a ledger unless `MESH_ID` is given, and the README says
  so; the relay image ran open (built-in defaults: no TLS, everyone admitted)
  without its config — an entrypoint now refuses; the HTTP-check header is
  `X-Iroh-NodeId` (POST, body exactly `true`), not what iroh's docs say;
  Let's Encrypt validates on 443 (TLS-ALPN-01), so 443 must reach the relay
  directly; `STOPSIGNAL SIGINT` (iroh-relay ignores SIGTERM) and `RUST_LOG=info`;
  `mesh-init.sh` checks `openssl`, cleans up a failed run, recognises the
  directories an early `up` leaves, sets 0644 on the configs deliberately;
  `--node-id` logs warnings to stderr and never creates a signing-only key
  (test + PD-R19); the 10 s retry's WARN repeats at most every 5 min; docs
  updated. Re-checked by hand after the fixes: the relay refuses to start
  without its config, serves with it, stops in 0.1 s; a fresh compose mesh
  replicates and verifies; a rerun over its volumes without `MESH_ID` is
  refused and leaves nothing behind; with the original `MESH_ID` the same ids
  come back and the history still verifies. (The first post-fix run caught a
  bug in the new history check — it mounted the not-yet-written configs, and
  Docker made directories of them — fixed by writing them first.)
- **Gate:** `scripts/gate.sh` — 1,550 passed, 0 failed, 0 ignored (6 min 24 s).
- **Revert checks:** `scripts/revert_specs/peer_discovery.json` — 19 of 19 bite.
- **Departures from the plan:** decision C (see plan.md, step 3): no relay in
  the compose stack; `--node-id`, `mesh-init.sh` and the quick retry added.
  Not automated: the compose end-to-end run and the relay image (Docker, the
  network); `spawn_refresh`'s choice of interval is covered through
  `refresh`'s result (PD-R18), not the loop itself. Follow-ups: audit the
  relay crate's own lockfile when bumping it; `relayCaCert` (planned entry).
- **Commit:** 45ff4e2
