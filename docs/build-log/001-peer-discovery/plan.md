# Plan: peer discovery without a third party (from intent.md, 2026-10-08)

## Design

Two new `p2p` config keys and one new `relayMode` value; nothing else in the
P2P layer changes. Every dial already goes by EndpointId through the endpoint's
address lookup (`anti_entropy_alpn.rs` `fetch_want` → `open_peer_session`), so
feeding that lookup is the whole of the node side.

- **`p2p.peerAddresses`** — `{ "<EndpointId>": ["host:port", …] }`. Each key
  must be one of `bootstrapEndpointIds` (an address is a hint for reaching an
  admitted peer, never a reason to admit one); each value is `host:port` or
  `ip:port`, at least one, checked for form at boot. At boot the node installs
  an iroh `MemoryLookup`, resolves every address (DNS names included) and adds
  `EndpointAddr { id, addrs }`; a task re-resolves every 5 minutes and replaces
  the entry. A name that does not resolve is a WARN naming peer and address and
  is retried — a DNS hiccup must not stop a node from booting.
- **`p2p.listenPort`** — the UDP port the endpoint listens on (IPv4 required,
  IPv6 allowed to fail, as iroh's own default). Added in step 1: iroh's
  default is a new random port at every boot, so a `host:port` a peer is told
  needs a fixed port on the node it names. `0` (default) keeps today's
  behaviour.
- **`relayMode: "custom"`** with **`p2p.relayUrl`** — `"https://relay.example.com"`
  (one relay per mesh: changed from a `relayUrls` list in step 2, because a
  node registers at one relay and iroh's lookup holds one relay per peer, so
  two relays could leave peers registered at different ones).
  The endpoint is built from `presets::Minimal` plus `RelayMode::Custom(map)`
  and the `MemoryLookup` — no n0 relay, no n0 discovery. Each bootstrap peer's
  lookup entry also carries the relay URL, so a peer behind a router is
  reached through the relay. `"custom"` needs at least one of `relayUrl` or
  `peerAddresses`; the URL must be `https` with only a host and port — no user
  info, query or path (no secrets in config or logs). (Step 2 dropped the
  planned plain-`http` exception for loopback: tests trust the in-process
  relay's self-signed certificate in test code only, so no config value can
  turn certificate checks off.)
- **`"n0"` and `"disabled"`** keep today's meaning; `"disabled"` now also uses
  `peerAddresses`. Boot logs which mode is in force and, for `"n0"`, keeps its
  warning.
- **Production template:** `relayMode: "custom"` with neither list set, so it
  refuses to boot until the operator chooses a relay or addresses — the message
  names both.

## Order of work

1. **Direct addresses.** `peerAddresses` (config, validation, README table),
   `MemoryLookup` at boot, DNS resolution and the refresh task. Tests on
   loopback: two P2P stacks with relays off converge through configured
   addresses only.
2. **Own relay.** `relayMode: "custom"`, `relayUrl`, the endpoint built
   without n0. Tests against an in-process `iroh-relay` server on 127.0.0.1:
   two nodes with no direct address configured converge through it; the
   endpoint's relay map and lookups name no n0 host; a relay with an allowlist
   refuses a node not on it.
3. **Packaging and docs** *(as built, after decision C of 2026-10-09: the
   compose stack shows direct addresses, the relay is packaged for real
   servers — a relay needs a public-CA certificate, which a local stack cannot
   get; trusting a private CA, `relayCaCert`, is a later entry. Added on the
   way: `gl-node --node-id` and `deploy/mesh-init.sh`, since a node's id exists
   only once its key does, and the stack needs each peer's id up front; and a
   10 s retry while an address has never resolved, found by the stack's
   node-0 booting before its peers)*. Originally: a pinned `deploy/iroh-relay/` image of the official
   server (`iroh-relay` 1.0.3, `--features server --locked`) with an example
   config (allowlist access, and the HTTP check commented for the hosted case);
   a `relay` service in `deploy/docker-compose.yml` that the three nodes use —
   so that stack finally replicates; the production template change; README,
   `docs/OPERATIONS.md`, CHANGELOG (*Added*; the n0 *Known limits* entry
   rewritten). Check: the compose stack's three nodes converge with no n0.

Each step is one commit, through the gate, with its revert checks and a
`log.md` entry.

## Risks

- **Several relay URLs per peer.** iroh may try only one relay address per
  peer; a mesh with two relays could then miss a peer homed on the other.
  Settled in step 2: iroh's lookup holds one relay per peer and a node
  registers at one relay, so the config takes one `relayUrl` per mesh.
- **Plain-HTTP relays for tests and dev.** If the iroh client refuses `http`
  relay URLs, tests need the server's self-signed TLS with verification off,
  which must stay test-only (never reachable from config).
- **New dev-dependencies.** The in-process relay needs `iroh-relay` with its
  `server` feature as a dev-dependency: more crates in `Cargo.lock`, none in
  the shipped binary. `cargo audit` covers them; the step names them.
- **LuLu.** Tests bind and dial 127.0.0.1 only (relay included), so the
  firewall is never asked. DNS resolution in tests uses `localhost`.
- **Config compatibility.** New keys are optional and old values unchanged; an
  older binary refuses the new keys (strict config), as the CHANGELOG says for
  every new key.

## Alternatives rejected

- A discovery server of our own (iroh's DNS/pkarr server): another service to
  run, and own relays plus addresses already cover reachability.
- A relay built into gl-node: we would own the relay's code and TLS.
- Relay tokens: a leaked token admits anyone; the allowlist and the HTTP check
  admit by EndpointId, which is already the trust unit.

## Proof

- Tests (gl-node): config acceptance and refusal for each new key and the
  `"custom"` rules; direct-address convergence (relays off); relay convergence
  (no direct addresses); no-n0 endpoint shape; allowlist refusal at the relay;
  DNS refresh replacing a lookup entry (resolver injected).
- Revert checks (`scripts/revert_specs/peer_discovery.json`): drop the
  `MemoryLookup` install → direct convergence fails; build `"custom"` from
  `presets::N0` → no-n0 test fails; drop the "address only for an allowlisted
  peer" rule → its config test fails; drop the refresh's replace → refresh
  test fails.
- Docs: README config table and *Relay mode* section, OPERATIONS.md (running a
  relay, choosing a mode), production template, CHANGELOG.
