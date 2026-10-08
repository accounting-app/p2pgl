# iroh 1.0: relays and peer addresses (read 2026-10-08)

What the intent and plan rely on, as read in the sources Cargo.lock pins
(`iroh` 1.0.3, `iroh-relay` 1.0.3, under `~/.cargo/registry/src/*/`).

## How a node is found today

- `crates/gl-node/src/p2p_service.rs` `boot_p2p` builds the endpoint from
  `p2p.relayMode`: `"n0"` → `Endpoint::builder(presets::N0)`, `"disabled"` →
  `presets::Minimal`. Peers are named only by EndpointId
  (`p2p.bootstrapEndpointIds`, also the replication allowlist).
- `presets::N0` uses n0's relays (`use1-1`, `usw1-1`, `euc1-1.relay.n0.iroh.link`,
  `iroh/src/defaults.rs`) and n0's discovery (pkarr publishing + DNS lookup,
  `iroh/src/address_lookup/{pkarr,dns}.rs`): an EndpointId resolves to an
  address through n0's service.
- `presets::Minimal` has no relay and no address lookup, and gl-node's config
  has no field for a peer's address — so a `"disabled"` node reaches no peer.

## Custom relays

- `iroh::endpoint::RelayMode` (`iroh/src/endpoint.rs:1925`): `Disabled`,
  `Default` (n0 production), `Staging` (n0 staging), **`Custom(RelayMap)`**.
  A `RelayMap` is built from `RelayUrl`s; `Builder::relay_mode` sets it
  (`endpoint.rs:557`).
- A node keeps a *home relay* from its map and is reachable there by its
  EndpointId; iroh tries a direct (hole-punched) path and falls back to the
  relay. Traffic through a relay stays end-to-end encrypted (QUIC/TLS keyed by
  the EndpointIds); the relay sees who connects to whom, and when.

## Giving a node its peers' addresses

- `iroh::address_lookup::memory::MemoryLookup` (`address_lookup/memory.rs`):
  `Builder::address_lookup(lookup.clone())`, then
  `lookup.add_endpoint_info(EndpointAddr { id, addrs })` where `addrs` holds
  `TransportAddr::Relay(url)` and/or `TransportAddr::Ip(socket_addr)`. Entries
  can be added and removed at runtime. gl-node's tests already use it
  (`anti_entropy_alpn.rs`, `loopback_addr`).
- `TransportAddr::Ip` takes a `SocketAddr`: a host name in config must be
  resolved by gl-node (and re-resolved if it can change).

## The relay server

- `iroh-relay` 1.0.3 ships a binary `iroh-relay` (`src/main.rs`,
  `required-features = ["server"]`): HTTPS relay, optional QUIC address
  discovery, TLS by ACME (Let's Encrypt) or certificate files, metrics.
- **Access control** (`main.rs:160`, `AccessConfig`): `everyone` (default),
  `allowlist` of EndpointIds, `denylist`, `http` (a POST per connecting
  endpoint, header `X-Iroh-Endpoint-Id`, `200 true` admits), and
  `shared_token` (bearer token, or `?token=` in the URL; env
  `IROH_RELAY_ACCESS_TOKEN`). An allowlist matches a mesh's
  `bootstrapEndpointIds`; `http` or tokens suit one relay serving many
  customers.
- Same major version as the client, so client and server agree on the
  protocol.
