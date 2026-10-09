# The mesh's own relay: the official iroh-relay server (docs/build-log/001-peer-discovery),
# built from crates.io at the exact version the nodes use. Pinned like the node
# image: base images by digest (L-10, see the root Dockerfile for how to refresh
# them), the crate by `=version`, and `--locked`, which builds the dependency
# versions in the crate's own published Cargo.lock. That lockfile is not ours:
# audit it with `cargo audit -f` on the crate's Cargo.lock when bumping.
#
#   docker build -t openledger/iroh-relay:1.0.3 deploy/iroh-relay
#   docker run -d --restart unless-stopped --name iroh-relay \
#     -p 80:80 -p 443:443 -p 7842:7842/udp \
#     -v "$(pwd)/relay.toml:/etc/iroh-relay/relay.toml:ro" \
#     -v iroh-relay-certs:/var/lib/iroh-relay openledger/iroh-relay:1.0.3
#
# Bump IROH_RELAY_VERSION together with the iroh version in Cargo.lock: the
# relay and the nodes speak the same protocol version.

FROM rust:1.91-slim@sha256:f75071363e7f4771769d4cf81b1b7b290e607f4d4459e8731f6abdcee9982dc8 AS builder
ARG IROH_RELAY_VERSION=1.0.3
RUN cargo install iroh-relay --version "=${IROH_RELAY_VERSION}" --features server --locked --root /out

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN groupadd --gid 1000 relay && \
    useradd --uid 1000 --gid relay --shell /bin/sh --create-home relay
COPY --from=builder /out/bin/iroh-relay /usr/local/bin/iroh-relay

# Fail closed: iroh-relay runs with its built-in defaults when its config file
# is missing — no TLS, and every node in the world admitted. This entrypoint
# refuses to start instead unless /etc/iroh-relay/relay.toml is mounted (as a
# file). Arguments, if given, go to iroh-relay as they are (e.g. `--dev` for a
# local, plain-HTTP relay on purpose).
RUN printf '%s\n' \
      '#!/bin/sh' \
      'set -e' \
      'config=/etc/iroh-relay/relay.toml' \
      'if [ "$#" -gt 0 ]; then exec iroh-relay "$@"; fi' \
      'if [ ! -f "$config" ]; then' \
      '  echo "iroh-relay: no config file at $config; refusing to start an open relay (mount your relay.toml there, see docs/OPERATIONS.md)" >&2' \
      '  exit 1' \
      'fi' \
      'exec iroh-relay --config-path "$config"' \
      > /usr/local/bin/relay-entrypoint \
    && chmod 0755 /usr/local/bin/relay-entrypoint

# Let's Encrypt keeps its account and certificates here (`cert_dir`); mount a
# volume so they survive a restart and the relay is not rate-limited.
RUN mkdir -p /var/lib/iroh-relay /etc/iroh-relay && chown relay:relay /var/lib/iroh-relay
USER relay
WORKDIR /var/lib/iroh-relay
# INFO shows startup, certificate renewal and refused connections ("not
# authorized"; the line does not name the node).
ENV RUST_LOG=info
# 443: the relay over HTTPS — and Let's Encrypt, which validates through it
#      (TLS-ALPN-01), so 443 must reach the relay directly, never through a
#      proxy that terminates TLS;
# 80: plain HTTP, the captive-portal probe nodes use;
# 7842/udp: QUIC address discovery.
# A non-root process may bind these inside the container: Docker 20.10 and
# later allow ports below 1024 on its default network (not with --network host).
EXPOSE 80 443 7842/udp
# iroh-relay shuts down on SIGINT and ignores SIGTERM, Docker's default.
STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/local/bin/relay-entrypoint"]
