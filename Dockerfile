# Base images are pinned by digest as well as tag (L-10). A tag is a mutable
# pointer: `rust:1.91-slim` resolves to a different image every time upstream
# rebuilds it, so two builds of the same source commit can ship different
# toolchains and different system libraries with nothing in the repository
# recording the change. The digest is the immutable content address; the tag is
# kept beside it only so a human can read what the digest is supposed to be.
#
# The digests below are the multi-arch OCI image indexes, so they resolve on
# every platform the tag supports (amd64/arm64/arm/386).
#
# To refresh a pin (do this deliberately, in its own commit, and update the tag
# in the same edit):
#   docker manifest inspect rust:1.91-slim -v | jq -r '.Descriptor.digest'
#   docker manifest inspect debian:bookworm-slim -v | jq -r '.Descriptor.digest'

# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.91-slim@sha256:f75071363e7f4771769d4cf81b1b7b290e607f4d4459e8731f6abdcee9982dc8 AS builder

WORKDIR /build

# Copy workspace files.
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY crates/ crates/
COPY testfixtures/ testfixtures/

# Build release binary.
#
# `--locked` (L-10) makes the build reproducible and supply-chain-honest: it
# fails rather than silently resolving a newer dependency when Cargo.lock does
# not match the manifests, so an image can never ship crate versions that were
# never reviewed or tested. This is the same flag CI's `cargo test --workspace
# --locked` already enforces.
#
# The builder image no longer installs `pkg-config libssl-dev`: nothing in the
# dependency graph links against OpenSSL (no `openssl-sys`/`native-tls` in
# Cargo.lock — TLS here is rustls, and `ring` builds its own C with the
# compiler `rust:*-slim` already ships). The packages were inherited scaffolding
# and only widened the build image's attack surface.
RUN cargo build --release --locked --bin gl-node

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user.
RUN groupadd --gid 1000 glnode && \
    useradd --uid 1000 --gid glnode --shell /bin/sh --create-home glnode

# Copy binary from builder.
COPY --from=builder /build/target/release/gl-node /usr/local/bin/gl-node

# Default config and data directory.
RUN mkdir -p /data && chown glnode:glnode /data

USER glnode
WORKDIR /data

# Default environment.
ENV GL_NODE_CONFIG=/data/gl-node.config.json
ENV RUST_LOG=info

# Expose HTTP port (configurable via config).
EXPOSE 3000

# Health check (§2.9) — probes GET /health on the running process.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/gl-node", "--health-check"]

ENTRYPOINT ["gl-node"]
