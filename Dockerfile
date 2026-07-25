# ── Stage 1: Build ────────────────────────────────────────────────────────────
FROM rust:1.87-slim AS builder

WORKDIR /build

# Install system deps for building (SSL, etc.).
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files.
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY crates/ crates/
COPY testfixtures/ testfixtures/

# Build release binary.
RUN cargo build --release --bin gl-node

# ── Stage 2: Runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

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

# Health check (§2.9).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/usr/local/bin/gl-node", "--version"] || exit 1

ENTRYPOINT ["gl-node"]
