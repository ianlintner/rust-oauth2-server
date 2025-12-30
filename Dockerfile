### Multi-stage build for Rust OAuth2 Server (with cargo-chef)
###
### This layout maximizes Docker layer cache reuse:
### - dependencies are compiled in an early cached layer
### - application code changes only rebuild the final binary

FROM rust:slim AS chef

WORKDIR /app

# Build dependencies for popular crates (openssl, etc.)
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    curl \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install cargo-chef (cached as a layer)
RUN cargo install cargo-chef --locked

FROM chef AS planner

# Only copy the manifests first so changes to app source don't bust the dependency cache.
COPY Cargo.toml Cargo.lock ./
COPY tests ./tests
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS cacher

# Optional cargo features (e.g., "mongo")
ARG CARGO_FEATURES=""

COPY --from=planner /app/recipe.json recipe.json
RUN if [ -n "$CARGO_FEATURES" ]; then \
            cargo chef cook --release --locked --recipe-path recipe.json --features "$CARGO_FEATURES"; \
        else \
            cargo chef cook --release --locked --recipe-path recipe.json; \
        fi

FROM chef AS builder

# Optional cargo features (e.g., "mongo")
ARG CARGO_FEATURES=""

# Reuse the dependency build artifacts from the cacher stage
COPY --from=cacher /app/target /app/target
COPY --from=cacher /usr/local/cargo /usr/local/cargo

# Copy full source tree and build the application
COPY . .
RUN if [ -n "$CARGO_FEATURES" ]; then \
            cargo build --release --locked --features "$CARGO_FEATURES"; \
        else \
            cargo build --release --locked; \
        fi

# Stage 2: Runtime
#
# NOTE: We keep the runtime distro aligned with the build environment's glibc.
# CI runners and upstream base images now commonly require GLIBC_2.38+, which
# Debian bookworm does not provide. Debian trixie includes GLIBC_2.38.
FROM debian:trixie-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy the built binary from builder
COPY --from=builder /app/target/release/rust_oauth2_server /app/rust_oauth2_server

# Backwards-compatibility: keep the old path if anything still references it
RUN ln -sf /app/rust_oauth2_server /app/oauth2_server

# Copy templates and static files
COPY templates ./templates
COPY static ./static

# Create directory for database
RUN mkdir -p /app/data

# Expose port
EXPOSE 8080

# Set environment variables
ENV OAUTH2_SERVER_HOST=0.0.0.0
ENV OAUTH2_SERVER_PORT=8080
ENV OAUTH2_DATABASE_URL=sqlite:/app/data/oauth2.db
ENV RUST_LOG=info

# Run the binary
CMD ["/app/rust_oauth2_server"]
