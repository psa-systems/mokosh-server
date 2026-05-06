# Development Dockerfile - debug builds, source mounted via volumes
FROM rust:1-slim-trixie

RUN apt-get update && apt-get install --yes --no-install-recommends \
    pkg-config libssl-dev curl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir --parents /app /data /config

WORKDIR /app

# Copy manifests + migrations (sqlx::migrate! reads at compile time).
# Workspace member manifests must also be present at this stage so cargo
# can resolve the workspace before the actual sources are mounted.
COPY Cargo.toml Cargo.lock ./
COPY migrations/ ./migrations/
COPY crates/google-oauth-flow/Cargo.toml ./crates/google-oauth-flow/Cargo.toml

# Pre-build dependencies (stub source for the root package and every
# workspace member).
RUN mkdir --parents src src/bin crates/google-oauth-flow/src \
    && echo "fn main() {}" > src/main.rs \
    && echo "" > src/lib.rs \
    && echo "fn main() {}" > src/bin/mokosh-bootstrap.rs \
    && echo "" > crates/google-oauth-flow/src/lib.rs \
    && cargo build --bins \
    && rm -rf src crates/google-oauth-flow/src

# Source code is mounted via volumes in compose

EXPOSE 4301

CMD ["cargo", "run", "--bin", "mokosh-server"]
