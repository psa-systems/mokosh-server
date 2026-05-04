# Development Dockerfile - debug builds, source mounted via volumes
FROM rust:1-slim-trixie

RUN apt-get update && apt-get install --yes --no-install-recommends \
    pkg-config libssl-dev curl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir --parents /app /data /config

WORKDIR /app

# Copy manifests + migrations (sqlx::migrate! reads at compile time)
COPY Cargo.toml Cargo.lock ./
COPY migrations/ ./migrations/

# Pre-build dependencies (stub source)
RUN mkdir --parents src src/bin \
    && echo "fn main() {}" > src/main.rs \
    && echo "" > src/lib.rs \
    && echo "fn main() {}" > src/bin/mokosh-bootstrap.rs \
    && cargo build --bins \
    && rm -rf src

# Source code is mounted via volumes in compose

EXPOSE 8080

CMD ["cargo", "run", "--bin", "mokosh-server"]
