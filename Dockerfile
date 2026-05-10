# Development Dockerfile - debug builds, source mounted via volumes
FROM rust:1-slim-trixie

RUN apt-get update && apt-get install --yes --no-install-recommends \
    pkg-config libssl-dev curl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir --parents /app /data /config

WORKDIR /app

# Source code, manifests, migrations are all mounted from the host via
# compose volumes. We deliberately do NOT pre-build with stub sources in
# the image - that approach was leaving stale `target/` fingerprints
# that confused cargo into a no-op rebuild when real sources arrived,
# silently running an empty binary. First container start does a full
# cargo build (~45s); subsequent starts hit the persisted target volume
# cache.

EXPOSE 4301

CMD ["cargo", "run", "--bin", "mokosh-server"]
