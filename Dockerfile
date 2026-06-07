# Development Dockerfile - debug builds. Source code (src/, crates/,
# migrations/, Cargo.toml, Cargo.lock, build.rs) is mounted in via
# compose volumes; the build target lives on a named volume so cargo's
# incremental cache survives container restarts.
#
# The previous version of this image did a pre-build deps trick (stub
# main.rs + cargo build) to populate /app/target. That was dead weight
# in this setup because compose.dev.yml mounts mokosh-server-target
# over /app/target, masking anything baked into the image. Each
# developer's first `just dev` does the full compile into the named
# volume; subsequent runs are incremental.
FROM ghcr.io/niceguyit/rust-builder-glibc:v1.0.1-rust1.94-trixie

RUN apt-get update && apt-get install --yes --no-install-recommends \
    pkg-config libssl-dev curl \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir --parents /app /data /config

WORKDIR /app

EXPOSE 4301

CMD ["cargo", "run", "--bin", "mokosh-server"]
