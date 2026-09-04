# Mokosh Server - production OCI image
FROM ghcr.io/niceguyit/rust-builder-musl:v1.0.0-rust1.94-alpine AS builder

WORKDIR /build

RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static lld

ENV RUSTFLAGS="-C link-arg=-fuse-ld=lld"

# PMS-781: dependency layer. Only the manifests land here, so the expensive
# third-party compile below is an image layer that no change under `src/` or
# `crates/*/src/` can invalidate - and, unlike a `target/` cache mount, a layer
# is something the CI `type=gha,mode=max` cache actually exports.
#
# Cargo needs a source file for every target a manifest declares, so each
# workspace crate gets a stub. `build.rs` is stubbed too: the real one calls
# `build_metadata::emit`, and `build-metadata`'s source only arrives with the
# real sources below.
COPY Cargo.toml Cargo.lock ./
COPY crates/build-metadata/Cargo.toml ./crates/build-metadata/
COPY crates/mokosh-types/Cargo.toml ./crates/mokosh-types/
RUN mkdir -p src/bin crates/build-metadata/src crates/mokosh-types/src \
    && echo 'fn main() {}' > build.rs \
    && echo 'fn main() {}' > src/main.rs \
    && echo 'fn main() {}' > src/bin/mokosh-bootstrap.rs \
    && touch src/lib.rs \
             crates/build-metadata/src/lib.rs \
             crates/mokosh-types/src/lib.rs

# `cargo clean` drops the three stub-built workspace crates and keeps every
# dependency artifact. It is deterministic where relying on mtimes is not: COPY
# preserves the build context's timestamps, which are older than this layer, so
# without the clean cargo would call the stubs fresh and the image would ship a
# `fn main() {}` binary.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release --bins \
    && cargo clean --release --package mokosh-server \
                             --package mokosh-types \
                             --package build-metadata

# Build-time version metadata. The `.git` directory is intentionally not
# copied into the build context, so `build.rs` cannot derive these from
# `git` itself - they must be passed in by the caller (CI, `just
# build-docker`, etc). When unset, `build.rs` falls back to "unknown"
# and the package version, which is fine for ad-hoc local builds but
# will not reflect the actual commit.
#
# These sit BELOW the dependency layer on purpose: the values change on every
# build (the build date always, the git hash on every commit), and an ENV
# change invalidates every layer under it. Above the dependency build they
# would recompile the whole dependency graph once per build and the layer
# would never be reused.
ARG MOKOSH_GIT_HASH=""
ARG MOKOSH_GIT_DESCRIBE=""
ARG MOKOSH_BUILD_DATE=""
ARG SOURCE_DATE_EPOCH=""
ENV MOKOSH_GIT_HASH=${MOKOSH_GIT_HASH}
ENV MOKOSH_GIT_DESCRIBE=${MOKOSH_GIT_DESCRIBE}
ENV MOKOSH_BUILD_DATE=${MOKOSH_BUILD_DATE}
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

# Real sources, least-frequently-changed first. All four are required at
# compile time: sqlx::migrate! reads migrations/, cargo needs the workspace
# members to resolve the workspace, and build.rs bakes the version metadata
# env vars into the binaries. (PMS-1007's vendored fonts are inside src/, which
# is why they live there rather than in a top-level assets/.)
COPY migrations ./migrations
COPY build.rs ./
COPY crates ./crates
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo build --release --bins

# Runtime stage
FROM alpine:3.21

WORKDIR /app

RUN apk add --no-cache ca-certificates tzdata

RUN adduser --disabled-password --uid 1001 appuser

COPY --from=builder /build/target/release/mokosh-server /app/mokosh-server
COPY --from=builder /build/target/release/mokosh-bootstrap /app/mokosh-bootstrap
COPY --from=builder /build/migrations /app/migrations

# PMS-1007: the Noto Sans faces the PDF renderer draws with are compiled into
# the binary, so the SIL Open Font License they are distributed under has to
# travel separately. It is a licence obligation, not a runtime input: nothing
# reads this file.
COPY --from=builder /build/src/pdf/fonts/OFL.txt /app/licenses/NotoSans-OFL.txt

# PMS-757: the uploads directory has to EXIST in the image, owned by the runtime
# user, before a deployment mounts a volume over it.
#
# Docker seeds an empty named volume from whatever the image has at the mount
# point, ownership included. With no directory there, the fresh volume is
# root-owned, and this container runs as uid 1001, so every upload would fail
# the day persistence was added. `ATTACHMENT_DIR` defaults to `./attachments`
# against WORKDIR /app, so this path is also what a bare `docker run` uses.
RUN mkdir -p /app/attachments

RUN chown --recursive appuser:appuser /app

USER appuser

ARG MOKOSH_GIT_HASH=""
ARG MOKOSH_GIT_DESCRIBE=""
LABEL org.opencontainers.image.description="Mokosh Server"
LABEL org.opencontainers.image.revision="${MOKOSH_GIT_HASH}"
LABEL org.opencontainers.image.version="${MOKOSH_GIT_DESCRIBE}"

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/v1/health || exit 1

ENTRYPOINT ["/app/mokosh-server"]
