# Mokosh Server - production OCI image
FROM ghcr.io/niceguyit/rust-builder-musl:v1.0.0-rust1.94-alpine AS builder

WORKDIR /build

RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static lld

ENV RUSTFLAGS="-C link-arg=-fuse-ld=lld"

# Build-time version metadata. The `.git` directory is intentionally not
# copied into the build context, so `build.rs` cannot derive these from
# `git` itself - they must be passed in by the caller (CI, `just
# build-docker`, etc). When unset, `build.rs` falls back to "unknown"
# and the package version, which is fine for ad-hoc local builds but
# will not reflect the actual commit.
ARG MOKOSH_GIT_HASH=""
ARG MOKOSH_GIT_DESCRIBE=""
ARG MOKOSH_BUILD_DATE=""
ARG SOURCE_DATE_EPOCH=""
ENV MOKOSH_GIT_HASH=${MOKOSH_GIT_HASH}
ENV MOKOSH_GIT_DESCRIBE=${MOKOSH_GIT_DESCRIBE}
ENV MOKOSH_BUILD_DATE=${MOKOSH_BUILD_DATE}
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

# Copy manifests, source, workspace members, build script, and migrations
# (sqlx::migrate! reads migrations at compile time; workspace members
# must be present so cargo can resolve the workspace; build.rs is needed
# so the version metadata env vars get baked into the binaries).
COPY Cargo.toml Cargo.lock build.rs ./
COPY src ./src
COPY crates ./crates
COPY migrations ./migrations

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

RUN chown --recursive appuser:appuser /app

USER appuser

ARG MOKOSH_GIT_HASH=""
ARG MOKOSH_GIT_DESCRIBE=""
LABEL org.opencontainers.image.source=https://dev.a8n.run/psa-systems/mokosh-server
LABEL org.opencontainers.image.description="Mokosh Server"
LABEL org.opencontainers.image.revision="${MOKOSH_GIT_HASH}"
LABEL org.opencontainers.image.version="${MOKOSH_GIT_DESCRIBE}"

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/v1/health || exit 1

ENTRYPOINT ["/app/mokosh-server"]
