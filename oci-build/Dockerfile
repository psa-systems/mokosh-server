# Mokosh Server - production OCI image
FROM rust:1.93-alpine AS builder

WORKDIR /build

RUN apk add --no-cache musl-dev pkgconfig openssl-dev openssl-libs-static lld

ENV RUSTFLAGS="-C link-arg=-fuse-ld=lld"

# Copy manifests, source, and migrations (sqlx::migrate! reads at compile time)
COPY Cargo.toml Cargo.lock ./
COPY src ./src
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

ARG GIT_SHA=""
LABEL org.opencontainers.image.source=https://dev.a8n.run/psa-systems/mokosh-server
LABEL org.opencontainers.image.description="Mokosh Server"
LABEL org.opencontainers.image.revision="${GIT_SHA}"

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/api/v1/health || exit 1

ENTRYPOINT ["/app/mokosh-server"]
