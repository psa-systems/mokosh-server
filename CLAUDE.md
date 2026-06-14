# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Mokosh Server: PSA (Professional Services Automation) REST API for MSPs. Rust + Axum + SQLx + PostgreSQL. Two binaries:

- `mokosh-server`: long-running HTTP API (`src/main.rs`).
- `mokosh-bootstrap`: one-shot CLI for first-run Infisical setup and OIDC client registration (`src/bin/mokosh-bootstrap.rs`).

## Common commands

All driven through `just` (see `justfile`). Required tooling: `just`, Nushell `0.112.2`, Docker + Compose v2, Rust stable, `sqlx-cli` for migrations.

```
just                       # list recipes
just check                 # cargo check + clippy + fmt --check (run before pushing)
just check-compile         # cargo check --all-targets
just check-clippy          # cargo clippy --all-targets
just check-fmt             # cargo fmt --all --check
just fmt                   # cargo fmt --all
just test                  # cargo test (workspace-wide)
just test-integration      # Postgres-backed tests/*.rs suite (mirrors CI integration.yml)
just install-hooks         # install the git pre-commit hook -> runs `just pre-commit`
just pre-commit            # fast, DB-free fmt/clippy/compile/unit/doc checks (mirrors CI check.yml)
just build                 # cargo build --release --bins
just migrate-run           # sqlx migrate run against $DATABASE_URL
just migrate-create <name> # new migration in migrations/
just check-docker          # validate OCI image builder stage
just build-docker          # build production OCI image (oci-build/Dockerfile)
```

Single test: `cargo test -p <crate> <test_name>` (workspace), e.g. `cargo test -p mokosh-auth-crypto totp::tests::generates_valid_code`.

### Dev stacks

Two compose layouts, mutually exclusive in practice:

```
just dev                   # LAN-IP stack: mokosh-server + Infisical + Postgres + Valkey on br0/eth0
just dev-down              # stop LAN-IP stack (volumes preserved)
just dev-clean             # stop + wipe volumes + remove .env (keeps .env.infisical)
just infisical-bootstrap   # one-time after `just dev`, fills INFISICAL_* in .env

just dev-sso               # Traefik-routed per-developer SSO stack at *.a8n.run (requires OIDC keys)
just dev-sso-down
just down                  # stop BOTH stacks, remove orphans (volumes preserved)
just restart               # down + dev-sso

just register-client       # register PSA-Mokosh-Clients (public OIDC, after dev-sso up)
just register-bunyip-client
just register-lets-chat-client
```

`just dev` rewrites `MOKOSH_HOST_BIND_IP` and `USER` in `.env` each run, discovering the LAN IP from `sys net | where name =~ 'eth0|br0'`. First run copies `.env.dev` to `.env`.

`just dev-sso` requires Ed25519 keypair at `secrets/dev-key.pem` + `secrets/dev-key.pub.pem`; auto-generated via `scripts/gen-oidc-key.sh dev-key` (each dev machine generates its own; not committed).

## Architecture

### Top-level layout

```
src/
  main.rs               mokosh-server entrypoint: AppConfig::from_env, bootstrap SSO, build router
  lib.rs                library crate root
  api/router.rs         create_api_router: nests every module under /api/v1, wires middleware + CORS
  bin/mokosh-bootstrap.rs CLI: bootstrap-infisical, clients register
  db/                   Database wrapper around sqlx::PgPool
  infisical/            Infisical HTTP client + first-run bootstrap
  modules/<name>/       Feature modules (see "Modules" below)
  utils/                error, email (Mailer trait + SmtpMailer/LogMailer), crypto, validation, pagination
  version.rs            VersionInfo (build-time git hash/describe via build.rs)

crates/                 Workspace members for the SSO/auth subsystem
migrations/             SQLx migrations, embedded at compile time via sqlx::migrate!
oci-build/Dockerfile    Production multi-stage Alpine + musl
Dockerfile              Dev image (debug build, source-mounted)
compose.dev.yml         LAN-IP dev stack
compose.dev-sso.yml     Traefik overlay for per-developer SSO
.forgejo/workflows/     CI (Forgejo)
dev-docs/               codebase-state.md is the authoritative module/route catalog
```

### Auth: three independent mechanisms (PMS-291)

The server accepts up to three independent auth paths in parallel; failing to mount one does NOT disable the others:

1. **Bunyip-as-OP Resource-Server** (`src/modules/auth/oidc_rs.rs`): mokosh verifies bunyip-issued `at+jwt` Bearer tokens against bunyip's JWKS. Configured by `OIDC_ISSUER` + `OIDC_AUDIENCE`. This is the path the mokosh-apps SPA and the E2E suite actually use; tokens come from `api.<tld>` = bunyip.
2. **mokosh-auth (mokosh's own OIDC OP)** (`crates/mokosh-auth*`): a full second IdP run by mokosh itself - EdDSA `at+jwt`, OAuth client registry, federation, recovery codes, TOTP, trusted devices. `crates/mokosh-auth` is the umbrella crate; `main.rs` calls `try_bootstrap_sso`. On success the SSO router is merged into the PSA router AND its key set is passed to `AuthMiddleware::with_at_jwt(...)`. Requires: `MOKOSH_AUTH_ISSUER`, `MOKOSH_AUTH_JWT_PRIVATE_KEY_PATH`, `MOKOSH_AUTH_JWT_ACTIVE_KID`, `MOKOSH_AUTH_JWT_PUBLIC_KEYS_DIR`, `MOKOSH_AUTH_DATA_ENCRYPTION_KEY`. The Ed25519 keypair (`<kid>.pem` + `<kid>.pub.pem`) must already exist in the configured `MOKOSH_AUTH_JWT_PRIVATE_KEY_PATH` / `MOKOSH_AUTH_JWT_PUBLIC_KEYS_DIR` BEFORE first start; PMS-289 makes a missing key set a fatal boot error rather than a silent WARN.
3. **Legacy HS256 cookie auth** (`src/modules/auth/`): JWT in cookie, Argon2 password hashing, session rows in `user_sessions`. Used by the original PSA endpoints. `AuthMiddleware` decodes the cookie into an `AuthState`. Routes opt in via `RequireAuth` / `RequireRole` / `RequireAdmin` / `RequireManager` / `RequireFinance` extractors.

**Posture decision (PMS-291)**: c-01 (staging) and nc-01 (production) currently run **all three** (interim path B from PMS-292 - keys provisioned, mechanism 2 mounted). The end-state is to drop mechanism 2 entirely (bunyip-as-OP only); tracked in PMS-295 as a follow-up. Until that lands, removing `MOKOSH_AUTH_*` from the env is a viable rollback only if the keys are also removed from `MOKOSH_AUTH_JWT_*` paths.

Auth workspace crates:

```
mokosh-auth-core         Domain model, IDs, time, repository traits, policy
mokosh-auth-crypto       AEAD, Ed25519 keys, Argon2 passwords, TOTP (RFC 6238), recovery codes, opaque tokens
mokosh-auth-storage      Postgres repos: client, session, refresh, code, signup, invite, tenant, user, etc.
mokosh-auth-oidc         /authorize, /token, /userinfo, /.well-known/openid-configuration, RP-initiated logout
mokosh-auth-federation   External IdP federation
mokosh-auth-http         Axum router, handlers, extractors, cookies, rate limit, LettreMailer (separate from host Mailer)
mokosh-auth              Umbrella: re-exports + bootstrap + AuthConfig
google-oauth-flow        Reusable Google OAuth popup/code-exchange client (used by legacy /auth/google routes)
```

The host crate also imports `mokosh-auth-crypto` directly so the legacy login flow can verify TOTP without duplicating that primitive.

### Routing model

`create_api_router` (`src/api/router.rs`) builds:

- `/api/v1/*` PSA router. Every module exposes either `<name>_routes(service)` (nested under a prefix) or merges directly when it owns multiple top-level prefixes (e.g. `time_tracking_routes`, `projects_routes`, `calendar_routes`, `contracts_routes`, `billing_routes`, etc. all use `.merge`). `auth_middleware` runs globally and populates `AuthState`; route handlers opt in.
- `/api/v1/portal/*` portal router with its OWN auth middleware (identity = `contacts` row, not `users`). Never sees `AuthState`.
- Fallback for non-API paths: small HTML "not a frontend" page linking back to the SaaS shell.

`#[cfg(feature = "multi-tenant")]` gates the `/tenants` CRUD routes; default features are `["multi-tenant", "server"]`. The `server` feature gates HTTP-only code so the library crate can be reused without Axum.

### Multi-tenancy

No middleware-level tenant scoping. Every service method takes `tenant_id: Uuid` explicitly. Forgetting to thread `user.tenant_id` becomes a cross-tenant data leak. See `dev-docs/codebase-state.md` cross-cutting issue #8.

### Migrations

Single big `001_initial_schema.sql` (~71 tables) plus a few small follow-ups. Embedded at compile time via `sqlx::migrate!`; `migrations/` must exist in the build context (both Dockerfiles copy it). On server start with `RUN_MIGRATIONS=true` (default) migrations run automatically.

### Module status

Most route groups are placeholders that return HTTP 501. Only `auth`, `contacts`, `tenants`, `tickets` have real handlers. The schema is far ahead of the handler layer. Before adding a new module, read `dev-docs/codebase-state.md` for the per-module status, open TODOs (`F1..F14`), and known shallow-DTO traps in tickets.

## Conventions specific to this repo

- Branches: `fix/...`, `feat/...`, `chore/...`. Forgejo PRs via `fj pr create` (host `dev.a8n.run`). `gh` is not installed.
- Releases: `just create-release <major|minor|hotfix>` bumps `Cargo.toml`, pushes a `release/v<X.Y.Z>` branch, opens the PR. CI tags + publishes on merge.
- Email backend selection: `MailerConfig::from_env().build()` returns `SmtpMailer` if `SMTP_HOST` is set, `LogMailer` otherwise. `SMTP_USERNAME` without `SMTP_PASSWORD` is a hard error at startup (fail-loud, not silent degrade).
- `ENCRYPTION_KEY` must parse as 32 bytes (raw or 64 hex chars) via `utils::crypto::parse_encryption_key`. Used for AES-256-GCM at-rest encryption of per-tenant secrets (e.g. payment-gateway configs).
- `CORS_ORIGIN` is comma-separated; required to be a valid header value or startup panics. Defaults to `[CLIENT_ORIGIN]`.
- Docker resource naming: every service/volume/network is prefixed with the app name; dev resources get an extra `dev-` prefix. Sub-service data stores sort adjacent to their parent (`dev-backup-infisical-postgres`, not `dev-backup-postgres-infisical`).
- Dev stack binds to a private LAN IP (br0/eth0), not 127.0.0.1, so sibling containers on the host can reach the API while the public internet cannot.
