# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Mokosh Server: PSA (Professional Services Automation) REST API for MSPs. Rust + Axum + SQLx + PostgreSQL. Two binaries:

- `mokosh-server`: long-running HTTP API (`src/main.rs`).
- `mokosh-bootstrap`: one-shot CLI for first-run Infisical setup and OIDC client registration (`src/bin/mokosh-bootstrap.rs`).

## Common commands

All driven through `just` (see `justfile`). Required tooling: `just`, Nushell `0.112.2`, Docker + Compose v2, Rust stable, `sqlx-cli` for migrations, `cargo-machete` for the unused-dependency gate (`cargo install --locked cargo-machete`).

```
just                       # list recipes
just check                 # cargo check + clippy + fmt --check + repo guards (run before pushing)
just check-compile         # cargo check --all-targets
just check-clippy          # cargo clippy --all-targets
just check-fmt             # cargo fmt --all --check
just check-unused-deps     # cargo-machete: fail on a dependency with no call site
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

Single test: `cargo test -p <crate> <test_name>` (workspace), e.g. `cargo test -p mokosh-server utils::totp::tests::rfc6238_vector`.

### Dev stack

A single Traefik-routed dev stack (PMS-511 folded the former SSO overlay into `compose.dev.yml`):

```
just dev                   # Traefik-routed stack at https://${USER}-mokosh-api.a8n.run (mokosh-server + Postgres + mailpit)
just dev-infisical         # opt-in: Infisical + its Postgres (compose profile: infisical)
just down                  # stop the dev stack, remove orphans (volumes preserved)
just dev-clean             # stop + wipe volumes + remove .env (keeps .env.infisical)
just infisical-bootstrap   # one-time after `just dev-infisical`, fills INFISICAL_* in .env
```

OIDC client registration recipes (`register-client`, etc.) were removed with mokosh-auth in PMS-295: bunyip is the sole OP and owns its own client registry, so RPs register with bunyip, not mokosh.

`just dev` rewrites `MOKOSH_HOST_BIND_IP` and `USER` in `.env` each run (the LAN IP, discovered from `sys net | where name =~ 'eth0|br0'`, still drives the published `postgres`/`mailpit` host ports for sqlx-cli and the mail UI; the `server` itself is ingress-only via Traefik). First run generates `.env` from the committed `.env.example` (via the `ensure-env` recipe, a dependency of `just dev`), minting fresh random values for every self-owned secret (PMS-490: DB passwords, `JWT_SECRET`, `ENCRYPTION_KEY`, the Infisical secrets) and leaving third-party credentials as empty placeholders. It does not copy a file; an existing `.env` is left untouched, so the generation runs once per clone.

`just dev-infisical` rewrites `MOKOSH_SERVER_INFISICAL_ADDRESS` in `.env` to `http://infisical:8080`, which compose passes to the `server` container as `INFISICAL_ADDRESS` (restart `server` to pick it up). It stays empty on a plain `just dev` so the readiness probe reports `checks.infisical == "skipped"` rather than 503ing against the profile-gated service (PMS-707). The separate plain `INFISICAL_BASE_URL` in `.env` is a different key: the host-side `http://localhost:28002` that `just infisical-bootstrap` uses.

`just dev` requires the shared external `network-traefik-public` to already exist. (Before PMS-295 it also needed a local Ed25519 keypair for mokosh-auth's OP signing; that subsystem is gone, so no key material is provisioned now. The bunyip-as-OP Resource-Server path verifies tokens against bunyip's JWKS over the network.)

## Architecture

### Top-level layout

```
src/
  main.rs               mokosh-server entrypoint: AppConfig::from_env, build router
  lib.rs                library crate root
  api/router.rs         create_api_router: nests every module under /api/v1, wires middleware + CORS
  bin/mokosh-bootstrap.rs CLI: bootstrap-infisical, qa-seed/qa-teardown
  db/                   Database wrapper around sqlx::PgPool
  infisical/            Infisical HTTP client + first-run bootstrap
  modules/<name>/       Feature modules (see "Modules" below)
  utils/                error, email (Mailer trait + SmtpMailer/LogMailer), crypto, validation, pagination
  version.rs            VersionInfo (build-time git hash/describe via build.rs)

crates/                 Workspace members: google-oauth-flow, mokosh-types, build-metadata
migrations/             SQLx migrations, embedded at compile time via sqlx::migrate!
oci-build/Dockerfile    Production multi-stage Alpine + musl
Dockerfile              Dev image (debug build, source-mounted)
compose.dev.yml         Traefik-routed dev stack (per-developer *.a8n.run)
.forgejo/workflows/     CI (Forgejo)
docs/                   Contributor/user docs; docs/dev-docs/ = internal notes (codebase-state.md = module/route catalog)
```

### Auth: two independent mechanisms (PMS-295)

bunyip-as-OP is the only OP. PMS-295 removed mokosh-auth (mechanism 2, mokosh's own OIDC OP) entirely; the server now accepts two independent auth paths in parallel, and failing to mount one does NOT disable the other:

1. **Bunyip-as-OP Resource-Server** (`src/modules/auth/oidc_rs.rs`): mokosh verifies bunyip-issued `at+jwt` Bearer tokens against bunyip's JWKS. Configured by `OIDC_ISSUER` + `OIDC_AUDIENCE`. This is the path the mokosh-apps SPA and the E2E suite actually use; tokens come from `api.<tld>` = bunyip. Mokosh holds no signing key and exposes no `/oauth2/*` endpoints.
2. **Legacy HS256 cookie auth** (`src/modules/auth/`): JWT in cookie, Argon2 password hashing, session rows in `user_sessions`. Used by the original PSA endpoints. `AuthMiddleware` decodes the cookie into an `AuthState`. Routes opt in via `RequireAuth` / `RequireRole` / `RequireAdmin` / `RequireManager` / `RequireFinance` extractors. TOTP (RFC 6238) + MFA recovery codes for this path live in `src/utils/totp.rs` + `src/utils/recovery.rs` (relocated from the removed `mokosh-auth-crypto` crate in PMS-295).

Both paths run the same principal gate (PMS-698): `AuthService::ensure_principal_usable` rejects a `users.status != 'active'` row and a tenant whose `status != 'active'`, so deactivating a user or suspending a tenant takes effect on the very next request regardless of which mechanism minted the token. The PMS-681 `iat`-vs-`password_changed_at` cutoff stays legacy-only on purpose: bunyip owns the credential on path 1, so a mokosh-side password change is not a revocation signal there.

**History (PMS-291 / PMS-292 / PMS-289)**: mokosh-auth was a configured-but-unused second IdP (`crates/mokosh-auth*`). PMS-289 made a misconfigured mokosh-auth a fatal boot error, which took staging+prod down (PMS-292 restored service by provisioning keys - interim path B). PMS-295 is the path-A follow-up: tear mokosh-auth out so `MOKOSH_AUTH_*` env, the `crates/mokosh-auth*` workspace members, and the `mokosh-server-secrets` volume all go away. The server boots fine with no `MOKOSH_AUTH_*` env present.

Remaining auth-adjacent workspace crate:

```
google-oauth-flow        Reusable Google OAuth popup/code-exchange client (used by legacy /auth/google routes)
```

### Routing model

`create_api_router` (`src/api/router.rs`) builds:

- `/api/v1/*` PSA router. Every module exposes either `<name>_routes(service)` (nested under a prefix) or merges directly when it owns multiple top-level prefixes (e.g. `time_tracking_routes`, `projects_routes`, `calendar_routes`, `contracts_routes`, `billing_routes`, etc. all use `.merge`). `auth_middleware` runs globally and populates `AuthState`; route handlers opt in.
- `/api/v1/portal/*` portal router with its OWN auth middleware (identity = `contacts` row, not `users`). Never sees `AuthState`.
- Fallback for non-API paths: small HTML "not a frontend" page linking back to the SaaS shell.

`#[cfg(feature = "multi-tenant")]` gates the `/tenants` CRUD routes; default features are `["multi-tenant", "server"]`. The `server` feature gates HTTP-only code so the library crate can be reused without Axum.

### Multi-tenancy

No middleware-level tenant scoping. Every service method takes `tenant_id: Uuid` explicitly. Forgetting to thread `user.tenant_id` becomes a cross-tenant data leak. See `docs/dev-docs/codebase-state.md` cross-cutting issue #8.

### Migrations

Per-feature files under `migrations/` (split from the original `001_initial_schema.sql` monolith in PMS-198). Embedded at compile time via `sqlx::migrate!`; `migrations/` must exist in the build context (both Dockerfiles copy it). On server start with `RUN_MIGRATIONS=true` (default) migrations run automatically.

**Migrations are immutable once committed.** sqlx stores a SHA-384 checksum of each migration in `_sqlx_migrations` when it applies it, and re-verifies on every startup. Editing (or renaming/deleting) a migration that has already been applied to any database makes that database refuse to boot with `migration N was previously applied but has been modified` (this is exactly how v0.4.0 broke nc-01: `023_seed_data.sql` was edited after a build had applied it). To change schema or seed data, add a NEW migration with `just migrate-create <name>` - never edit an existing one. CI enforces this: `scripts/check-migration-immutability.nu` (wired into `.forgejo/workflows/check.yml`, DEV-395) fails any PR that modifies/renames/deletes a migration already on `main`, alongside `check-migration-prefixes.nu` (prefix uniqueness, PMS-198).

### Module status

Most route groups have real handlers. `src/api/router.rs` nests/merges ~30 implemented modules (`auth`, `contacts`, `tenants`, `tickets`, `billing`, `projects`, `calendar`, `contracts`, `quotes`, `assets`, `rmm`, `sla`, `saved_reports`, `workflows`, `time_tracking`, and more); the old `stub_routes()` 501 placeholder mechanism is gone. The only endpoint still returning HTTP 501 is the PDF format of the report-export route (`src/modules/reports/routes.rs`); CSV is implemented. The schema is still ahead of the handler layer in places. Before adding a new module, read `docs/dev-docs/codebase-state.md` for the per-module status, open TODOs (`F1..F14`), and known shallow-DTO traps in tickets.

## Conventions specific to this repo

- Branches: `fix/...`, `feat/...`, `chore/...`. Forgejo PRs via `fj pr create` (host `dev.a8n.run`). `gh` is not installed.
- CI runner labels (PMS-719, GOV-43): a job that compiles on the runner requests `RUNS_ON_OPENSUSE_DEV_LATEST` (only that image ships `cc` / `gcc` / `ld` plus glibc and OpenSSL headers); everything else stays on `RUNS_ON_OPENSUSE_BASE_LATEST`. Base plus a compile fails at `linker cc not found` on a cold cache (PMS-705, PMS-706); the fix is the label, never a run-time `zypper install gcc`. `scripts/check-runner-labels.nu` (in `just check` and `check.yml`) enforces this and requires every `runs-on:` to carry a comment justifying its label.
- OCI build cache (PMS-720, GOV-20): `build-oci-image.yml` builds on a `docker-container` buildx driver and caches to the runner's built-in Actions cache server (`cache_from type=gha`, `cache_to type=gha,mode=max,ignore-error=true`), with `crazy-max/ghaction-github-runtime@v3` re-exporting `ACTIONS_CACHE_URL` / `ACTIONS_RUNTIME_TOKEN` so a raw `docker buildx build` can reach it. The retired `type=inline` and `type=registry` `:buildcache` backends are banned. `scripts/check-oci-build-cache.nu` (in `just check` and `check.yml`) enforces this; because `ignore-error=true` makes a dead cache go green silently, read freshness from the build log's `importing cache manifest from gha` line, not the exit code.
- Unused dependencies (PMS-780): `cargo machete` runs in `just check` and `check.yml` as a blocking gate, so a crate declared in `Cargo.toml` with no call site fails the PR. `pulldown-cmark` and `minijinja` had been compiled on every cold build for nothing. Response compression is brotli-then-gzip: `CompressionLayer::new()` offers only the algorithms whose `tower-http` cargo features are compiled in, so `compression-br` must stay in the feature list (guarded by the negotiation tests in `src/api/router.rs`).
- Releases: `just create-release <major|minor|hotfix>` bumps `Cargo.toml`, pushes a `release/v<X.Y.Z>` branch, opens the PR. CI tags + publishes on merge.
- Email backend selection: `MailerConfig::from_env().build()` returns `SmtpMailer` if `SMTP_HOST` is set, `LogMailer` otherwise. `SMTP_USERNAME` without `SMTP_PASSWORD` is a hard error at startup (fail-loud, not silent degrade).
- `ENCRYPTION_KEY` must parse as 32 bytes (raw or 64 hex chars) via `utils::crypto::parse_encryption_key`. Used for AES-256-GCM at-rest encryption of per-tenant secrets (e.g. payment-gateway configs).
- `CORS_ORIGIN` is comma-separated; required to be a valid header value or startup panics. Defaults to `[CLIENT_ORIGIN]`.
- `LOGIN_APPROVAL_ENABLED` (PMS-658) turns on the suspicious-login notify-and-approve gate; off by default because it can withhold a login, so it is opt-in per deployment for a staged rollout. When on and a password login clears password/MFA but comes from a new country (needs `IP2LOCATION_DB_PATH`) or a new device (client-supplied `device_id` in the login body), the session/tokens are withheld and a single-use 6-digit code is emailed; the client re-POSTs `/auth/login` with `approval_code` to finish (mirrors the `mfa_required` flow). Off = the PMS-657 alert-only behaviour. Gates password login in v1 (Google and portal are follow-ups); tables `login_approvals` + `user_login_devices`.
- Docker resource naming: every service/volume/network is prefixed with the app name; dev resources get an extra `dev-` prefix. Sub-service data stores sort adjacent to their parent (`dev-backup-infisical-postgres`, not `dev-backup-postgres-infisical`).
- Dev stack binds to a private LAN IP (br0/eth0), not 127.0.0.1, so sibling containers on the host can reach the API while the public internet cannot.
