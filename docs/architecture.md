# Architecture

What mokosh-server is made of: the runtime pieces, where the code lives, how the schema moves, and what ships as an image. Start with [`quickstart.md`](quickstart.md) if you just want the dev stack running.

## Runtime shape

- **HTTP**: Axum 0.8 (Tokio runtime) with Tower middleware (CORS, tracing, brotli/gzip compression, request limits, request-id).
- **Database**: PostgreSQL 18 via SQLx (compile-time-checked migrations).
- **Secrets**: tenant-supplied secrets are AES-256-GCM ciphertext in the database by default, encrypted under `ENCRYPTION_KEY` (`SECRET_BACKEND=database`). `SECRET_BACKEND=infisical` keeps them in a self-hosted Infisical instance reached over HTTP instead, and then also requires `INFISICAL_ADDRESS`, `INFISICAL_PROJECT_ID`, `INFISICAL_CLIENT_ID` and `INFISICAL_CLIENT_SECRET`. An unrecognized value is a startup error rather than a fall back to the default.
- **Email**: Lettre (SMTP).
- **Auth**: two independent mechanisms run in parallel, and failing to mount one does not disable the other. The SPA and the E2E suite authenticate through bunyip, the sole OpenID Connect provider: mokosh verifies bunyip-issued Bearer tokens against bunyip's JWKS, configured by `OIDC_ISSUER` and `OIDC_AUDIENCE`. The original PSA endpoints use the legacy HS256 cookie session with Argon2 password hashing. The "Auth" section of [`CLAUDE.md`](../CLAUDE.md) carries the detail.
- **Tenancy**: multi-tenant only. Every service method takes an explicit `tenant_id`; the former `single-tenant` cargo feature was removed.

## Modules

Feature modules live under `src/modules/`, one directory each, and cover the usual PSA surface area: tickets, contracts, contacts, billing, quotes, projects, assets, time tracking, SLAs, RMM, knowledge base, portal, reports, notifications, audit, auth, tenants, settings and calendar, among others.

That list is illustrative, not a census: a hand-copied one goes stale within a month and a reader cannot tell. `ls src/modules` is the current set, `src/api/router.rs` is what is actually mounted, and the "Routing model" section of [`CLAUDE.md`](../CLAUDE.md) says what authenticates each top-level nest under `/api/v1`.

## Why Traefik ingress, and why loopback for the rest?

The dev host is a VPS on the public internet, and several developers share it. The `server` is reached only through the shared Traefik, which gives each developer their own `*.a8n.run` hostname with a real Let's Encrypt certificate instead of a port on a shared IP. Everything else that needs a host port (`postgres` for `sqlx-cli`, `mailpit` for the mail UI, `infisical` for its admin UI) publishes on `127.0.0.1` only, so it is reachable from the host's own tooling and from nowhere else. Sibling containers do not need a host port either: they reach each service by its compose DNS name on the `dev-mokosh-private-${USER}` network.

## Database migrations

Migrations live in `migrations/` and are embedded into the binary at compile time via `sqlx::migrate!`. They run automatically on server start when `RUN_MIGRATIONS=true`, which is the default whether or not the variable is set.

```nu
# Apply pending migrations against $DATABASE_URL (host-side).
just migrate-run

# Create a new migration.
just migrate-create add_widgets_table
```

Compile-time migration validation requires the `migrations/` directory to be present at build time. Both the dev `Dockerfile` and `oci-build/Dockerfile` copy it into the image.

A migration already on `main` is immutable: SQLx re-verifies applied-migration checksums on boot, so editing one stops every deployed database. `just check-migration-immutability` is the guard.

## Docker images

Two Dockerfiles, two purposes.

| File | Purpose |
| --- | --- |
| `Dockerfile` | Dev image. Debug build, source mounted from the host via volumes, `cargo run` as the entrypoint. Used by `compose.dev.yml`. |
| `oci-build/Dockerfile` | Production image. Multi-stage Alpine build (musl + lld), release binaries, non-root `appuser`, healthcheck on `/api/v1/health`. Built and published by the Forgejo workflow in `.forgejo/workflows/build-oci-image.yml`. |

## Repository layout

```
src/
  api/             Axum router composition: create_api_router builds every /api/v1 nest.
  bin/             Standalone CLI binaries (mokosh-bootstrap).
  cli.rs           Operator subcommands the mokosh-server binary dispatches before it binds a port.
  db/              Database wrapper around sqlx::PgPool, plus the per-tenant transaction helpers.
  infisical/       Infisical HTTP client + first-run bootstrap.
  modules/         Feature modules (tickets, contracts, billing, ...).
  pdf/             Document model, and the one place it becomes PDF bytes.
  scheduler/       Registry for the interval background jobs.
  secrets/         Secret backend selection (database or Infisical) behind one store trait.
  storage/         Upload root and file storage, the single reader of ATTACHMENT_DIR.
  utils/           Shared helpers (errors, email, crypto, validation, pagination).
  version.rs       VersionInfo (build-time git hash/describe via build.rs).
  version_check.rs Opt-in self-hosted update check against MOKOSH_UPDATE_CHECK_URL.
  lib.rs           Library crate entrypoint.
  main.rs          mokosh-server binary entrypoint.
crates/            Workspace members: mokosh-types, build-metadata.
migrations/        SQLx migrations (embedded at compile time).
oci-build/         Production OCI image (multi-stage Alpine).
Dockerfile         Dev OCI image (debug build, source-mounted).
compose.dev.yml    Dev stack: mokosh-server + Postgres + mailpit, routed by the shared Traefik
                   (Infisical + its Postgres + Valkey sit behind the `infisical` profile).
.env.example       Committed template; the first `just dev` generates .env from it with fresh per-clone secrets.
justfile           Task runner.
.forgejo/          CI workflows (Forgejo).
.devcontainer/     VS Code devcontainer config.
docs/              This documentation set; docs/dev-docs/ holds the internal notes.
```

## Releases

`just create-release <major|minor|hotfix>` bumps the version in `Cargo.toml`, creates and pushes a `release/v<X.Y.Z>` branch, and prints the PR URL. After the PR merges, the `create-release` workflow tags and publishes the release automatically.
