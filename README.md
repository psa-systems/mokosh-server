# Mokosh Server

Professional Services Automation (PSA) platform for MSPs. REST API server built on Axum + SQLx + PostgreSQL. Secrets are sourced from a self-hosted Infisical instance.

## Architecture

- **HTTP**: Axum 0.8 (Tokio runtime) with Tower middleware (CORS, tracing, gzip, request limits, request-id).
- **Database**: PostgreSQL 18 via SQLx (compile-time-checked migrations).
- **Secrets**: Infisical (Universal Auth machine identity) reached over HTTP.
- **Email**: Lettre (SMTP).
- **Auth**: JWT (HS256) plus Argon2 password hashing.
- **Tenancy**: feature-flagged. `multi-tenant` is the default; `single-tenant` is also supported.

Modules under `src/modules/` cover the typical PSA surface area: `tickets`, `contracts`, `contacts`, `billing`, `projects`, `assets`, `time_tracking`, `sla`, `rmm`, `knowledge_base`, `portal`, `reports`, `notifications`, `audit`, `auth`, `tenants`, `settings`, `calendar`.

## Binaries

| Binary | Purpose |
| --- | --- |
| `mokosh-server` | Long-running HTTP API (Axum). |
| `mokosh-bootstrap` | One-shot CLI that performs first-run setup of a fresh Infisical instance and writes the resulting Universal Auth credentials into `.env`. |

## Prerequisites

- Rust toolchain (matches `rust-toolchain.toml` if present, otherwise stable).
- Docker + Docker Compose v2.
- [`just`](https://github.com/casey/just) for the task runner.
- [Nushell `0.112.2`](https://www.nushell.sh/) (used by several `just` recipes).
- (No host-side PostgreSQL needed - the dev compose stack now bundles a `postgres` service for the app DB, published to the host on `${MOKOSH_HOST_BIND_IP}:${MOKOSH_PG_HOST_PORT:-5433}` for `sqlx-cli`.)

## Quick start

The dev stack lives in `compose.dev.yml` and is driven entirely through `just`. The first run copies `.env.dev` to `.env` (gitignored) and discovers the host's private LAN IP automatically.

```nu
# 1. Bring up the dev stack (mokosh-server + Infisical + Postgres + Valkey).
#    The recipe discovers the host bind IP from `sys net | where name =~ 'eth0|br0'`
#    and publishes mokosh-server on `${MOKOSH_HOST_BIND_IP}:${MOKOSH_PORT}`.
just dev

# 2. In a second terminal, bootstrap Infisical (one-time, after the
#    container is healthy). See "Infisical bootstrap" below for the
#    .env.infisical contents this needs.
just infisical-bootstrap

# 3. Re-run `just dev` so the server picks up the new INFISICAL_* values.
just dev-down
just dev
```

The API is then reachable at `http://<MOKOSH_HOST_BIND_IP>:<MOKOSH_PORT>` (defaults to the host's br0/eth0 IP on port `4301`). The Infisical admin UI is reachable at `http://localhost:28002`.

### Why a private LAN bind, not 127.0.0.1?

The dev host is a VPS on the public internet. Binding to `127.0.0.1` would hide the port from the internet but also prevent other Docker containers on the host from reaching it. Binding to a private LAN interface (br0/eth0, e.g. `172.16.x.x`) keeps the port off the public internet and still allows sibling containers to connect.

## Configuration

| Variable | Where set | Purpose |
| --- | --- | --- |
| `COMPOSE_FILE` | `.env` | Pins `docker compose` to `compose.dev.yml`. |
| `DATABASE_URL` | `.env` | Host-side connection string against the bundled `postgres` service (used by `sqlx migrate`, `cargo run` on the host). |
| `MOKOSH_PG_DB`, `MOKOSH_PG_USER`, `MOKOSH_PG_PASSWORD` | `.env` | App-database credentials. Dev defaults only. |
| `MOKOSH_PG_HOST_PORT` | `.env` | Host-published port for the `postgres` service. Default `5433`. |
| `MOKOSH_PORT` | `.env` | TCP port for the API server (container and host bind). |
| `MOKOSH_HOST_BIND_IP` | written to `.env` by `just dev` | Host interface IP that the container's port is published on. Falls back to `127.0.0.1` when unset. |
| `JWT_SECRET`, `ENCRYPTION_KEY` | `.env` | API server secrets. Dev defaults only; rotate for any non-local environment. |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | `.env` | Optional first-run admin bootstrap. Dev only; see "First-run admin bootstrap" below. |
| `INFISICAL_*` | `.env` | Infisical server config (bootstrap inputs) and Universal Auth client credentials (filled by `mokosh-bootstrap`). |
| `RUST_LOG` | `.env` | Tracing subscriber filter. |

`compose.dev.yml` references every value via `${VAR}` substitution and contains no hardcoded secrets. Required vars use `${VAR:?...}` so compose fails loudly with a helpful message when a value is missing.

## Recipes

```nu
just                       # list all recipes
just dev [args]            # bring up the dev stack (passes args to `docker compose up`, e.g. --detach)
just dev-down              # stop the dev stack (volumes preserved)
just dev-clean             # stop and remove volumes; remove .env (preserves .env.infisical)
just infisical-bootstrap   # one-time: drives Infisical first-run setup and rewrites .env
just check                 # cargo check + clippy + fmt --check
just check-clippy
just check-compile
just check-fmt
just fmt
just test
just build                 # cargo build --release --bins
just check-docker          # build the OCI image's builder stage only (validation)
just build-docker          # build the production OCI image (oci-build/Dockerfile)
just migrate-run           # apply pending migrations against $DATABASE_URL
just migrate-create <name> # create a new migration file
just create-release <bump> # bump version (major|minor|hotfix), push release branch, print PR link
```

## First-run admin bootstrap

When both `ADMIN_EMAIL` and `ADMIN_PASSWORD` are set in `.env` AND the `users` table is empty, the server creates a `super_admin` user under the default tenant on startup. The account is marked `active` and `email_verified_at = NOW()`, so you can log in immediately without going through the signup or email-verification flow.

Once any user exists in the database, the env vars are ignored on subsequent startups. It is safe to leave `ADMIN_EMAIL` / `ADMIN_PASSWORD` in `.env` indefinitely.

The dev `.env.dev` ships with `admin@example.com` / `devpassword12`. Override locally:

```nu
# Override in .env (gitignored), then restart the stack.
"ADMIN_EMAIL=you@example.com\nADMIN_PASSWORD=at-least-12-characters\n" | save --append .env
just dev-down
just dev
```

DEV ONLY. Production deployments should provision the first admin through a real workflow (signup form, IaC, manual SQL) rather than environment variables.

## Infisical bootstrap

The first-run setup is driven by `mokosh-bootstrap` (invoked via `just infisical-bootstrap`). The recipe loads `.env.infisical` (gitignored) before invoking the binary, so the admin password never lands in shell history.

```nu
# Create the gitignored credentials file.
"INFISICAL_ADMIN_EMAIL=admin@example.com
INFISICAL_ADMIN_PASSWORD=at-least-12-characters
" | save .env.infisical

# Run bootstrap. This signs up the admin, creates the project and machine
# identity, and writes INFISICAL_PROJECT_ID / INFISICAL_CLIENT_ID /
# INFISICAL_CLIENT_SECRET back into .env.
just infisical-bootstrap

# Verify .env now has the three Universal Auth values populated.
open .env | lines | where ($it | str starts-with 'INFISICAL_')
```

After bootstrap, restart the stack so the API server picks up the new credentials:

```nu
just dev-down
just dev
```

## Database migrations

Migrations live in `migrations/` and are embedded into the binary at compile time via `sqlx::migrate!`. They run automatically on server start when `RUN_MIGRATIONS=true` (the default).

```nu
# Apply pending migrations against $DATABASE_URL (host-side).
just migrate-run

# Create a new migration.
just migrate-create add_widgets_table
```

Compile-time migration validation requires the `migrations/` directory to be present at build time. Both the dev `Dockerfile` and `oci-build/Dockerfile` copy it into the image.

## Docker images

Two Dockerfiles, two purposes.

| File | Purpose |
| --- | --- |
| `Dockerfile` | Dev image. Debug build, source mounted from the host via volumes, `cargo run` as the entrypoint. Used by `compose.dev.yml`. |
| `oci-build/Dockerfile` | Production image. Multi-stage Alpine build (musl + lld), release binaries, non-root `appuser`, healthcheck on `/api/v1/health`. Built and published as a multi-arch image (`linux/amd64`, `linux/arm64`) by the Forgejo workflow in `.forgejo/workflows/build-oci-image.yml`. |

## Operator deployment (`compose.yml`)

The repo root ships a `compose.yml` for operators: self-hosters and our own production stacks. It pulls a published image from the container registry (no local source build) and bundles the application Postgres.

```nu
# 1. Configure
cp .env.example .env
# Edit .env: set MOKOSH_PG_PASSWORD, JWT_SECRET, ENCRYPTION_KEY,
# CORS_ORIGIN, BASE_URL, and (optionally) MOKOSH_VERSION to pin a tag.

# 2. Pull and start
docker compose pull
docker compose up --detach

# 3. Confirm
curl --include http://localhost:8080/api/v1/health
curl --silent http://localhost:8080/api/v1/version | jq
```

### Applying updates

Updates are deliberate operator actions. The running server exposes `GET /api/v1/version/check` which reports whether a newer release tag is available:

```nu
curl --silent http://localhost:8080/api/v1/version/check | jq
# {
#   "enabled": true,
#   "running": "0.2.0",
#   "latest": "v0.3.0",
#   "update_available": true,
#   "source_url": "https://dev.a8n.run/api/v1/repos/psa-systems/mokosh-server/releases/latest",
#   "error": null
# }
```

The lookup target is configured via `UPDATE_CHECK_URL` (any release feed that returns JSON with a `tag_name` field; defaults to the upstream Forgejo release endpoint). Leave `UPDATE_CHECK_URL` empty to disable - the endpoint then reports `enabled: false` and makes no network calls. Results are cached for 10 minutes inside the server process.

To apply an available update:

```nu
# Optional: pin the new version in .env
"MOKOSH_VERSION=v0.3.0\n" | save --append .env

docker compose pull
docker compose up --detach
```

### Image tags

Multi-arch images (`linux/amd64`, `linux/arm64`) are published to `dev.a8n.run/psa-systems-private/mokosh-api` on every push to `main`. Operator tag policy:

| Tag | Use |
| --- | --- |
| `:latest` | Tracks `main`. Acceptable for staging; not for production. |
| `:vX.Y.Z` | Immutable release tag created by the `create-release` workflow. Use for production pins. |

## Repository layout

```
src/
  api/           Axum router composition.
  bin/           CLI binaries (mokosh-bootstrap).
  db/            Database connection + helpers.
  infisical/    Infisical client + first-run bootstrap.
  modules/       Feature modules (tickets, contracts, billing, ...).
  utils/         Shared helpers (errors, ...).
  lib.rs         Library crate entrypoint.
  main.rs        mokosh-server binary entrypoint.
migrations/      SQLx migrations (embedded at compile time).
oci-build/       Production OCI image (multi-stage Alpine).
Dockerfile       Dev OCI image (debug build, source-mounted).
compose.dev.yml  Dev stack: mokosh-server + Infisical + Postgres + Valkey.
.env.dev         Dev defaults (copied to .env on first `just dev`).
.env.example     Sanitized example for non-dev environments.
justfile         Task runner.
.forgejo/        CI workflows (Forgejo).
.devcontainer/   VS Code devcontainer config.
```

## Releases

`just create-release <major|minor|hotfix>` bumps the version in `Cargo.toml`, creates and pushes a `release/v<X.Y.Z>` branch, and prints the PR URL. After the PR merges, the `create-release` workflow tags and publishes the release automatically.

## License

Proprietary. See `Cargo.toml`.
