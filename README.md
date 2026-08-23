# Mokosh Server

Professional Services Automation (PSA) platform for MSPs. REST API server built on Axum + SQLx + PostgreSQL. Secrets are sourced from a self-hosted Infisical instance.

<!--
BUNYIP-587 records the shared Bunyip-to-Mokosh walkthrough GIF. When it lands,
commit a copy at docs/assets/mokosh-walkthrough.gif (a cross-repo relative path
to the Bunyip copy does not render on the mirrors, and hot-linking the raw asset
URL is fragile) and replace this comment with:
![Mokosh walkthrough](docs/assets/mokosh-walkthrough.gif)
-->

## Try it

Live staging: **<https://msp.a8n.systems>**. Sign in through the platform and click through the product; the walkthrough starts in Bunyip and moves into Mokosh.

> Staging shows features **in development**, not a polished demo. State is **wiped on every deploy** - accounts and data are throwaway. Do not reuse a real password.

## Architecture

- **HTTP**: Axum 0.8 (Tokio runtime) with Tower middleware (CORS, tracing, brotli/gzip compression, request limits, request-id).
- **Database**: PostgreSQL 18 via SQLx (compile-time-checked migrations).
- **Secrets**: Infisical (Universal Auth machine identity) reached over HTTP.
- **Email**: Lettre (SMTP).
- **Auth**: JWT (HS256) plus Argon2 password hashing.
- **Tenancy**: multi-tenant only. Every service method takes an explicit `tenant_id`; the former `single-tenant` cargo feature was removed in PMS-262.

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
- The shared Traefik ingress network `network-traefik-public` must already exist; `compose.dev.yml` attaches to it as an external network and `just dev` fails if it is absent.
- (No host-side PostgreSQL needed - the dev compose stack bundles a `postgres` service for the app DB, published on `127.0.0.1:${MOKOSH_PG_HOST_PORT:-5433}` for `sqlx-cli`.)

## Quick start

The dev stack lives in `compose.dev.yml` and is driven entirely through `just`. The first run generates `.env` (gitignored) from the committed `.env.example`, minting fresh random values for every self-owned secret.

```nu
# 1. Bring up the dev stack: mokosh-server + Postgres + mailpit.
just dev

# 2. Stop it when you are done, from a second terminal or after Ctrl-C
#    (volumes are preserved).
just down
```

That is the whole loop. The API is reached through the shared Traefik, which terminates TLS and routes **`https://<your-username>-mokosh-api.a8n.run`** to the `server` container's `MOKOSH_PORT` (`8080`). The `server` service publishes no host port at all: Traefik is its sole ingress, so there is no `http://<ip>:8080` to curl. Mailpit's web UI is at `http://localhost:8025`.

Infisical is opt-in and not part of `just dev`. Start it, then run the one-time bootstrap:

```nu
# 3. (Optional) Start Infisical + its Postgres sidecar (compose profile: infisical).
just dev-infisical

# 4. In a second terminal, bootstrap Infisical once it is healthy. See
#    "Infisical bootstrap" below for the .env.infisical contents this needs.
just infisical-bootstrap

# 5. Restart the stack so the server picks up the new INFISICAL_* values.
just down
just dev
```

The Infisical admin UI is at `http://localhost:28002`.

### Why Traefik ingress, and why loopback for the rest?

The dev host is a VPS on the public internet, and several developers share it. The `server` is reached only through the shared Traefik, which gives each developer their own `*.a8n.run` hostname with a real Let's Encrypt certificate instead of a port on a shared IP. Everything else that needs a host port (`postgres` for `sqlx-cli`, `mailpit` for the mail UI, `infisical` for its admin UI) publishes on `127.0.0.1` only, so it is reachable from the host's own tooling and from nowhere else (PMS-496). Sibling containers do not need a host port either: they reach each service by its compose DNS name on the `dev-mokosh-private-${USER}` network.

## Configuration

| Variable | Where set | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | `.env` | Host-side connection string against the bundled `postgres` service (used by `sqlx migrate`, `cargo run` on the host). |
| `MOKOSH_PG_DB`, `MOKOSH_PG_USER`, `MOKOSH_PG_PASSWORD` | `.env` | App-database credentials. The password is generated per clone on first `.env` creation. |
| `MOKOSH_PG_HOST_PORT` | `.env` | Loopback port the `postgres` service is published on. Default `5433`. |
| `MOKOSH_PORT` | `.env` | Port the API server listens on inside its container, and the port Traefik forwards to. Default `8080`. |
| `MOKOSH_HOST_BIND_IP`, `USER` | written to `.env` by `just dev` | The host's private LAN IP and your username. `USER` names the per-developer containers, volumes, networks and the `${USER}-mokosh-api.a8n.run` route. Nothing publishes a port on `MOKOSH_HOST_BIND_IP`. |
| `MOKOSH_SERVER_INFISICAL_ADDRESS` | written to `.env` by `just dev-infisical` | In-network Infisical URL handed to the server as `INFISICAL_ADDRESS`. Empty on a plain `just dev`, which makes the readiness probe report Infisical as `skipped`. |
| `JWT_SECRET`, `ENCRYPTION_KEY` | `.env` | API server secrets, generated per clone on first `.env` creation; provision them explicitly for any non-local environment. |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | `.env` | Optional first-run admin bootstrap. Dev only; see "First-run admin bootstrap" below. |
| `INFISICAL_*` | `.env` | Infisical server config (bootstrap inputs) and Universal Auth client credentials (filled by `mokosh-bootstrap`). |
| `ATTACHMENT_DIR` | `.env` | Upload root for ticket attachments and tenant logos. The dev stack points it at `/data/attachments` on the `dev-mokosh-attachments-${USER}` volume so an upload survives a rebuild; deployed environments want an absolute path on a mounted volume. |
| `RUST_LOG` | `.env` | Tracing subscriber filter. |

`compose.dev.yml` references every value via `${VAR}` substitution and contains no hardcoded secrets. Required vars use `${VAR:?...}` so compose fails loudly with a helpful message when a value is missing.

## Recipes

Every recipe `just --list` prints is listed here; run `just --list` for the grouped view straight from the `justfile`.

```nu
# General
just                        # the `default` recipe: list every recipe
just install-hooks          # install the git pre-commit hook (once per fresh clone) -> runs `just pre-commit`
just pre-commit             # check.yml's cargo checks (fmt/clippy/compile/unit/doc) in the dev `server` container

# Dev stack
just dev [args]             # start the Traefik-routed dev stack (args go to `docker compose up`, e.g. --build --detach)
just dev-infisical [args]   # start Infisical and its Postgres sidecar (compose profile: infisical)
just down                   # stop the dev stack (volumes preserved)
just dev-clean              # stop the stack, remove this repo's volumes and target/, delete .env (keeps .env.infisical)
just dev-clean-all          # everything dev-clean does, plus remove this repo's images and prune its buildx cache
just infisical-bootstrap    # one-time: drive Infisical first-run setup and fill INFISICAL_* in .env

# Checks
just check                  # umbrella: every check.yml step except its cargo test steps (see below)
just check-compile          # cargo check --all-targets
just check-clippy           # cargo clippy --all-targets -- -D warnings (same as check.yml)
just check-fmt              # cargo fmt --all --check
just check-docker           # build the OCI image's builder stage only (validation; NOT in `just check`)
just check-migrations       # fail if two migrations share a numeric prefix (PMS-198)
just check-migration-immutability # fail if a migration already on main is modified or deleted (DEV-395)
just check-pool-safety      # fail if a serving `.pool()` call lacks its `// SAFETY (PMS-285` note (PMS-692)
just check-mail-copy        # fail if a `Mailer` helper duplicates a seeded template's copy (PMS-700)
just check-rate-limit-helper # fail if a 429 response is built outside the shared builder (PMS-773)
just check-runner-labels    # fail if a CI job requests the wrong runner label (PMS-719)
just check-oci-cache        # fail if the OCI build leaves the type=gha runner cache (PMS-720)
just check-oci-publish-tags # fail if the publish tags drift from oci-build/get-tags.nu (PMS-733)
just check-workspace-deps   # fail if [workspace.dependencies] and its members disagree (PMS-785)
just check-unused-deps      # cargo-machete: fail on a dependency with no call site (PMS-780)
just check-env-example      # fail if a var the code reads is missing from .env.example or compose.dev.yml (PMS-836)
just check-doc-recipes      # fail if README.md or docs/quickstart.md names a recipe the justfile lacks (PMS-843)
just check-config-doc-paths # fail if a docs/ path in .env.example, compose.dev.yml or the justfile is missing (PMS-855)

# Format, test, build
just fmt                    # cargo fmt --all
just test                   # cargo test
just test-integration       # Postgres-backed tests/*.rs suite in the dev `server` container (mirrors CI integration.yml)
just verify-demo            # the demo-critical subset of the integration suite (seed_demo + data_transfer)
just test-e2e [args]        # Playwright E2E suite against staging or $E2E_BASE_URL (args go to `playwright test`)
just build                  # cargo build --release --bins
just build-docker           # build the production OCI image (oci-build/Dockerfile)

# Database
just migrate-run            # apply pending migrations against $DATABASE_URL
just migrate-create <name>  # create a new migration file

# Release
just create-release <bump>  # bump version (major|minor|hotfix), push release branch, print PR link
```

`just check` plus `just pre-commit` together cover every step of
`.forgejo/workflows/check.yml`; neither covers it alone.
[`docs/dev-docs/local-vs-ci-checks.md`](docs/dev-docs/local-vs-ci-checks.md)
maps the workflow onto the recipes step by step and states why `check-docker`,
`test-integration`, `verify-demo` and `test-e2e` stay outside the umbrella.

## First-run admin bootstrap

When both `ADMIN_EMAIL` and `ADMIN_PASSWORD` are set in `.env` AND the `users` table is empty, the server creates a `super_admin` user under the default tenant on startup. The account is marked `active` and `email_verified_at = NOW()`, so you can log in immediately without going through the signup or email-verification flow.

Once any user exists in the database, the env vars are ignored on subsequent startups. It is safe to leave `ADMIN_EMAIL` / `ADMIN_PASSWORD` in `.env` indefinitely.

The generated `.env` ships `ADMIN_EMAIL` / `ADMIN_PASSWORD` empty (they are blank in `.env.example`), so no admin is bootstrapped until you set them. To create a dev admin, set both and restart:

```nu
# Set in .env (gitignored), then restart the stack.
"ADMIN_EMAIL=you@example.com\nADMIN_PASSWORD=at-least-12-characters\n" | save --append .env
just down
just dev
```

DEV ONLY. Production deployments should provision the first admin through a real workflow (signup form, IaC, manual SQL) rather than environment variables.

## Infisical bootstrap

Infisical runs behind the `infisical` compose profile, so start it with `just dev-infisical` first. The first-run setup is then driven by `mokosh-bootstrap` (invoked via `just infisical-bootstrap`). The recipe loads `.env.infisical` (gitignored) before invoking the binary, so the admin password never lands in shell history.

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
just down
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
| `oci-build/Dockerfile` | Production image. Multi-stage Alpine build (musl + lld), release binaries, non-root `appuser`, healthcheck on `/api/v1/health`. Built and published by the Forgejo workflow in `.forgejo/workflows/build-oci-image.yml`. |

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
compose.dev.yml  Dev stack: mokosh-server + Postgres + mailpit, routed by the shared Traefik
                 (Infisical + its Postgres + Valkey sit behind the `infisical` profile).
.env.example     Committed template; `just dev` generates `.env` from it with fresh per-clone secrets.
justfile         Task runner.
.forgejo/        CI workflows (Forgejo).
.devcontainer/   VS Code devcontainer config.
```

## Releases

`just create-release <major|minor|hotfix>` bumps the version in `Cargo.toml`, creates and pushes a `release/v<X.Y.Z>` branch, and prints the PR URL. After the PR merges, the `create-release` workflow tags and publishes the release automatically.

## License

Proprietary. See `Cargo.toml`.

## Development happens on Forgejo

The development home for this repository is <https://dev.a8n.run/psa-systems/mokosh-server>. The [GitHub](https://github.com/psa-systems/mokosh-server) and [Codeberg](https://codeberg.org/psa-systems/mokosh-server) copies are read-only mirrors that exist for visibility only: issues and pull requests are disabled there, and no community support runs on the mirrors. File issues and open pull requests on Forgejo.
