# Quickstart - mokosh-server (dev)

Get a fresh clone running on a Linux host in about 20 minutes (cold first build, mostly waiting on cargo).

The repo's README mentions `.env.dev` but that file is gitignored and missing from a fresh clone. This doc covers the seeding step plus everything around it.

## 1. Prerequisites

You need:

- Linux host with Docker Engine running and your user in the `docker` group.
- `just` (task runner).
- Nushell `0.112.2` (several `just` recipes are written in nu).
- Rust stable (`cargo`, `rustc`).
- `sqlx-cli` for host-side migrations.
- `docker compose` v2 (the `compose` subcommand, not legacy `docker-compose`).

Check what is present:

```nu
which just nu cargo sqlx
docker compose version
groups | str contains 'docker'
```

If anything is missing, install only that piece (steps 2 and 3 below cover the user-level installs that need no sudo).

## 2. User-level installs (no sudo)

```nu
# docker compose v2 plugin
mkdir --parents ~/.docker/cli-plugins
^curl --silent --show-error --location --fail --output ~/.docker/cli-plugins/docker-compose https://github.com/docker/compose/releases/download/v2.40.0/docker-compose-linux-x86_64
chmod +x ~/.docker/cli-plugins/docker-compose
docker compose version

# Rust toolchain (minimal profile, lands in ~/.cargo)
^curl --proto '=https' --tlsv1.2 --silent --show-error --fail https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal --no-modify-path
^source $"($env.HOME)/.cargo/env.nu"
cargo --version

# sqlx-cli (Postgres + rustls only)
cargo install sqlx-cli --version ^0.8 --no-default-features --features postgres,rustls
sqlx --version
```

If you need `just` or Nushell themselves and you do have sudo, install via your distro package manager (openSUSE: `sudo zypper install just nushell`). Otherwise grab prebuilt binaries from each project's releases page and drop them in `~/.local/bin/`.

## 3. Seed `.env.dev`

`.env.dev` is gitignored. `just dev` copies it to `.env` on first run, so the file has to exist before you boot. Create it from the template below, then never edit `.env` directly (it is regenerated from `.env.dev`).

```nu
cd ~/mokosh-server   # or wherever you cloned

let jwt_secret = (^openssl rand --hex 32 | str trim)
let app_key    = (^openssl rand --hex 32 | str trim)
let inf_root   = (^openssl rand --hex 16 | str trim)   # Infisical wants 16 bytes
let inf_auth   = (^openssl rand --hex 32 | str trim)

$"COMPOSE_FILE=compose.dev.yml

MOKOSH_PG_DB=mokosh
MOKOSH_PG_USER=postgres
MOKOSH_PG_PASSWORD=postgres
MOKOSH_PG_HOST_PORT=5433
DATABASE_URL=postgres://postgres:postgres@localhost:5433/mokosh
DATABASE_URL_IN_CONTAINER=postgres://postgres:postgres@postgres:5432/mokosh

HOST=0.0.0.0
MOKOSH_PORT=4301
PORT=4301
ENVIRONMENT=development
BASE_URL=http://localhost:4301

JWT_SECRET=($jwt_secret)
ENCRYPTION_KEY=($app_key)

GOOGLE_OAUTH_CLIENT_ID=dev-placeholder-client-id
GOOGLE_OAUTH_CLIENT_SECRET=dev-placeholder-client-secret
GOOGLE_OAUTH_REDIRECT_URI=http://localhost:4301/api/v1/auth/google/callback
CLIENT_ORIGIN=http://localhost:4301
OAUTH_SUPER_ADMIN_DOMAINS=niceguyit.biz

ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=devpassword12
RUN_MIGRATIONS=true

SMTP_HOST=mailpit
SMTP_PORT=1025
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM=Mokosh Dev <noreply@mokosh.localdev>
SMTP_TLS=none

INFISICAL_BASE_URL=http://localhost:28002
INFISICAL_SITE_URL=http://localhost:28002
INFISICAL_ENVIRONMENT=dev
INFISICAL_TELEMETRY_ENABLED=false
INFISICAL_PROJECT_ID=
INFISICAL_CLIENT_ID=
INFISICAL_CLIENT_SECRET=

INFISICAL_PG_DB=infisical
INFISICAL_PG_USER=infisical
INFISICAL_PG_PASSWORD=infisical
INFISICAL_DB_CONNECTION_URI=postgres://infisical:infisical@infisical-postgres:5432/infisical
INFISICAL_REDIS_URL=redis://valkey:6379
INFISICAL_ENCRYPTION_KEY=($inf_root)
INFISICAL_AUTH_SECRET=($inf_auth)

RUST_LOG=info,mokosh_server=debug
" | save .env.dev
```

Important detail: `INFISICAL_ENCRYPTION_KEY` is 16 bytes (32 hex chars). 32 bytes will crash Infisical at boot migration with `RangeError: Invalid key length`.

The Google OAuth placeholders let compose validate. `/api/v1/auth/google/*` will 500 at request time until you paste real credentials from the Google console. Legacy email/password auth works fine without them.

## 4. Boot the stack

```nu
just dev --detach
```

What `just dev` does:

1. Copies `.env.dev` to `.env` if `.env` is missing.
2. Detects your LAN IP from `sys net | where name =~ 'eth0|br0'` and writes `MOKOSH_HOST_BIND_IP` plus `USER` to `.env`.
3. Runs `docker compose --file compose.dev.yml up --detach`. Cold first build compiles every Rust crate inside the `server` container (5 to 15 min). Subsequent boots reuse the `dev-mokosh-server-target-long` volume and are about 30 seconds.

Watch the server compile:

```nu
docker logs --follow dev-mokosh-server-long
# Ctrl-C to detach. Look for: "Server listening on http://0.0.0.0:4301".
```

## 5. Bootstrap Infisical (one-time)

After step 4 finishes, the `infisical` service is healthy but empty. Bootstrap it once:

```nu
"INFISICAL_ADMIN_EMAIL=admin@example.com
INFISICAL_ADMIN_PASSWORD=devpassword12345
" | save .env.infisical

just infisical-bootstrap
```

This creates the admin user, project, machine identity, and writes `INFISICAL_PROJECT_ID`, `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET` into `.env`.

Restart so the server picks up the new credentials:

```nu
just dev-down
just dev --detach
```

## 6. Verify

```nu
let bind_ip = (open .env | lines | parse '{k}={v}' | where k == MOKOSH_HOST_BIND_IP | get v.0)
let port    = 4302   # MOKOSH_API_HOST_PORT default; container 4301 maps to host 4302
let base    = $"http://($bind_ip):($port)"

http get $"($base)/api/v1/health"     # expect: OK
http get $"($base)/api/v1/version"    # expect: JSON with name, version, git_describe

# Log in as the bootstrap admin
http post --content-type application/json $"($base)/api/v1/auth/login" {
  email: "admin@example.com",
  password: "devpassword12"
}
# expect: access_token + refresh_token + user.role = "super_admin"
```

Service URLs:

| Service     | URL                                     | Notes |
| ----------- | --------------------------------------- | ----- |
| Mokosh API  | `http://<LAN-IP>:4302`                  | container `4301` -> host `4302` |
| Infisical   | `http://localhost:28002`                | admin: `admin@example.com` / `devpassword12345` |
| Mailpit     | `http://localhost:8025`                 | catches all outbound dev email |
| Postgres    | `localhost:5433` / `postgres:5432`      | db `mokosh`, user/pass `postgres` |

## 7. Routine commands

```nu
just dev --detach            # boot or rebuild
just dev-down                # stop, keep volumes
just down                    # stop both LAN-IP and SSO stacks, remove orphans
just dev-clean               # stop + drop volumes + remove .env (keeps .env.dev, .env.infisical)

just check                   # cargo check + clippy + fmt --check (run before pushing)
just test                    # cargo test workspace-wide
just fmt                     # cargo fmt --all
just migrate-run             # sqlx migrate run against $DATABASE_URL (host)
just migrate-create <name>   # new migration file

docker compose --file compose.dev.yml logs --follow server
docker compose --file compose.dev.yml ps
```

Run a single test: `cargo test --package <crate> <test_path>`, e.g. `cargo test --package mokosh-auth-crypto totp::tests::generates_valid_code`.

## 8. Troubleshooting

**`infisical-long Error: dependency failed to start`**
Boot migration crashed on `Invalid key length`. `INFISICAL_ENCRYPTION_KEY` must be 32 hex chars (16 bytes). Edit `.env.dev`, then:
```nu
docker compose --file compose.dev.yml down --volumes
rm .env
just dev --detach
```

**`USER missing - run via just dev`**
You ran `docker compose` directly instead of through `just dev`. The justfile writes `USER` into `.env` each run. Use `just dev` (or export `USER` manually).

**`MOKOSH_HOST_BIND_IP` resolves to nothing / wrong interface**
The recipe uses `sys net | where name =~ 'eth0|br0'`. If your interface is different, edit `.env` after `just dev` writes it:
```nu
open .env | lines | where not ($it | str starts-with 'MOKOSH_HOST_BIND_IP=') | append 'MOKOSH_HOST_BIND_IP=127.0.0.1' | str join "\n" | save --force .env
just dev-down
just dev --detach
```

**Port collisions on shared hosts**
Defaults: API `4302`, Postgres `5433`, Infisical UI `28002`, Mailpit UI `8025`, SMTP `1025`. Change `MOKOSH_PORT` / `MOKOSH_PG_HOST_PORT` in `.env.dev` (Infisical/Mailpit ports are pinned in `compose.dev.yml`).

**`Failed to read GOOGLE_OAUTH_* env`**
Server panics at startup if the three `GOOGLE_OAUTH_*` vars are empty. Placeholder strings are fine for dev; only real Google credentials make the OAuth routes functional.

**Server compile takes forever**
First build hits every crate in the workspace cold. Watch `docker logs --follow dev-mokosh-server-long`. Subsequent boots reuse `dev-mokosh-server-target-long` and are about 30 seconds.

**Reset everything**
```nu
just dev-clean        # stop + drop app volumes + remove .env
# Then re-run from step 5 (bootstrap Infisical) because the project rows
# in infisical-postgres are gone too.
```

## 9. What is real vs. stub

Only `auth`, `contacts`, `tenants`, `tickets` modules have real handlers. The other 14 modules return HTTP 501. The database schema is far ahead of the handler layer. Before adding a feature module, read [`codebase-state.md`](codebase-state.md) for per-module status and known defects (`F1..F14`).

SSO / OIDC IdP (the `crates/mokosh-auth*` subsystem) requires `MOKOSH_AUTH_*` env vars. They are intentionally absent from `.env.dev`; the server logs `SSO subsystem not mounted` and runs with legacy email/password auth only. The separate `just dev-sso` flow (Traefik-routed at `*.a8n.run`) is for testing client OIDC integration and is not part of quickstart.
