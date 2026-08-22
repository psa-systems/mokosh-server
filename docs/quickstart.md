# Quickstart - mokosh-server (dev)

Get a fresh clone running on a Linux host in about 20 minutes (cold first build, mostly waiting on cargo).

`just dev` generates the gitignored `.env` from the committed `.env.example` on first run (it does not copy a hand-authored file), minting fresh random secrets. This doc covers that step plus everything around it.

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

## 3. Generate `.env`

You do not hand-author any env file. `just dev` runs the `ensure-env` recipe first, which generates `.env` from the committed `.env.example` when `.env` is missing: it copies the template, then mints fresh random values for every self-owned secret (`MOKOSH_PG_PASSWORD`, `MOKOSH_MIGRATOR_PASSWORD`, `MOKOSH_APP_PASSWORD`, `JWT_SECRET`, `ENCRYPTION_KEY`, `INFISICAL_PG_PASSWORD`, `INFISICAL_ENCRYPTION_KEY` at the correct 16-byte length, `INFISICAL_AUTH_SECRET`) and rebuilds the `postgres://` URL lines from those same generated passwords. `just dev` then stamps `MOKOSH_HOST_BIND_IP` and `USER` on each run (step 4). An existing `.env` is left untouched, so this runs once per clone; edit `.env` directly for anything you want to change after that.

Third-party credentials stay as placeholders in `.env.example` and are carried into `.env` unchanged, because they cannot be generated:

- `INFISICAL_CLIENT_ID` / `INFISICAL_CLIENT_SECRET` / `INFISICAL_PROJECT_ID` are empty until the one-time Infisical bootstrap (step 5) fills them in `.env`.

You do not need to touch anything before booting: `just dev` in step 4 generates a working `.env` on its own.

## 4. Boot the stack

```nu
just dev --detach
```

What `just dev` does:

1. Generates `.env` from `.env.example` (via the `ensure-env` recipe) if `.env` is missing, minting fresh self-owned secrets.
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
just down
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
just down                    # stop, keep volumes
just dev-clean               # stop + drop volumes + remove .env (leaves .env.infisical; next `just dev` regenerates .env)

just check                   # cargo check + clippy + fmt --check + repo guards (run before pushing)
just test                    # cargo test workspace-wide
just fmt                     # cargo fmt --all
just migrate-run             # sqlx migrate run against $DATABASE_URL (host)
just migrate-create <name>   # new migration file

docker compose --file compose.dev.yml logs --follow server
docker compose --file compose.dev.yml ps
```

Run a single test: `cargo test -p <crate> <test_path>`, e.g. `cargo test -p mokosh-server utils::totp::tests::rfc6238_vector`.

## 8. Troubleshooting

**`infisical-long Error: dependency failed to start`**
Boot migration crashed on `Invalid key length`. `INFISICAL_ENCRYPTION_KEY` must be 32 hex chars (16 bytes); `ensure-env` generates it at that length, so this only happens if `.env` was hand-edited. Remove `.env` so the next `just dev` regenerates it:
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
just down
just dev --detach
```

**Port collisions on shared hosts**
Defaults: API `4302`, Postgres `5433`, Infisical UI `28002`, Mailpit UI `8025`, SMTP `1025`. Change `MOKOSH_PORT` / `MOKOSH_PG_HOST_PORT` in `.env` after `just dev` generates it (Infisical/Mailpit ports are pinned in `compose.dev.yml`).

**Server compile takes forever**
First build hits every crate in the workspace cold. Watch `docker logs --follow dev-mokosh-server-long`. Subsequent boots reuse `dev-mokosh-server-target-long` and are about 30 seconds.

**Reset everything**
```nu
just dev-clean        # stop + drop app volumes + remove .env
# Then re-run from step 5 (bootstrap Infisical) because the project rows
# in infisical-postgres are gone too.
```

## 9. What is real vs. stub

Most of the ~30 route groups have real handlers (`auth`, `contacts`, `tenants`, `tickets`, `billing`, `projects`, `calendar`, `contracts`, `quotes`, `assets`, `rmm`, `sla`, and more). The only endpoint still returning HTTP 501 is the PDF format of the report-export route (CSV is implemented). The database schema is still ahead of the handler layer in places. Before adding a feature module, read [`codebase-state.md`](dev-docs/codebase-state.md) for per-module status, open TODOs (`F1..F14`), and known shallow-DTO traps.

Authentication (PMS-295): mokosh no longer runs its own OIDC IdP. The `crates/mokosh-auth*` subsystem and its `MOKOSH_AUTH_*` env vars were removed; bunyip is the sole OP. Two independent paths run in parallel: the bunyip-as-OP Resource-Server path (mokosh verifies bunyip-issued Bearer tokens against bunyip's JWKS, configured by `OIDC_ISSUER` / `OIDC_AUDIENCE`), which the SPA and E2E suite use, and the legacy HS256 email/password cookie auth used by the original PSA endpoints. A bare dev `.env` with no OIDC vars still boots and serves the legacy path. As of PMS-511 `just dev` is the single Traefik-routed stack (per-developer `https://${USER}-mokosh-api.a8n.run`); the former separate `dev-sso` overlay recipe is gone.
