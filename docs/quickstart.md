# Quickstart - mokosh-server (dev)

Get a fresh clone running on a Linux host in about 20 minutes (cold first build, mostly waiting on cargo).

`just dev` generates the gitignored `.env` from the committed `.env.example` on first run (it does not copy a hand-authored file), minting fresh random secrets. Those secrets are different in every clone, so this document never quotes a password: it tells you which key to read out of `.env`. The API is reached through the shared Traefik at `https://<your-username>-mokosh-api.a8n.run`; the `server` container publishes no host port at all.

## 1. Prerequisites

You need:

- Linux host with Docker Engine running and your user in the `docker` group.
- `just` (task runner).
- Nushell `0.112.2` (several `just` recipes are written in nu, and every snippet below is nu).
- Rust stable (`cargo`, `rustc`). The server itself compiles inside the `server` container, but the host toolchain runs `just check`, `just infisical-bootstrap` and any `cargo` command you run directly.
- `sqlx-cli`, only for host-side `just migrate-run`. The server applies migrations itself on start (`RUN_MIGRATIONS=true`).
- `docker compose` v2 (the `compose` subcommand, not legacy `docker-compose`).
- The shared Traefik ingress network `network-traefik-public`. `compose.dev.yml` attaches to it as an `external` network, so `just dev` fails immediately if it does not exist.

Check what is present:

```nu
which just nu cargo sqlx
docker compose version
groups | str contains 'docker'
docker network ls --format "{{.Name}}" | lines | any {|n| $n == "network-traefik-public" }
```

The last two must print `true`. If anything is missing, install only that piece (steps 2 and 3 below cover the user-level installs that need no sudo). The Traefik network is owned by the shared Traefik stack, not by this repo: ask whoever runs the dev host if it is absent.

## 2. User-level installs (no sudo)

```nu
# docker compose v2 plugin (nu's `mkdir` creates parent directories already)
mkdir ~/.docker/cli-plugins
^curl --silent --show-error --location --fail --output ~/.docker/cli-plugins/docker-compose https://github.com/docker/compose/releases/download/v2.40.0/docker-compose-linux-x86_64
chmod +x ~/.docker/cli-plugins/docker-compose
docker compose version

# Rust toolchain (minimal profile, lands in ~/.cargo)
^curl --proto '=https' --tlsv1.2 --silent --show-error --fail https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal --no-modify-path
# rustup's env script is bash; put its bin dir on PATH for this nu session
# instead, and add the same line to your nu config to make it permanent.
$env.PATH = ($env.PATH | prepend $"($env.HOME)/.cargo/bin")
cargo --version

# sqlx-cli (Postgres + rustls only)
cargo install sqlx-cli --version '^0.8' --no-default-features --features postgres,rustls
sqlx --version
```

If you need `just` or Nushell themselves and you do have sudo, install via your distro package manager (openSUSE: `sudo zypper install just nushell`). Otherwise grab prebuilt binaries from each project's releases page and drop them in `~/.local/bin/`.

## 3. Generate `.env`

You do not hand-author any env file. `just dev` runs the `ensure-env` recipe first, which generates `.env` from the committed `.env.example` when `.env` is missing: it copies the template, then mints fresh random values for every self-owned secret (`MOKOSH_PG_PASSWORD`, `MOKOSH_MIGRATOR_PASSWORD`, `MOKOSH_APP_PASSWORD`, `JWT_SECRET`, `ENCRYPTION_KEY`, `INFISICAL_PG_PASSWORD`, `INFISICAL_ENCRYPTION_KEY` at the correct 16-byte length, `INFISICAL_AUTH_SECRET`) and rebuilds the `postgres://` URL lines from those same generated passwords. `just dev` then stamps `MOKOSH_HOST_BIND_IP` and `USER` on each run (step 4). An existing `.env` is left untouched, so this runs once per clone; edit `.env` directly for anything you want to change after that.

Because the values are generated per clone, nothing outside `.env` can tell you what they are. Read them from the file when you need one:

```nu
# The whole host-side connection string for the app database.
open .env | lines | parse '{k}={v}' | where k == DATABASE_URL | get v.0

# Or just the superuser password the `postgres` service was initialised with.
open .env | lines | parse '{k}={v}' | where k == MOKOSH_PG_PASSWORD | get v.0
```

Third-party credentials stay as placeholders in `.env.example` and are carried into `.env` unchanged, because they cannot be generated:

- `INFISICAL_CLIENT_ID` / `INFISICAL_CLIENT_SECRET` / `INFISICAL_PROJECT_ID` are empty until the one-time Infisical bootstrap (step 7) fills them in `.env`.
- `ADMIN_EMAIL` / `ADMIN_PASSWORD` are empty, so no admin account is created until you set them (step 6).

You do not need to touch anything before booting: `just dev` in step 4 generates a working `.env` on its own.

## 4. Boot the stack

```nu
just dev --detach
```

What `just dev` does:

1. Generates `.env` from `.env.example` (via the `ensure-env` recipe) if `.env` is missing, minting fresh self-owned secrets.
2. Detects your private LAN IP from `sys net | where name =~ 'eth0|br0'` and writes `MOKOSH_HOST_BIND_IP` plus `USER` to `.env`. `USER` is the one that matters: it names your containers, volumes, network and your `${USER}-mokosh-api.a8n.run` route. Nothing publishes a port on `MOKOSH_HOST_BIND_IP` any more (PMS-496).
3. Runs `docker compose --file compose.dev.yml up --detach`, starting `server`, `postgres` and `mailpit`. Infisical is behind a compose profile and does NOT start here (step 7). Cold first build compiles every Rust crate inside the `server` container (5 to 15 min). Subsequent boots reuse the `dev-mokosh-server-target-${USER}` volume and are about 30 seconds.

Watch the server compile and boot:

```nu
docker compose --file compose.dev.yml logs --follow server
# Ctrl-C to detach. The boot line is: "Server listening on http://0.0.0.0:8080".
```

`8080` is the in-container port (`MOKOSH_PORT`). It is not published to the host: Traefik reaches it over the `network-traefik-public` network and terminates TLS for `https://${USER}-mokosh-api.a8n.run`.

## 5. Verify

Check readiness over HTTP rather than reading the log. `/api/v1/health` is the liveness probe (it only proves the process is up); `/api/v1/ready` also pings Postgres, so it is the one that proves the stack works end to end.

```nu
let api = $"https://(^whoami | str trim)-mokosh-api.a8n.run"

http get $"($api)/api/v1/health"
# expect: OK

http get $"($api)/api/v1/ready"
# expect: {status: ready, checks: {db: ok, infisical: skipped}}
# `infisical: skipped` is correct on a plain `just dev` - see step 7.

http get $"($api)/api/v1/version"
# expect: a record with name, version, git_describe, git_hash, build_date
```

If `/api/v1/ready` answers `503` with `checks.db` carrying an error string, the server booted but cannot reach Postgres; see Troubleshooting. If the request fails at TLS or returns Traefik's 404, the route is not up: confirm the container is running (`docker compose --file compose.dev.yml ps`) and that `USER` in `.env` matches your username.

## 6. Create a dev admin (optional)

`.env` ships `ADMIN_EMAIL` / `ADMIN_PASSWORD` empty, so a fresh stack has no user accounts and nothing to log in as. Set both and restart; the server creates one `super_admin` under the default tenant on the next boot, and only while the `users` table is still empty.

```nu
"ADMIN_EMAIL=you@example.com\nADMIN_PASSWORD=at-least-12-characters\n" | save --append .env
just down
just dev --detach
```

Then log in against your own values:

```nu
let api = $"https://(^whoami | str trim)-mokosh-api.a8n.run"
http post --content-type application/json $"($api)/api/v1/auth/login" {
  email: "you@example.com",
  password: "at-least-12-characters"
}
# expect: access_token, refresh_token, expires_at, mfa_required: false,
# and user.role = "super_admin"
```

DEV ONLY. Once any user exists these two variables are ignored, so it is safe to leave them in `.env`.

## 7. Bootstrap Infisical (optional, one-time)

Infisical is opt-in: it sits behind the `infisical` compose profile and `just dev` does not start it. Without it the server runs normally and the readiness probe reports `infisical: skipped`, because `INFISICAL_ADDRESS` is empty (PMS-707).

```nu
just dev-infisical --detach
```

That also writes `MOKOSH_SERVER_INFISICAL_ADDRESS=http://infisical:8080` into `.env`, which compose hands to the `server` container as `INFISICAL_ADDRESS`. Wait for the container to report healthy, then bootstrap it once:

```nu
"INFISICAL_ADMIN_EMAIL=admin@example.com
INFISICAL_ADMIN_PASSWORD=at-least-12-characters
" | save .env.infisical

just infisical-bootstrap
```

`.env.infisical` is gitignored, and the recipe loads it before invoking the binary so the password never lands in shell history. Bootstrap creates the admin user, project and machine identity, and writes `INFISICAL_PROJECT_ID`, `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET` into `.env`:

```nu
open .env | lines | where ($it | str starts-with 'INFISICAL_')
```

Restart so the server picks up the new credentials:

```nu
just down
just dev --detach
```

`/api/v1/ready` now reports `infisical: ok` instead of `skipped`.

## 8. Where things live

| Service | Reached at | Notes |
| --- | --- | --- |
| Mokosh API | `https://<your-username>-mokosh-api.a8n.run` | Traefik is the sole ingress and terminates TLS; the container listens on `MOKOSH_PORT` (`8080`) and publishes no host port. |
| Mailpit | `http://localhost:8025` | Catches all outbound dev email. Loopback only. |
| Postgres | `127.0.0.1:5433` (`postgres:5432` in-network) | Database `mokosh`, user `postgres`. The password is generated per clone: read `MOKOSH_PG_PASSWORD` (or the whole `DATABASE_URL`) from `.env`. Loopback only. |
| Infisical | `http://localhost:28002` | Only when started with `just dev-infisical`. Admin credentials are the ones you put in `.env.infisical`. Loopback only. |

Everything except the API publishes on `127.0.0.1` alone, so host-side tooling reaches it and the LAN cannot (PMS-496).

## 9. Routine commands

```nu
just dev --detach            # boot or rebuild
just down                    # stop, keep volumes
just dev-clean               # stop + drop this repo's volumes + target/ + .env (leaves .env.infisical; next `just dev` regenerates .env)
just dev-clean-all           # everything dev-clean does, plus this repo's images and its buildx cache

just check                   # every check.yml step except its cargo test steps (run before pushing)
just pre-commit              # the cargo test steps `just check` leaves out, plus fmt/clippy/compile
just test                    # cargo test workspace-wide
just test-integration        # the Postgres-backed tests/*.rs suite
just fmt                     # cargo fmt --all
just migrate-run             # sqlx migrate run against $DATABASE_URL (host)
just migrate-create <name>   # new migration file

docker compose --file compose.dev.yml logs --follow server
docker compose --file compose.dev.yml ps
```

Run a single test: `cargo test -p <crate> <test_path>`, e.g. `cargo test -p mokosh-server utils::totp::tests::rfc6238_vector`.

## 10. Troubleshooting

**`network network-traefik-public declared as external, but could not be found`**
The shared Traefik network is missing, and `just dev` cannot create it (it belongs to the Traefik stack, not to this repo). Start the shared Traefik stack, or ask the owner of the dev host to.

**`USER missing - run via just dev`**
You ran `docker compose` directly instead of through `just dev`. The justfile writes `USER` into `.env` on each run. Use `just dev` (or export `USER` manually before the compose call).

**`https://<your-username>-mokosh-api.a8n.run` returns a certificate error or a Traefik 404**
Nothing is routing to your container. Check it is running with `docker compose --file compose.dev.yml ps`, and that the `USER` line in `.env` matches the username in the hostname you are requesting: the router name, the certificate and the route are all built from it.

**`/api/v1/ready` returns 503 with a `checks.db` error**
The server is up but cannot reach Postgres. Usually the `postgres` container is still initialising (`docker compose --file compose.dev.yml ps` shows its health), or `.env` was hand-edited so the generated passwords no longer match the ones the database was initialised with. The passwords are only applied at first `initdb`: if they have diverged, `just dev-clean` and boot again.

**`infisical Error: dependency failed to start`**
Boot migration crashed on `Invalid key length`. `INFISICAL_ENCRYPTION_KEY` must be 32 hex chars (16 bytes); `ensure-env` generates it at that length, so this only happens if `.env` was hand-edited. Wipe the generated state so the next boot mints a correct key and Infisical initialises against it. `just dev-clean` also drops the build-cache volume, so the next `just dev` recompiles from cold:
```nu
just dev-clean
just dev --detach
just dev-infisical --detach
```

**Port collisions on shared hosts**
The API needs no host port, so it cannot collide. The rest publish on loopback: Postgres `5433`, Infisical UI `28002`, Mailpit UI `8025` and SMTP `1025`. Change `MOKOSH_PG_HOST_PORT` in `.env` after `just dev` generates it; the Infisical and Mailpit ports are pinned in `compose.dev.yml`.

**Server compile takes forever**
First build hits every crate in the workspace cold. Watch `docker compose --file compose.dev.yml logs --follow server`. Subsequent boots reuse the `dev-mokosh-server-target-${USER}` volume and are about 30 seconds.

**Reset everything**
```nu
just dev-clean        # stop + drop this repo's volumes + target/ + .env
# Then re-run from step 4. If you had bootstrapped Infisical, redo step 7 too:
# the project rows in its Postgres are gone with the volume.
```

## 11. What is real vs. stub

Most of the ~30 route groups have real handlers (`auth`, `contacts`, `tenants`, `tickets`, `billing`, `projects`, `calendar`, `contracts`, `quotes`, `assets`, `rmm`, `sla`, and more). The report-export route implements CSV only and rejects every other `format`, `pdf` included, with 400 and not 501: `format` is an enumerated query parameter, so a value outside the implemented set is an out-of-range request rather than a server-side gap (PMS-854; adding PDF is tracked in PMS-876). The database schema is still ahead of the handler layer in places. Before adding a feature module, read the "Routing model" section of [`CLAUDE.md`](../CLAUDE.md) for what is mounted today and what authenticates it; [`codebase-state.md`](dev-docs/codebase-state.md) is a frozen 2026-05-06 snapshot (PMS-849) that is still worth reading for the `F1..F14` fix ids, the numbered cross-cutting issues and the shallow-DTO traps, but every status claim in it is from that date.

Authentication (PMS-295): mokosh no longer runs its own OIDC IdP. That subsystem's workspace crates and its `MOKOSH_AUTH_*` env vars were removed; bunyip is the sole OP. Two independent paths run in parallel: the bunyip-as-OP Resource-Server path (mokosh verifies bunyip-issued Bearer tokens against bunyip's JWKS, configured by `OIDC_ISSUER` / `OIDC_AUDIENCE`), which the SPA and E2E suite use, and the legacy HS256 email/password cookie auth used by the original PSA endpoints. A bare dev `.env` with no OIDC vars still boots and serves the legacy path. As of PMS-511 `just dev` is the single Traefik-routed stack (per-developer `https://${USER}-mokosh-api.a8n.run`); the former separate `dev-sso` overlay recipe is gone.
