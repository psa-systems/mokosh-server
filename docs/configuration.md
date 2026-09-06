# Configuration

Every value the server reads comes from the environment. `.env` is generated once per clone from the committed `.env.example` by the first `just dev`, minting fresh random values for every self-owned secret; see step 3 of [`quickstart.md`](quickstart.md) for what generation does and does not fill in.

`.env.example` is the complete inventory of keys, not this page: `just check-env-example` fails the build when a variable the code reads has no `.env.example` key or no `compose.dev.yml` line, and when `.env.example` declares a key nothing consumes. The table below is the annotated subset a developer touches most, with the one column that matters, where the value is actually set.

| Variable | Where set | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | `.env` for host-side tools, `compose.dev.yml` for the container | Host-side connection string against the bundled `postgres` service, used by `sqlx migrate` and anything else run on the host. The `server` container gets its own value, composed from the knobs below, connecting as `mokosh_migrator`. |
| `MOKOSH_PG_DB`, `MOKOSH_PG_USER`, `MOKOSH_PG_PASSWORD` | `.env` | Database name, and the superuser the `postgres` service is initialized with. The password is generated per clone on first `.env` creation. |
| `MOKOSH_MIGRATOR_PASSWORD`, `MOKOSH_APP_PASSWORD`, `MOKOSH_APP_DATABASE_URL`, `MOKOSH_ADMIN_DATABASE_URL` | `.env` | The split-role model that makes row-level security enforce at runtime. The server self-provisions two roles at startup: `mokosh_migrator` (`BYPASSRLS`, what `DATABASE_URL` connects as, for migrations, bootstrap and cross-tenant workers) and `mokosh_app` (`NOBYPASSRLS`, what `MOKOSH_APP_DATABASE_URL` connects as, for request serving). `MOKOSH_ADMIN_DATABASE_URL` is the privileged connection used once to create both roles, and is unused after that. With `MOKOSH_APP_DATABASE_URL` unset the server falls back to `DATABASE_URL`, single-role, and row-level security goes inert, so set it in any shared environment. Both passwords are generated per clone. |
| `MOKOSH_PG_HOST_PORT` | `.env` | Loopback port the `postgres` service is published on. Default `5433`. |
| `MOKOSH_PORT` | `.env` | Port the API server listens on inside its container, and the port Traefik forwards to. Default `8080`. |
| `MOKOSH_HOST_BIND_IP`, `USER` | written to `.env` by `just dev` | The host's private LAN IP and your username. `USER` names the per-developer containers, volumes, networks and the `${USER}-mokosh-api.a8n.run` route. Nothing publishes a port on `MOKOSH_HOST_BIND_IP`. |
| `MOKOSH_SERVER_INFISICAL_ADDRESS` | written to `.env` by `just dev-infisical` | In-network Infisical URL handed to the server as `INFISICAL_ADDRESS`. Empty on a plain `just dev`, which makes the readiness probe report Infisical as `skipped`. |
| `JWT_SECRET`, `ENCRYPTION_KEY` | `.env` | API server secrets, generated per clone on first `.env` creation; provision them explicitly for any non-local environment. `ENCRYPTION_KEY` is also the key the database secret backend encrypts under, so losing it loses every stored secret. |
| `SECRET_BACKEND` | `.env` | Where tenant-supplied secrets live: `database` (the default, AES-256-GCM ciphertext under `ENCRYPTION_KEY`) or `infisical`, which additionally requires `INFISICAL_ADDRESS`, `INFISICAL_PROJECT_ID`, `INFISICAL_CLIENT_ID` and `INFISICAL_CLIENT_SECRET`. An unrecognized value fails startup. |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | `.env` | Optional first-run admin bootstrap, dev only. Both empty in a generated `.env`; see [`first-run-onboarding.md`](first-run-onboarding.md). |
| `INFISICAL_URL` | `.env` | Host-side URL of the dev Infisical instance, read by the bootstrap CLI when `just infisical-bootstrap` runs it on the host. Default `http://localhost:28002`. Not the same key as `MOKOSH_SERVER_INFISICAL_ADDRESS` above, which is the in-network URL the server container gets. |
| `INFISICAL_*` | `.env` | Infisical server config (bootstrap inputs) and Universal Auth client credentials (filled by `mokosh-bootstrap`). |
| `ATTACHMENT_DIR` | `compose.dev.yml` | Upload root for ticket attachments, tenant logos and knowledge base images. Left commented out in `.env.example` on purpose: the dev stack points it at `/data/attachments` on the `dev-mokosh-attachments-${USER}` volume so an upload survives a rebuild, and setting it in `.env` would override that. Deployed environments want an absolute path on a mounted volume. |
| `RUN_MIGRATIONS` | `.env` | Whether the server applies pending migrations on start. Default `true` whether or not the variable is set. |
| `RUST_LOG` | `.env` | Tracing subscriber filter. |

`compose.dev.yml` references every value via `${VAR}` substitution and contains no hardcoded secrets. Required vars use `${VAR:?...}` so compose fails loudly with a helpful message when a value is missing.
