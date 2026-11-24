# Production deployment

`compose.prod.yml` at the repository root is the production stack. It mirrors `compose.dev.yml`: the same two services (`postgres` and `server`) and the same role-provisioning model. Only the environment-specific parts differ. Postgres always runs in the compose stack on a named volume (`mokosh-postgres-data`); managed Postgres is not supported by this file.

## Image

The `server` service runs the release image built from `oci-build/Dockerfile`, `dev.a8n.run/psa-systems-private/mokosh-server:${MOKOSH_SERVER_VERSION}`. Pin an exact release tag; there is no default. No source is mounted. Uploads live on the `mokosh-attachments` volume at `/app/attachments`, the directory the image creates for the runtime user. See [Release and deploy](release-and-deploy.md) for how a tag becomes a deployable image and the server-before-apps ordering.

## Secrets and variables

The file reads every value through `${VAR}` interpolation and fails fast on a missing required one. Nothing is generated: supply the variables from the production secret store, for example `infisical run --env prod -- docker compose --file compose.prod.yml up --detach`, or a SOPS-decrypted env file passed with `--env-file`. Application-tier secrets such as `SMTP_PASSWORD` also honour the `{NAME}_FILE` convention, so a compose `secrets:` entry can replace the plain variable; database URLs, `JWT_SECRET` and `ENCRYPTION_KEY` are plain variables. [Configuration](../configuration.md) lists every key.

Required: `MOKOSH_SERVER_VERSION`, `MOKOSH_PG_PASSWORD`, `MOKOSH_MIGRATOR_PASSWORD`, `MOKOSH_APP_PASSWORD`, `JWT_SECRET`, `ENCRYPTION_KEY`, `BASE_URL`, `MOKOSH_API_HOST`, `SMTP_HOST`, `SMTP_FROM`, `OIDC_ISSUER`, `OIDC_AUDIENCE`, `CLIENT_ORIGIN`, `SPA_BASE_URL`, `MOKOSH_DEPLOYMENT_MODE`.

## Mail and networking

`SMTP_HOST` points at the real relay (`SMTP_PORT` defaults to 587 with `starttls`); there is no mailpit. The stack publishes no host port. The shared Traefik on the external `network-traefik-public` network is the sole ingress and terminates TLS for `MOKOSH_API_HOST`. Postgres is reachable only as `postgres:5432` on the private network.

## Restart, health and limits

Both services use `restart: unless-stopped`, healthchecks, rotated JSON logs, and CPU and memory limits overridable with `MOKOSH_SERVER_CPUS`, `MOKOSH_SERVER_MEMORY`, `MOKOSH_PG_CPUS` and `MOKOSH_PG_MEMORY`. The server waits for a healthy Postgres.

## The admin database URL is one-time

On the first boot against an empty volume, set `MOKOSH_ADMIN_DATABASE_URL` to the Postgres superuser (`postgres://${MOKOSH_PG_USER}:${MOKOSH_PG_PASSWORD}@postgres:5432/${MOKOSH_PG_DB}`). The server uses it to create `mokosh_migrator` (BYPASSRLS, runs migrations) and `mokosh_app` (NOBYPASSRLS, serves requests, so row-level security applies), then closes that connection. The roles persist in the volume. After the first successful boot, unset `MOKOSH_ADMIN_DATABASE_URL`: the server skips provisioning whenever the migrator role already connects. Keep it set only if you need the server to reconcile a changed `MOKOSH_APP_PASSWORD`. See [Postgres security](postgres-security.md).

## Verify

```
docker compose --file compose.prod.yml config
docker compose --file compose.prod.yml ps
docker compose --file compose.prod.yml logs server
```

`ps` should show both services healthy, and the server log should show the roles provisioned on the first boot only.

## Backup and restore

See [Backups](backups.md) for the database dump, the uploads volume and the restore order, and [Upgrades](upgrades.md) for moving to a new image.
