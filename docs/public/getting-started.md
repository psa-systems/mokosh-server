# Getting started

This page is the shortest path from "nothing" to "first admin signed in and clicking around". It covers a production-style deployment running the published container image behind a reverse proxy, with Bunyip as the identity provider. For a developer-focused local stack with hot reload see the quickstart under `docs/` in the source repository.

## What you need

- Linux host with Docker Engine and docker compose v2.
- A PostgreSQL 15 or newer instance the server can reach. The compose stack ships one; a managed Postgres works too.
- A Bunyip instance you control, with an OIDC client registered for this Mokosh deployment. Bunyip is the sole identity provider: Mokosh does not maintain its own password store beyond the local development seed.
- A hostname you can point at the HTTP service, with TLS terminated at a reverse proxy (Traefik, Caddy, nginx). The server itself speaks plain HTTP.
- A working SMTP relay if you want transactional mail (invites, password reset, invoice delivery). The server runs without one; outbound mail then goes to the log.

## 1. Pull and configure

Pull the image and copy the sample environment:

```nu
docker pull dev.a8n.run/psa-systems-private/mokosh-server:latest
curl --output .env https://dev.a8n.run/psa-systems/mokosh-server/raw/main/.env.example
```

Open `.env` and fill the required variables. The smallest viable set is:

- `DATABASE_URL`: Postgres connection string. The server runs its own migrations on start.
- `ENCRYPTION_KEY`: 32 random bytes, base64 encoded. Protects every secret stored in the database.
- `CORS_ORIGIN`: the public URL of the SPA that talks to this API.
- `OIDC_ISSUER`: the Bunyip issuer URL.
- `OIDC_AUDIENCE`: the OIDC audience your Bunyip client is registered under.
- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_FROM`: SMTP relay. Omit the whole block to keep mail in the log.

[Configuration](configuration.md) lists every variable grouped by subsystem.

## 2. Boot

```nu
docker compose up --detach
docker compose logs --follow server
```

The server runs its embedded migrations on startup. The first boot may take a minute while the schema is created. You should see a line reading `Listening on 0.0.0.0:3000` (or the port you set).

Point your reverse proxy at the server's port and verify:

```nu
curl --header 'Accept: application/json' https://api.mokosh.example.com/api/v1/health
```

It answers `{"status":"ok"}` to anyone. A super admin sees build metadata as well.

## 3. First sign in

The first administrator signs in through Bunyip. There is no self-service sign-up on the Mokosh side.

1. In Bunyip, provision the account that will be the first Mokosh operator. Give it the Mokosh platform-admin role on the directory object for this deployment.
2. Open the SPA at your configured URL and click sign in. Bunyip authenticates the user and redirects back with an access token.
3. Mokosh provisions a personal tenant for that user on first sign in and grants them tenant admin.
4. Separately, the deployment-wide operator surface lives behind `/platform/login`. Provision at least one `platform_admins` row so operator-only settings (SMTP relay, product name, application-tier secrets) can be reached. Local dev can bootstrap this with `ADMIN_EMAIL` + `ADMIN_PASSWORD` at startup; production should provision it through a real workflow and remove the seed variables.

See [first-run onboarding](operations/first-run-onboarding.md) for the exact first-admin flow, including the case where SMTP is not yet configured.

## 4. Invite the team

Signed in as the first tenant admin, create your real tenant (or rename the personal one) and invite team members. An invite sent to address X is only honored by a Bunyip login with a verified X.

Each role maps to what the user can do:

- Admin: everything inside the tenant.
- Manager: read everything, manage tickets and time, no billing writes.
- Technician: ticket work, time logging, assigned contacts.
- Client: contact plane only; reaches the customer portal.

[Tenancy](tenancy.md) covers the role model in detail.

## 5. Point an SPA at it

Mokosh Server is the API. The customer-facing and staff-facing SPAs live in `mokosh-apps`; the staging demo at `msp.a8n.systems` serves that image against a shared Mokosh backend. A production deployment runs the same SPA image with its `API_BASE_URL` set to your Mokosh host, behind the same reverse proxy.

## Next steps

- [Configure integrations](integrations.md): Stripe for checkout, PayPal for payments, Xero or QuickBooks for delegated invoicing, Google or Microsoft 365 for contact sync, Infisical for secrets.
- [Set up billing](billing.md): tax rate, net terms, templates, product catalog.
- [Plan backups](operations/backups.md): database, uploaded documents, and (if in use) Infisical state.
