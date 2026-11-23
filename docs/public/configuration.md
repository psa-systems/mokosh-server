# Configuration

Every variable the server reads at boot, grouped by subsystem. For an exhaustive variable-by-variable table with the release that added each key and the operator action a change needs, see the generated reference under `docs/configuration.md` in the source repository, which is rebuilt from the config registry.

## How configuration is resolved

The server reads configuration keys through a registry, not ad-hoc environment lookups. A declared key can be served from one of several providers chosen per deployment: the process environment, a file under a named directory, a row in the database, Bunyip's host-secrets endpoint, or Infisical. The backend is picked by `CONFIG_BACKEND` for ordinary configuration keys and by `SECRET_BACKEND` and `APP_SECRET_BACKEND` for the two secret tiers. See [the provider runbook](operations/provider-runbook.md) for the workflow to move a key between providers without downtime.

A missing required key refuses boot with a message naming the key.

## Database

- `DATABASE_URL`: Postgres connection string. Required.
- `DATABASE_MAX_CONNECTIONS`: pool size. Defaults to a modest value; raise it if you see acquisition timeouts under load.
- `RUN_MIGRATIONS`: when `true` the server runs its embedded migrations on startup. Leave on except where a release-time external migration step is doing it instead.

## HTTP service

- `HOST`, `PORT`: bind address. Defaults to `0.0.0.0:3000`.
- `CORS_ORIGIN`: comma-separated list of origins allowed to call the API with credentials. Required when a browser-side SPA talks to the API. Wildcard suffix entries of the form `https://*.msp.example.com` are accepted and match any subdomain under `msp.example.com`.
- `TRUSTED_PROXY_CIDRS`: CIDR ranges the server treats as trustworthy when reading forwarded headers.

## Encryption and session

- `ENCRYPTION_KEY`: 32 random bytes, base64 encoded. Used to encrypt stored secrets and TOTP seeds. Required. Rotate only with a planned data re-encryption step; a wrong value refuses boot.
- `JWT_SECRET`: HMAC secret for legacy session JWTs. Required while any user still signs in through the legacy path; see [authentication](authentication.md).

## Authentication (Bunyip)

- `OIDC_ISSUER`: the Bunyip issuer URL. Required to authenticate any user through Bunyip.
- `OIDC_AUDIENCE`: the OIDC audience the Bunyip client is registered under. Required.
- `OIDC_BACKCHANNEL_CLIENT_ID`: the client id Bunyip addresses back-channel logout tokens to. Unset refuses every logout token.
- `BUNYIP_API_BASE_URL`, `BUNYIP_DIRECTORY_CLIENT_ID`, `BUNYIP_DIRECTORY_CLIENT_SECRET`: set together to let Mokosh look invitees up in Bunyip's directory when sending a grant invitation; unset means standalone-mode shape with email-only invites.
- `BUNYIP_SECRETS_URL`, `BUNYIP_SECRETS_CLIENT_ID`, `BUNYIP_SECRETS_CLIENT_SECRET`: optional hosted-deployment path that reads the application-tier Google OAuth client from Bunyip rather than from this deployment's own provider. Set the three together or not at all.
- `BUNYIP_MAILER_URL`, `BUNYIP_MAILER_CLIENT_ID`, `BUNYIP_MAILER_CLIENT_SECRET`: Bunyip's mailer relay. Read only when `MAIL_PROVIDER=bunyip`.
- `LOGIN_APPROVAL_ENABLED`: when `true`, a sign-in from a country or device the account has not seen before is held until the owner approves it from an emailed link.
- `ALLOW_UNINVITED_BUNYIP_SIGNUP`: when `true`, a Bunyip sign-in without a pending invite still gets a personal tenant. Staging only; off in production.

## SMTP

- `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`: relay credentials. Mokosh uses STARTTLS when the port is 587 and TLS when 465. `SMTP_PASSWORD` is an application-tier secret and should be set through the configured provider, not as a plain variable.
- `SMTP_FROM`: the From address on outbound mail. Required when SMTP is set.
- `SMTP_FROM_NAME`: optional display name.
- `MAIL_PROVIDER`: `smtp` (the default) or `bunyip`. The `bunyip` provider sends outbound mail through Bunyip's relay rather than an SMTP server.

Omit the whole block to run with no outbound mail. Every mail then goes to the log at `info` level.

## Storage

- `STORAGE_PROVIDER`: `filesystem` (the default) or `s3`.
- `STORAGE_ROOT`: for `filesystem`, the directory uploaded documents land in. Must be writable and persisted across restarts.
- `STORAGE_S3_ENDPOINT`, `STORAGE_S3_BUCKET`, `STORAGE_S3_ACCESS_KEY_ID`, `STORAGE_S3_SECRET_ACCESS_KEY`: S3 or S3-compatible destination. Set together when `STORAGE_PROVIDER=s3`.

## Infisical

- `INFISICAL_HOST`, `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET`, `INFISICAL_PROJECT_ID`: Universal Auth credentials for Infisical. Used only when `SECRET_BACKEND=infisical` or `CONFIG_BACKEND=infisical`. First-run setup is driven by `mokosh-bootstrap bootstrap-infisical`; see [provider runbook](operations/provider-runbook.md).

## Delegated invoicing (Xero, QuickBooks)

- `XERO_CLIENT_ID`, `XERO_CLIENT_SECRET`, `XERO_WEBHOOK_KEY`: Xero OAuth client and webhook signing key. Set all three to turn Xero delegation on for the deployment. Setting one half refuses boot; a missing webhook key refuses verifying deliveries.
- `QUICKBOOKS_CLIENT_ID`, `QUICKBOOKS_CLIENT_SECRET`, `QUICKBOOKS_VERIFIER_TOKEN`: QuickBooks equivalents.

Both client secrets and verifier tokens are application-tier secrets and should be set through the configured provider.

## Google and Microsoft 365 contact sync

- `GOOGLE_CONTACTS_CLIENT_ID`, `GOOGLE_CONTACTS_CLIENT_SECRET`: Google OAuth client for the contact-sync import. Application-tier secrets.
- `MICROSOFT_CONTACTS_CLIENT_ID`, `MICROSOFT_CONTACTS_CLIENT_SECRET`: Microsoft 365 equivalents.

Either pair is optional. A deployment without them does not expose the corresponding contact-sync provider.

## Stripe

- `STRIPE_PUBLISHABLE_KEY`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`: Stripe keys and webhook signing secret. Required to accept invoice payments through Stripe Checkout.

## PayPal

- `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, `PAYPAL_WEBHOOK_ID`: PayPal credentials. Required to accept invoice payments through PayPal.

## Platform

- `SYSTEM_TENANT_ID`: the UUID of the deployment-owned tenant used for platform-level settings. Required.
- `PORTAL_COOKIE_DOMAIN`: cookie domain for the customer-portal session. Optional; leave unset to keep the default.
- `MOKOSH_UPDATE_CHECK_URL`: opt-in URL for the self-hosted update check. Unset keeps the server from phoning home.

## Scheduling

- `ATTACHMENT_MAX_BYTES`, `KB_ATTACHMENT_MAX_BYTES`: per-upload byte caps for ticket and KB attachment uploads. Invalid values refuse boot.
- `PUBLIC_API_PER_MIN`: per-IP rate budget on the unauthenticated public tree. Defaults to 60 per minute.

## Provider backend selectors

- `CONFIG_BACKEND`: where ordinary config keys are read from. `environment` (the default), `file`, `database`, `bunyip`.
- `SECRET_BACKEND`: tenant-tier secrets (per-tenant integration credentials). `database` (the default), `environment`, `file`, `infisical`.
- `APP_SECRET_BACKEND`: application-tier secrets (`SMTP_PASSWORD`, the Google and Microsoft OAuth clients, Xero and QuickBooks client secrets). Same choices as `SECRET_BACKEND`.

An unknown value in any of these three refuses boot and names the legal set.
