# Configuration

Every variable the server reads, which release added it, and whether the server starts without it. An operator upgrading reads [Recently added](#recently-added) first; for a jump across more than five releases, `just config-since <running version>` lists every change since that release, and the [All variables](#all-variables) list carries the same facts row by row.

The facts are not hand-maintained. `src/config/registry.rs` declares each configuration key with the release that added it and whether it is required (PMS-1442), `src/config/variables.toml` does the same for the variables read outside the registry (the bootstrap and provider-of-record reads in `config::guard::ENTRY_POINTS`) and for removed ones, and `just config-docs` renders them into this page. `just check-config-docs` (part of `just check`) fails when a variable has no row, a row's Required or Added in disagrees with the facts, a row names a variable nothing declares, or the changelog below is missing an entry or a Breaking mark. Adding a variable therefore means declaring it with `since` and `required`, running `just config-docs`, and describing its row.

In development, `.env` is generated once per clone from the committed `.env.example` by the first `just dev`, minting fresh random values for every self-owned secret; see step 3 of [`quickstart.md`](quickstart.md). `just check-env-example` keeps `.env.example` and `compose.dev.yml` in step with the same registry.

## Recently added

<!-- BEGIN GENERATED: recently-added (just config-docs) -->

Configuration changes in the last 5 releases, newest first, rendered by `just config-docs` from `src/config/registry.rs` and `src/config/variables.toml` (edit those, not this section). **Breaking** marks a change that stops the server starting, or turns off a feature that worked, unless the operator acts first; each one names the action and the issue that introduced it. Upgrading across more releases than this? Run `just config-since <running version>`.

<a id="release-v0-16-0"></a>

### v0.16.0

#### Added

- [`ALLOW_UNINVITED_BUNYIP_SIGNUP`](#var-allow-uninvited-bunyip-signup) (Required: no) - Optional, off by default. Set `true` only where uninvited Bunyip sign-up is wanted (staging). (PMS-1457)
- [`APP_SECRET_BACKEND`](#var-app-secret-backend) (Required: no) - Optional. Selects where application-tier secrets live; unset keeps the hosting profile's default. (PMS-1424)

#### Changed

- **Breaking:** [`GOOGLE_CONTACTS_CLIENT_ID`](#var-google-contacts-client-id) (Required: no) - Now an application-tier secret served by `APP_SECRET_BACKEND`'s provider, no longer a plain variable. Move both halves there (an `app_secrets` row, Infisical `/app`, a `{NAME}_FILE` compose secret or an `APP_SECRETS_DIR` file); setting only one half refuses boot. (PMS-1430)
- **Breaking:** [`GOOGLE_CONTACTS_CLIENT_SECRET`](#var-google-contacts-client-secret) (Required: no) - Now an application-tier secret served by `APP_SECRET_BACKEND`'s provider, no longer a plain variable. Move both halves there (an `app_secrets` row, Infisical `/app`, a `{NAME}_FILE` compose secret or an `APP_SECRETS_DIR` file); setting only one half refuses boot. (PMS-1430)
- **Breaking:** [`SECRET_BACKEND`](#var-secret-backend) (Required: no) - Now selects tenant-tier secrets only. If you set it expecting application secrets (`SMTP_PASSWORD`, the Google client pair) to move too, also set `APP_SECRET_BACKEND` to the same provider before restarting. (PMS-1424)

<a id="release-v0-15-0"></a>

### v0.15.0

#### Added

- [`OIDC_BACKCHANNEL_CLIENT_ID`](#var-oidc-backchannel-client-id) (Required: no) - Optional. Set it to the OIDC client id Bunyip addresses back-channel logout tokens to; unset refuses every logout token. (PMS-998)
- [`STORAGE_PROVIDER`](#var-storage-provider) (Required: no) - Optional. The new name for a storage setting; the old name keeps working, so rename at your next compose edit. (PMS-1317)
- [`STORAGE_ROOT`](#var-storage-root) (Required: no) - Optional. The new name for a storage setting; the old name keeps working, so rename at your next compose edit. (PMS-1317)
- [`STORAGE_S3_ACCESS_KEY_ID`](#var-storage-s3-access-key-id) (Required: no) - Optional. The new name for a storage setting; the old name keeps working, so rename at your next compose edit. (PMS-1317)
- [`STORAGE_S3_BUCKET`](#var-storage-s3-bucket) (Required: no) - Optional. The new name for a storage setting; the old name keeps working, so rename at your next compose edit. (PMS-1317)
- [`STORAGE_S3_ENDPOINT`](#var-storage-s3-endpoint) (Required: no) - Optional. The new name for a storage setting; the old name keeps working, so rename at your next compose edit. (PMS-1317)
- [`STORAGE_S3_PATH_STYLE`](#var-storage-s3-path-style) (Required: no) - Optional. The new name for a storage setting; the old name keeps working, so rename at your next compose edit. (PMS-1317)
- [`STORAGE_S3_REGION`](#var-storage-s3-region) (Required: no) - Optional. The new name for a storage setting; the old name keeps working, so rename at your next compose edit. (PMS-1317)
- [`STORAGE_S3_SECRET_ACCESS_KEY`](#var-storage-s3-secret-access-key) (Required: no) - Optional. The new name for a storage setting; the old name keeps working, so rename at your next compose edit. (PMS-1317)

#### Deprecated

- [`ATTACHMENT_DIR`](#var-attachment-dir) (Required: no) - Renamed to `STORAGE_ROOT`. The old name still works and logs a warning naming the new one; rename it at your next compose edit. (PMS-1317)
- [`S3_ACCESS_KEY_ID`](#var-s3-access-key-id) (Required: no) - Renamed to `STORAGE_S3_ACCESS_KEY_ID`. The old name still works and logs a warning naming the new one; rename it at your next compose edit. (PMS-1317)
- [`S3_BUCKET`](#var-s3-bucket) (Required: no) - Renamed to `STORAGE_S3_BUCKET`. The old name still works and logs a warning naming the new one; rename it at your next compose edit. (PMS-1317)
- [`S3_ENDPOINT`](#var-s3-endpoint) (Required: no) - Renamed to `STORAGE_S3_ENDPOINT`. The old name still works and logs a warning naming the new one; rename it at your next compose edit. (PMS-1317)
- [`S3_PATH_STYLE`](#var-s3-path-style) (Required: no) - Renamed to `STORAGE_S3_PATH_STYLE`. The old name still works and logs a warning naming the new one; rename it at your next compose edit. (PMS-1317)
- [`S3_REGION`](#var-s3-region) (Required: no) - Renamed to `STORAGE_S3_REGION`. The old name still works and logs a warning naming the new one; rename it at your next compose edit. (PMS-1317)
- [`S3_SECRET_ACCESS_KEY`](#var-s3-secret-access-key) (Required: no) - Renamed to `STORAGE_S3_SECRET_ACCESS_KEY`. The old name still works and logs a warning naming the new one; rename it at your next compose edit. (PMS-1317)
- [`STORAGE_BACKEND`](#var-storage-backend) (Required: no) - Renamed to `STORAGE_PROVIDER`. The old name still works and logs a warning naming the new one; rename it at your next compose edit. (PMS-1317)

<a id="release-v0-14-0"></a>

### v0.14.0

#### Added

- **Breaking:** [`MOKOSH_DEPLOYMENT_MODE`](#var-mokosh-deployment-mode) (Required: yes) - Set `self-hosted` or `saas` before restarting; boot refuses without it outside dev/test. Introduced by PMS-1011. (PMS-1160)
- [`APP_SECRETS_DIR`](#var-app-secrets-dir) (Required: no) - Optional. Directory the file application-secret provider reads; unset disables that provider. (PMS-988)
- [`AUTH_PROVIDERS`](#var-auth-providers) (Required: no) - Optional. Unset keeps the hosting profile's default (`bunyip,local` in saas, `local` self-hosted). (PMS-981)
- [`BRANDING_COMPANY_BACKGROUND_MAX_BYTES`](#var-branding-company-background-max-bytes) (Required: no) - Optional. Unset keeps the built-in cap for that asset. (MAPPS-622)
- [`BRANDING_COMPANY_FAVICON_MAX_BYTES`](#var-branding-company-favicon-max-bytes) (Required: no) - Optional. Unset keeps the built-in cap for that asset. (MAPPS-622)
- [`BRANDING_COMPANY_LOGO_MAX_BYTES`](#var-branding-company-logo-max-bytes) (Required: no) - Optional. Unset keeps the built-in cap for that asset. (MAPPS-622)
- [`BRANDING_TENANT_BACKGROUND_MAX_BYTES`](#var-branding-tenant-background-max-bytes) (Required: no) - Optional. Unset keeps the built-in cap for that asset. (MAPPS-622)
- [`BRANDING_TENANT_FAVICON_MAX_BYTES`](#var-branding-tenant-favicon-max-bytes) (Required: no) - Optional. Unset keeps the built-in cap for that asset. (MAPPS-622)
- [`BUNYIP_CONFIG_CLIENT_ID`](#var-bunyip-config-client-id) (Required: no) - Optional. Configuration provider chain and its construction values; unset keeps the hosting profile's default. (PMS-987)
- [`BUNYIP_CONFIG_CLIENT_SECRET`](#var-bunyip-config-client-secret) (Required: no) - Optional. Configuration provider chain and its construction values; unset keeps the hosting profile's default. (PMS-987)
- [`BUNYIP_CONFIG_URL`](#var-bunyip-config-url) (Required: no) - Optional. Configuration provider chain and its construction values; unset keeps the hosting profile's default. (PMS-987)
- [`BUNYIP_STATUS_CLIENT_ID`](#var-bunyip-status-client-id) (Required: no) - Optional. Set both to let Bunyip read provider status with its machine credential. (PMS-1193)
- [`BUNYIP_STATUS_CLIENT_SECRET`](#var-bunyip-status-client-secret) (Required: no) - Optional. Set both to let Bunyip read provider status with its machine credential. (PMS-1193)
- [`CONFIG_BACKEND`](#var-config-backend) (Required: no) - Optional. `environment` is the only accepted value and the default. (PMS-982)
- [`CONFIG_FILE_DIR`](#var-config-file-dir) (Required: no) - Optional. Configuration provider chain and its construction values; unset keeps the hosting profile's default. (PMS-987)
- [`CONFIG_PROVIDERS`](#var-config-providers) (Required: no) - Optional. Configuration provider chain and its construction values; unset keeps the hosting profile's default. (PMS-987)
- [`GOOGLE_CONTACTS_CLIENT_ID`](#var-google-contacts-client-id) (Required: no) - Optional. Leave it unset to keep the default.
- [`GOOGLE_CONTACTS_CLIENT_SECRET`](#var-google-contacts-client-secret) (Required: no) - Optional. Leave it unset to keep the default.
- [`KB_ATTACHMENT_MAX_BYTES`](#var-kb-attachment-max-bytes) (Required: no) - Optional. Unset keeps the built-in cap. (PMS-923)
- [`MAIL_PROVIDER`](#var-mail-provider) (Required: no) - Optional. Unset keeps the profile default, or `smtp` when `SMTP_HOST` is set. (PMS-1013)
- [`MOKOSH_MAX_TENANTS`](#var-mokosh-max-tenants) (Required: no) - Optional. Unset means no tenant cap. (MAPPS-457)
- [`ORGANIZATIONS_ENABLED`](#var-organizations-enabled) (Required: no) - Optional. Unset follows the hosting profile (off self-hosted, on saas). (PMS-983)
- [`OUTBOUND_PRIVATE_ALLOWLIST`](#var-outbound-private-allowlist) (Required: no) - Optional. Leave it unset to keep the default.
- [`PAYPAL_API_BASE`](#var-paypal-api-base) (Required: no) - Optional. Leave it unset to keep the default.
- [`S3_ACCESS_KEY_ID`](#var-s3-access-key-id) (Required: no) - Optional. Leave it unset to keep the default.
- [`S3_BUCKET`](#var-s3-bucket) (Required: no) - Optional. Leave it unset to keep the default.
- [`S3_ENDPOINT`](#var-s3-endpoint) (Required: no) - Optional. Leave it unset to keep the default.
- [`S3_PATH_STYLE`](#var-s3-path-style) (Required: no) - Optional. Leave it unset to keep the default.
- [`S3_REGION`](#var-s3-region) (Required: no) - Optional. Leave it unset to keep the default.
- [`S3_SECRET_ACCESS_KEY`](#var-s3-secret-access-key) (Required: no) - Optional. Leave it unset to keep the default.
- [`SECRET_BACKEND`](#var-secret-backend) (Required: no) - Optional. Unset keeps the default provider (`database` for secrets, `local` for storage). (PMS-910)
- [`STORAGE_BACKEND`](#var-storage-backend) (Required: no) - Optional. Unset keeps the default provider (`database` for secrets, `local` for storage). (PMS-910)

#### Changed

- **Breaking:** [`BASE_URL`](#var-base-url) (Required: yes) - Now required outside dev/test: boot refuses when it is unset instead of falling back to a localhost or single-role default. Set it before restarting. (PMS-1160)
- **Breaking:** [`CLIENT_ORIGIN`](#var-client-origin) (Required: yes) - Now required outside dev/test: boot refuses when it is unset instead of falling back to a localhost or single-role default. Set it before restarting. (PMS-1160)
- **Breaking:** [`MOKOSH_APP_DATABASE_URL`](#var-mokosh-app-database-url) (Required: yes) - Now required outside dev/test: boot refuses when it is unset instead of falling back to a localhost or single-role default. Set it before restarting. (PMS-1160)
- **Breaking:** [`SPA_BASE_URL`](#var-spa-base-url) (Required: yes) - Now required outside dev/test: boot refuses when it is unset instead of falling back to a localhost or single-role default. Set it before restarting. (PMS-1160)

#### Removed

- **Breaking:** [`GOOGLE_OAUTH_CLIENT_ID`](#var-google-oauth-client-id) (Required: no) - Delete it from the compose variables; the Google sign-in routes it served are gone. (PMS-837)
- **Breaking:** [`GOOGLE_OAUTH_CLIENT_SECRET`](#var-google-oauth-client-secret) (Required: no) - Delete it from the compose secrets; the Google sign-in routes it served are gone. (PMS-837)
- **Breaking:** [`GOOGLE_OAUTH_REDIRECT_URI`](#var-google-oauth-redirect-uri) (Required: no) - Delete it from the compose variables; the Google sign-in routes it served are gone. (PMS-837)
- **Breaking:** [`OAUTH_SUPER_ADMIN_EMAILS`](#var-oauth-super-admin-emails) (Required: no) - Delete it from the compose variables; only the removed Google sign-in path read it. (PMS-837)

<a id="release-v0-13-0"></a>

### v0.13.0

No configuration changes.

<a id="release-v0-12-0"></a>

### v0.12.0

#### Added

- [`ABUSE_CONTACT_EMAIL`](#var-abuse-contact-email) (Required: no) - Optional. Unset drops the public logo URL or the abuse line from client-facing surfaces. (PMS-748)
- [`INFISICAL_ADDRESS`](#var-infisical-address) (Required: no) - Optional. Blank reports Infisical as skipped in the readiness probe. (GOV-50)
- [`PUBLIC_API_BASE_URL`](#var-public-api-base-url) (Required: no) - Optional. Unset drops the public logo URL or the abuse line from client-facing surfaces. (PMS-748)
- [`SPA_BASE_URL`](#var-spa-base-url) (Required: no) - Optional at the time (required since v0.14.0). Set it to the mokosh-apps origin so SPA-only email links land there. (MAPPS-425)
- [`TENANT_LOGO_MAX_BYTES`](#var-tenant-logo-max-bytes) (Required: no) - Optional. Leave it unset to keep the default.

<!-- END GENERATED: recently-added -->

## All variables

- **Required** `yes` means the server refuses to start without the variable when `ENVIRONMENT` is anything but `development`, `dev` or `test`; those three fall back to a development value so `just dev` boots with nothing set. `no` is followed by the default, or by what stays off while it is unset.
- **Added in** is the release that introduced the variable, followed by the release that made it required, deprecated it or removed it, where one did. Keys that predate the first release tag are dated `v0.1.0`.
- **Where set** is where the dev stack sets it. A deployment sets every variable in its compose variables or compose secrets.

### Deployment shape and database

| Variable | Required | Added in | Where set | Purpose |
| --- | --- | --- | --- | --- |
| <a id="var-mokosh-deployment-mode"></a>`MOKOSH_DEPLOYMENT_MODE` | yes | v0.14.0 | `.env` | `self-hosted` or `saas`. Selects the hosting profile, which supplies the default provider for every capability (configuration, secrets, authentication, email, storage). An unrecognized value fails startup naming both legal values (PMS-1011, PMS-1160). |
| <a id="var-environment"></a>`ENVIRONMENT` | no, default `development` | v0.1.0 | `.env` | `development`, `dev` and `test` accept the built-in development secrets and skip the required-variable gate; every other value enforces both. A deployment sets `production` or `staging`. |
| <a id="var-database-url"></a>`DATABASE_URL` | yes | v0.1.0 | `.env` for host-side tools, `compose.dev.yml` for the container | Privileged `mokosh_migrator` connection string (`BYPASSRLS`), used for migrations, bootstrap and cross-tenant workers. The built-in fallback is a localhost Postgres, so a deployment without it cannot start. |
| <a id="var-mokosh-app-database-url"></a>`MOKOSH_APP_DATABASE_URL` | yes | v0.3.0; required since v0.14.0 | `.env` | Request-serving `mokosh_app` connection string (`NOBYPASSRLS`, PMS-285). Unset in development falls back to `DATABASE_URL`, single-role, and row-level security goes inert, which is why every other environment refuses to start without it (PMS-1160). |
| <a id="var-mokosh-admin-database-url"></a>`MOKOSH_ADMIN_DATABASE_URL` | no, needed only on the first boot against an unprovisioned database | v0.4.0 | `.env` | Superuser connection the server uses once to create the `mokosh_migrator` and `mokosh_app` roles (PMS-489). Unused once both roles exist. |
| <a id="var-mokosh-migrator-password"></a>`MOKOSH_MIGRATOR_PASSWORD` | no, needed only when the roles are provisioned | v0.3.0 | `.env` | Password given to the `mokosh_migrator` role when it is created. Generated per clone in development. |
| <a id="var-mokosh-app-password"></a>`MOKOSH_APP_PASSWORD` | no, needed only when the roles are provisioned | v0.3.0 | `.env` | Password given to `mokosh_app`; boot reconciles the role's password from it. Generated per clone in development. |
| <a id="var-run-migrations"></a>`RUN_MIGRATIONS` | no, default `true` | v0.1.0 | `.env` | Whether the server applies pending migrations on start. |
| <a id="var-rust-log"></a>`RUST_LOG` | no, default `info` | v0.1.0 | `.env` | Tracing filter (the dev stack sets `info,mokosh_server=debug`). |

### Secrets and encryption

| Variable | Required | Added in | Where set | Purpose |
| --- | --- | --- | --- | --- |
| <a id="var-jwt-secret"></a>`JWT_SECRET` | yes | v0.1.0; required since v0.4.0 | `.env` | HS256 session signing key, at least 32 bytes outside development (PMS-497, PMS-499). Generated per clone in development. |
| <a id="var-encryption-key"></a>`ENCRYPTION_KEY` | yes | v0.1.0; required since v0.4.0 | `.env` | AES-256-GCM key for data at rest, 64 hex characters outside development (PMS-498). The database secret provider encrypts under it, so losing it loses every stored secret. |
| <a id="var-bunyip-webhook-secret"></a>`BUNYIP_WEBHOOK_SECRET` | yes | v0.6.0 | `.env` | Shared secret for Bunyip's `account_deleted` webhook; equals bunyip-api's `BUNYIP_WEBHOOK_SIGNING_SECRET` (PMS-591). |
| <a id="var-secret-backend"></a>`SECRET_BACKEND` | no, default the hosting profile's (`database`) | v0.14.0 | `.env` | Where TENANT-tier secrets live: `database` (AES-256-GCM ciphertext under `ENCRYPTION_KEY`) or `infisical`, which also needs the `INFISICAL_*` machine identity below. Since v0.16.0 it no longer selects application-tier secrets (PMS-1424). An unrecognized value fails startup. |
| <a id="var-app-secret-backend"></a>`APP_SECRET_BACKEND` | no, default the hosting profile's (`database`) | v0.16.0 | `.env` | Where APPLICATION-tier secrets live (`SMTP_PASSWORD`, the Google client pair): `environment`, `file`, `database` or `infisical` (PMS-1424). Separate from `SECRET_BACKEND` because a tenant secret is a per-tenant write that a read-only provider cannot hold. An unrecognized value fails startup. |
| <a id="var-app-secrets-dir"></a>`APP_SECRETS_DIR` | no, unset disables the file provider | v0.14.0 | `.env` | Directory the file application-secret provider reads, one file per governed secret named without an extension (PMS-988). |
| <a id="var-google-contacts-client-id"></a>`GOOGLE_CONTACTS_CLIENT_ID` | no, unset leaves Google Contacts import unavailable | v0.14.0 | governed application-tier secret, NOT `.env` | The host's Google Cloud OAuth client id for the Google Contacts import (PMS-1430). Served by the `APP_SECRET_BACKEND` provider: Infisical under `/app`, a `{NAME}_FILE` compose secret, an `APP_SECRETS_DIR` file or an `app_secrets` row. Setting only one half of the pair is a boot error naming the missing half. |
| <a id="var-google-contacts-client-secret"></a>`GOOGLE_CONTACTS_CLIENT_SECRET` | no, unset leaves Google Contacts import unavailable | v0.14.0 | governed application-tier secret, NOT `.env` | The secret half of the pair above, served by the same provider so both come from one Google project. |
| <a id="var-infisical-address"></a>`INFISICAL_ADDRESS` | no, blank reports Infisical as skipped | v0.12.0 | `MOKOSH_SERVER_INFISICAL_ADDRESS` in `.env`, written by `just dev-infisical` | In-network Infisical base URL, for the readiness probe and the Infisical secret provider (GOV-50, PMS-707). |
| <a id="var-infisical-project-id"></a>`INFISICAL_PROJECT_ID` | no, needed only with the `infisical` provider | v0.1.0 | `.env`, filled by `just infisical-bootstrap` | Infisical project the secret provider reads and writes. |
| <a id="var-infisical-client-id"></a>`INFISICAL_CLIENT_ID` | no, needed only with the `infisical` provider | v0.1.0 | `.env`, filled by `just infisical-bootstrap` | Universal Auth machine identity client id. |
| <a id="var-infisical-client-secret"></a>`INFISICAL_CLIENT_SECRET` | no, needed only with the `infisical` provider | v0.1.0 | `.env`, filled by `just infisical-bootstrap` | Universal Auth machine identity client secret. |
| <a id="var-infisical-environment"></a>`INFISICAL_ENVIRONMENT` | no, default `dev` | v0.1.0 | `.env` | Infisical environment slug the provider reads from. |

### Configuration providers

| Variable | Required | Added in | Where set | Purpose |
| --- | --- | --- | --- | --- |
| <a id="var-config-backend"></a>`CONFIG_BACKEND` | no, default `environment` | v0.14.0 | `.env` | The single-provider configuration slot. `environment` is the only value it accepts; `file`, `database` and `bunyip` are reached through `CONFIG_PROVIDERS` (PMS-982, PMS-987). An unrecognized value fails startup naming the legal ones. |
| <a id="var-config-providers"></a>`CONFIG_PROVIDERS` | no, default the hosting profile's provider | v0.14.0 | `.env` | Comma-separated priority list of configuration providers, e.g. `file,database,environment`. Today it powers the `provider-status`, `provider-migrate` and `provider-purge` subcommands (PMS-1012); request-serving reads still go through `CONFIG_BACKEND`. |
| <a id="var-config-file-dir"></a>`CONFIG_FILE_DIR` | no, unset disables the file provider | v0.14.0 | `.env` | Directory the file configuration provider reads, one file per key. |
| <a id="var-bunyip-config-url"></a>`BUNYIP_CONFIG_URL` | no, unset disables the Bunyip provider | v0.14.0 | `.env` | Base URL of the Bunyip API the Bunyip configuration provider reads. |
| <a id="var-bunyip-config-client-id"></a>`BUNYIP_CONFIG_CLIENT_ID` | no, needed only with `BUNYIP_CONFIG_URL` | v0.14.0 | `.env` | Machine-credential client id for Bunyip's `POST /v1/oauth2/token`. |
| <a id="var-bunyip-config-client-secret"></a>`BUNYIP_CONFIG_CLIENT_SECRET` | no, needed only with `BUNYIP_CONFIG_URL` | v0.14.0 | `.env` | Machine-credential client secret for the same token call. |

### Server and public URLs

| Variable | Required | Added in | Where set | Purpose |
| --- | --- | --- | --- | --- |
| <a id="var-host"></a>`HOST` | no, default `0.0.0.0` | v0.1.0 | `.env` | Listen address. |
| <a id="var-port"></a>`PORT` | no, default `8080` | v0.1.0 | `MOKOSH_PORT` in `.env` | Listen port inside the container, and the port Traefik forwards to. |
| <a id="var-base-url"></a>`BASE_URL` | yes | v0.1.0; required since v0.14.0 | `.env` | Base of platform-owned email links (password reset, portal grant, invoice pay). The development fallback is localhost, which outside development would send every link nowhere (PMS-1160). |
| <a id="var-client-origin"></a>`CLIENT_ORIGIN` | yes | v0.2.0; required since v0.14.0 | `.env` | Browser-visible origin of the client that talks to this API: the `CORS_ORIGIN` default and the OAuth popup `postMessage` origin (PMS-1160). |
| <a id="var-spa-base-url"></a>`SPA_BASE_URL` | yes | v0.12.0; required since v0.14.0 | `.env` | Base for emailed links to pages only mokosh-apps serves (request forms, portal set-password, invoice Pay Now). On a deployment `CLIENT_ORIGIN` is the apex, so falling back to it lands every such link on Bunyip's 404 (MAPPS-425, PMS-1160). |
| <a id="var-cors-origin"></a>`CORS_ORIGIN` | no, default `CLIENT_ORIGIN` | v0.2.0 | `.env` | Comma-separated CORS allow-list. Every entry must be a valid header value or the server panics at startup. |
| <a id="var-public-api-base-url"></a>`PUBLIC_API_BASE_URL` | no, unset sends request-form email without the logo | v0.12.0 | `.env` | This deployment's public API base, used to make the tenant logo absolute in request-form email (PMS-748, MAPPS-429). |
| <a id="var-abuse-contact-email"></a>`ABUSE_CONTACT_EMAIL` | no, unset drops the report-abuse line | v0.12.0 | `.env` | Address a client can report an unwanted request-form email to (PMS-748). |
| <a id="var-mokosh-max-tenants"></a>`MOKOSH_MAX_TENANTS` | no, unset leaves tenant creation uncapped | v0.14.0 | `.env` | Ceiling on tenants the super-admin can create; the create endpoint answers 409 at the cap (MAPPS-457). |
| <a id="var-mokosh-update-check-url"></a>`MOKOSH_UPDATE_CHECK_URL` | no, unset disables the update probe | v0.3.0 | `.env` | Upstream version probe for the self-hosted update check (PMS-238). |

### Mail

| Variable | Required | Added in | Where set | Purpose |
| --- | --- | --- | --- | --- |
| <a id="var-mail-provider"></a>`MAIL_PROVIDER` | no, default the hosting profile's (`log` self-hosted, `smtp` saas) | v0.14.0 | `.env` | `log` (`LogMailer`, no bytes leave the box) or `smtp` (`SmtpMailer` against `SMTP_HOST`). Unset with `SMTP_HOST` set means `smtp`. An unrecognized value, or `smtp` without `SMTP_HOST`, fails startup (PMS-1013). |
| <a id="var-smtp-host"></a>`SMTP_HOST` | no, unset selects `LogMailer` | v0.2.0 | `.env` | SMTP relay host; the dev stack points it at mailpit. The admin email settings override every `SMTP_*` value per field (PMS-638). |
| <a id="var-smtp-port"></a>`SMTP_PORT` | no, default `587` | v0.2.0 | `.env` | SMTP relay port. |
| <a id="var-smtp-username"></a>`SMTP_USERNAME` | no, unset sends unauthenticated | v0.2.0 | `.env` | SMTP login; set without `SMTP_PASSWORD` it fails startup. |
| <a id="var-smtp-password"></a>`SMTP_PASSWORD` | no, needed with `SMTP_USERNAME` | v0.2.0 | governed application-tier secret | SMTP relay password, served by the `APP_SECRET_BACKEND` provider. |
| <a id="var-smtp-from"></a>`SMTP_FROM` | no, needed when `SMTP_HOST` is set | v0.2.0 | `.env` | Sender mailbox (RFC 5322). Its domain must be one the relay may send for. |
| <a id="var-smtp-tls"></a>`SMTP_TLS` | no, default `starttls` | v0.2.0 | `.env` | `none`, `starttls` or `implicit`. |

### Authentication

| Variable | Required | Added in | Where set | Purpose |
| --- | --- | --- | --- | --- |
| <a id="var-auth-providers"></a>`AUTH_PROVIDERS` | no, default the hosting profile's (`bunyip,local` saas, `local` self-hosted) | v0.14.0 | `.env` | Comma-separated authentication-provider priority list. `AuthService::login` refuses the local password path without `local`, and the middleware skips Bunyip verification without `bunyip` (PMS-981). |
| <a id="var-oidc-issuer"></a>`OIDC_ISSUER` | no, unset turns Bunyip sign-in off | v0.3.0 | `compose.dev.yml`, derived from `${USER}` | Bunyip issuer; must equal the token `iss` and Bunyip's discovery issuer. |
| <a id="var-oidc-audience"></a>`OIDC_AUDIENCE` | no, unset turns Bunyip sign-in off | v0.3.0 | `compose.dev.yml`, derived from `${USER}` | Audience on the mokosh-apps `oauth_clients` row in bunyip-api. |
| <a id="var-oidc-jwks-cache-ttl-secs"></a>`OIDC_JWKS_CACHE_TTL_SECS` | no, default `600` | v0.3.0 | `.env` | How long Bunyip's JWKS is cached, in seconds. |
| <a id="var-oidc-leeway-seconds"></a>`OIDC_LEEWAY_SECONDS` | no, default `30` | v0.3.0 | `.env` | Clock leeway for token validation, in seconds. |
| <a id="var-oidc-default-tenant-id"></a>`OIDC_DEFAULT_TENANT_ID` | no, default the migration-023 seed tenant | v0.3.0 | `.env` | Shared landing tenant a Bunyip user is provisioned into (PMS-239). |
| <a id="var-oidc-backchannel-client-id"></a>`OIDC_BACKCHANNEL_CLIENT_ID` | no, unset refuses every back-channel logout token | v0.15.0 | `.env` | Client id Bunyip addresses a back-channel logout token to: the mokosh-apps row's `client_id`, not its audience (PMS-998). |
| <a id="var-allow-uninvited-bunyip-signup"></a>`ALLOW_UNINVITED_BUNYIP_SIGNUP` | no, default off | v0.16.0 | `.env` | Lets a Bunyip identity with a verified email provision a personal tenant on first sight. Production stays invitation-only; staging turns it on (PMS-1457). |
| <a id="var-bunyip-status-client-id"></a>`BUNYIP_STATUS_CLIENT_ID` | no, unset gates provider status on `RequireAdmin` alone | v0.14.0 | `.env` | Machine credential Bunyip's provider-status aggregator presents as HTTP Basic (PMS-1193). Set together with the secret below. |
| <a id="var-bunyip-status-client-secret"></a>`BUNYIP_STATUS_CLIENT_SECRET` | no, unset gates provider status on `RequireAdmin` alone | v0.14.0 | `.env` | The secret half, compared in constant time. |
| <a id="var-admin-email"></a>`ADMIN_EMAIL` | no, unset skips the first-run admin | v0.1.0 | `.env` | Optional first-run super-admin, development only; see [`first-run-onboarding.md`](first-run-onboarding.md). |
| <a id="var-admin-password"></a>`ADMIN_PASSWORD` | no, unset skips the first-run admin | v0.1.0 | `.env` | Password for the first-run admin above. |
| <a id="var-login-approval-enabled"></a>`LOGIN_APPROVAL_ENABLED` | no, default off | v0.8.0 | `.env` | The suspicious-login notify-and-approve gate (PMS-658), off by default because it can withhold a login. |

### Features, network and payments

| Variable | Required | Added in | Where set | Purpose |
| --- | --- | --- | --- | --- |
| <a id="var-organizations-enabled"></a>`ORGANIZATIONS_ENABLED` | no, default the hosting profile's (off self-hosted, on saas) | v0.14.0 | `.env` | The organizations feature flag (PMS-983). |
| <a id="var-ip2location-db-path"></a>`IP2LOCATION_DB_PATH` | no, unset turns country lookup off | v0.7.0 | `.env` | IP2Location database path inside the container, for login-location alerts (PMS-657). |
| <a id="var-ip2proxy-db-path"></a>`IP2PROXY_DB_PATH` | no, unset turns ASN and VPN enrichment off | v0.11.0 | `.env` | IP2Proxy database path inside the container (BUNYIP-475). |
| <a id="var-trusted-proxy-cidr"></a>`TRUSTED_PROXY_CIDR` | no, default loopback plus private ranges | v0.7.0 | `.env` | CIDRs whose `X-Forwarded-For` is trusted for the client IP (PMS-587). Tighten it to the proxy subnet in production. |
| <a id="var-outbound-private-allowlist"></a>`OUTBOUND_PRIVATE_ALLOWLIST` | no, unset refuses every private outbound target | v0.14.0 | `.env` | Hosts, IPs or CIDRs exempt from the outbound-URL screen, for a self-hosted integration on a private network (PMS-809). |
| <a id="var-stripe-api-base"></a>`STRIPE_API_BASE` | no, default `https://api.stripe.com` | v0.10.0 | `.env` | Stripe REST base, overridden only by tests driving a stub. |
| <a id="var-paypal-api-base"></a>`PAYPAL_API_BASE` | no, default PayPal's live or sandbox host | v0.14.0 | `.env` | PayPal REST base, overridden only by tests driving a stub. |
| <a id="var-mokosh-demo-seed"></a>`MOKOSH_DEMO_SEED` | no, default off outside production | v0.3.0 | `.env` | Seeds demo data into a new tenant; production always seeds (PMS-710). |
| <a id="var-mokosh-seed-tenant-id"></a>`MOKOSH_SEED_TENANT_ID` | no, default the migration-023 seed tenant | v0.3.0 | `.env` | Template tenant the demo seed copies from; a value that is not a UUID fails startup. |

### Storage and uploads

| Variable | Required | Added in | Where set | Purpose |
| --- | --- | --- | --- | --- |
| <a id="var-storage-provider"></a>`STORAGE_PROVIDER` | no, default `local` | v0.15.0 | `compose.dev.yml` | `local` or `s3`. An unrecognized value fails startup rather than writing uploads to a container filesystem (PMS-1317). |
| <a id="var-storage-root"></a>`STORAGE_ROOT` | no, default `./attachments` | v0.15.0 | `compose.dev.yml` | Filesystem root for the `local` provider: attachments, tenant logos, knowledge base images and issued documents, each under its tenant (see [Storage layout](#storage-layout)). Deployments want an absolute path on a mounted volume. |
| <a id="var-storage-s3-endpoint"></a>`STORAGE_S3_ENDPOINT` | no, needed when `STORAGE_PROVIDER=s3` | v0.15.0 | `compose.dev.yml` | S3-compatible endpoint, an http(s) URL. With `s3` and no endpoint, bucket or credential the server refuses to start. |
| <a id="var-storage-s3-bucket"></a>`STORAGE_S3_BUCKET` | no, needed when `STORAGE_PROVIDER=s3` | v0.15.0 | `compose.dev.yml` | Bucket name. |
| <a id="var-storage-s3-region"></a>`STORAGE_S3_REGION` | no, default `us-east-1` | v0.15.0 | `compose.dev.yml` | Signing region. |
| <a id="var-storage-s3-path-style"></a>`STORAGE_S3_PATH_STYLE` | no, default `true` | v0.15.0 | `compose.dev.yml` | Path-style addressing, which every non-AWS store serves; `false` selects virtual-hosted. |
| <a id="var-storage-s3-access-key-id"></a>`STORAGE_S3_ACCESS_KEY_ID` | no, needed when `STORAGE_PROVIDER=s3` | v0.15.0 | `compose.dev.yml` | Access key id. |
| <a id="var-storage-s3-secret-access-key"></a>`STORAGE_S3_SECRET_ACCESS_KEY` | no, needed when `STORAGE_PROVIDER=s3` | v0.15.0 | `compose.dev.yml` | Secret access key. |
| <a id="var-storage-backend"></a>`STORAGE_BACKEND` | no | v0.14.0; deprecated in v0.15.0, use `STORAGE_PROVIDER` | `compose.dev.yml` | Deprecated alias, honoured only when the new name is unset; using it logs a line naming the replacement, and `mokosh-server provider-status` reports which name supplied each setting. Removal is PMS-1443. |
| <a id="var-attachment-dir"></a>`ATTACHMENT_DIR` | no | v0.4.0; deprecated in v0.15.0, use `STORAGE_ROOT` | `compose.dev.yml` | Deprecated alias, as above. |
| <a id="var-s3-endpoint"></a>`S3_ENDPOINT` | no | v0.14.0; deprecated in v0.15.0, use `STORAGE_S3_ENDPOINT` | `compose.dev.yml` | Deprecated alias, as above. |
| <a id="var-s3-bucket"></a>`S3_BUCKET` | no | v0.14.0; deprecated in v0.15.0, use `STORAGE_S3_BUCKET` | `compose.dev.yml` | Deprecated alias, as above. |
| <a id="var-s3-region"></a>`S3_REGION` | no | v0.14.0; deprecated in v0.15.0, use `STORAGE_S3_REGION` | `compose.dev.yml` | Deprecated alias, as above. |
| <a id="var-s3-path-style"></a>`S3_PATH_STYLE` | no | v0.14.0; deprecated in v0.15.0, use `STORAGE_S3_PATH_STYLE` | `compose.dev.yml` | Deprecated alias, as above. |
| <a id="var-s3-access-key-id"></a>`S3_ACCESS_KEY_ID` | no | v0.14.0; deprecated in v0.15.0, use `STORAGE_S3_ACCESS_KEY_ID` | `compose.dev.yml` | Deprecated alias, as above. |
| <a id="var-s3-secret-access-key"></a>`S3_SECRET_ACCESS_KEY` | no | v0.14.0; deprecated in v0.15.0, use `STORAGE_S3_SECRET_ACCESS_KEY` | `compose.dev.yml` | Deprecated alias, as above. |
| <a id="var-attachment-max-bytes"></a>`ATTACHMENT_MAX_BYTES` | no, default 25 MiB | v0.4.0 | `.env` | Per-attachment size cap in bytes. |
| <a id="var-kb-attachment-max-bytes"></a>`KB_ATTACHMENT_MAX_BYTES` | no, default 5 MiB | v0.14.0 | `.env` | Cap on an image embedded in a knowledge base article (PMS-923). |
| <a id="var-tenant-logo-max-bytes"></a>`TENANT_LOGO_MAX_BYTES` | no, default 1 MiB | v0.12.0 | `.env` | Cap on an uploaded tenant logo. |
| <a id="var-branding-tenant-favicon-max-bytes"></a>`BRANDING_TENANT_FAVICON_MAX_BYTES` | no, default 512 KiB | v0.14.0 | `.env` | Cap on a tenant favicon (MAPPS-622). |
| <a id="var-branding-tenant-background-max-bytes"></a>`BRANDING_TENANT_BACKGROUND_MAX_BYTES` | no, default 2 MiB | v0.14.0 | `.env` | Cap on a tenant sign-in background. |
| <a id="var-branding-company-logo-max-bytes"></a>`BRANDING_COMPANY_LOGO_MAX_BYTES` | no, default 1 MiB | v0.14.0 | `.env` | Cap on a client company logo. |
| <a id="var-branding-company-favicon-max-bytes"></a>`BRANDING_COMPANY_FAVICON_MAX_BYTES` | no, default 512 KiB | v0.14.0 | `.env` | Cap on a client company favicon. |
| <a id="var-branding-company-background-max-bytes"></a>`BRANDING_COMPANY_BACKGROUND_MAX_BYTES` | no, default 2 MiB | v0.14.0 | `.env` | Cap on a client company sign-in background. |

### Removed

Kept so an old compose file can still be read against this page. The server ignores them; delete them from the compose files.

| Variable | Required | Added in | Where set | Purpose |
| --- | --- | --- | --- | --- |
| <a id="var-google-oauth-client-id"></a>`GOOGLE_OAUTH_CLIENT_ID` | no | v0.2.0; removed in v0.14.0 | nowhere | Client id of the retired Google sign-in routes (PMS-837). |
| <a id="var-google-oauth-client-secret"></a>`GOOGLE_OAUTH_CLIENT_SECRET` | no | v0.2.0; removed in v0.14.0 | nowhere | Client secret of the retired Google sign-in routes (PMS-837). |
| <a id="var-google-oauth-redirect-uri"></a>`GOOGLE_OAUTH_REDIRECT_URI` | no | v0.2.0; removed in v0.14.0 | nowhere | Redirect URI of the retired Google sign-in routes (PMS-837). |
| <a id="var-oauth-super-admin-emails"></a>`OAUTH_SUPER_ADMIN_EMAILS` | no | v0.3.0; removed in v0.14.0 | nowhere | Super-admin allowlist only the retired Google sign-in read (PMS-837). |

## Development stack variables

These configure the dev compose stack, not the server, so they carry no Required or Added in facts.

| Variable | Where set | Purpose |
| --- | --- | --- |
| `MOKOSH_PG_DB`, `MOKOSH_PG_USER`, `MOKOSH_PG_PASSWORD` | `.env` | Database name and the superuser the `postgres` service is initialized with. The password is generated per clone. |
| `MOKOSH_PG_HOST_PORT` | `.env` | Loopback port the `postgres` service is published on, default `5433`. `DATABASE_URL`, `MOKOSH_ADMIN_DATABASE_URL` and `MOKOSH_APP_DATABASE_URL` interpolate it (PMS-1376), so moving it moves every host-side connection; a URL left on the old port reaches another checkout's database on a shared host. |
| `MOKOSH_MAILPIT_SMTP_HOST_PORT`, `MOKOSH_MAILPIT_WEB_HOST_PORT`, `MOKOSH_INFISICAL_HOST_PORT`, `MOKOSH_MINIO_API_HOST_PORT`, `MOKOSH_MINIO_CONSOLE_HOST_PORT` | `.env` | The other loopback host ports (PMS-900), defaults `1025`, `8025`, `28002`, `29000`, `29001`, so two checkouts on one box do not collide. Changing `MOKOSH_INFISICAL_HOST_PORT` means changing `INFISICAL_URL` and `INFISICAL_SITE_URL` with it. |
| `MOKOSH_PORT` | `.env` | Port the server listens on inside its container, handed to it as `PORT`. Default `8080`. |
| `USER` | written to `.env` by `just dev` | Names the per-developer containers, volumes, networks and the `${USER}-mokosh-api.a8n.run` route. No service publishes on a LAN address (PMS-496, PMS-863). |
| `MOKOSH_SERVER_INFISICAL_ADDRESS` | written to `.env` by `just dev-infisical` | In-network Infisical URL handed to the server as `INFISICAL_ADDRESS`; empty on a plain `just dev`. |
| `INFISICAL_URL` | `.env` | Host-side URL of the dev Infisical, read by the bootstrap CLI on the host. Default `http://localhost:28002`. |
| `INFISICAL_*` (the sidecar's own settings) | `.env` | Infisical server configuration for the opt-in `infisical` profile. |
| `MINIO_ROOT_USER`, `MINIO_ROOT_PASSWORD` | `.env` | The dev MinIO's credential, which `just dev-s3` copies into the blank `STORAGE_S3_*` keys. |

`compose.dev.yml` references every value via `${VAR}` substitution and contains no hardcoded secrets. Required vars use `${VAR:?...}` so compose fails loudly when a value is missing.

## Storage layout

Every stored object lives under one root: `STORAGE_ROOT` when `STORAGE_PROVIDER` is `local`, the bucket when it is `s3`. The path below the root is the same string either way, so moving a deployment between the two is a copy and not a re-layout.

**Tenant isolation is a property of the path, not only of the database.** An object's path begins with the id of the tenant that owns it, so one tenant's files occupy one directory and a per-tenant bucket, quota, export or provider migration has a prefix to be built on. That is also why directories were chosen over a bucket per tenant: a directory moves to another provider by copying a prefix, and bucket-per-tenant runs into provider account limits.

| Path | What it is |
|---|---|
| `{tenant}/{id}` | a file attached to a ticket or a ticket note |
| `{tenant}/logo.{ext}` | the tenant's live logo, overwritten on replace |
| `{tenant}/kb-articles/{id}` | an image embedded in a knowledge base article |
| `{tenant}/documents/{id}` | an invoice or credit-note PDF, as it was issued |
| `{tenant}/branding/{digest}` | a logo frozen onto a sent invoice, content-addressed |
| `{tenant}/contact-imports/{id}` | an uploaded `.vcf`, held until the import that reads it ends |

`{tenant}/logo.{ext}` and `{tenant}/branding/{digest}` are deliberately different directories: the first is one mutable object per tenant, the second holds the immutable copies frozen onto documents, one per distinct logo rather than one per invoice.

### Paths that do not yet begin with their tenant

Two kinds of path are exceptions, and an operator reading a volume will see both.

**Old locations, read-only.** A knowledge base image written before the layout change is at `kb-articles/{id}`, and a tenant logo written before it is at `tenant-logos/{tenant}.{ext}`. Both are still served, and a one-shot pass at each server start walks them to the paths above; once it has, neither directory refills. Nothing writes to them.

**Branding assets other than the tenant logo**, which are still on a shared directory per kind and are the subject of PMS-1397:

| Path | What it is |
|---|---|
| `tenant-favicons/{tenant}.{ext}` | the tenant's favicon |
| `tenant-backgrounds/{tenant}.{ext}` | the tenant's sign-in background |
| `company-logos/{company}.{ext}` | a client company's logo |
| `company-favicons/{company}.{ext}` | a client company's favicon |
| `company-backgrounds/{company}.{ext}` | a client company's sign-in background |

These are listed rather than left to be discovered, because the point of documenting a layout is that it is the real one. The three `company-*` directories carry no tenant at all. That is not a way for one tenant to read another's file through the API - the routes that serve these are deliberately public, with the id as the credential, so no tenant-scoped key is presented in the first place - but it does mean those five cannot be moved, quota-limited or exported per tenant until PMS-1397 lands.

`crate::storage` is the only place any of this is decided, with `src/modules/branding/assets.rs` holding the five above. A caller is handed a tenant and an object identity and never a path, so a new kind of stored object cannot invent its own layout, and `storage::tests::every_object_kind_puts_its_tenant_first` fails the build if one is added without its tenant in front.
