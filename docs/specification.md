# mokosh-server specification

This document describes mokosh-server as implemented in the source tree: the crate manifests, `src/main.rs`, the router in
`src/api/router.rs`, the modules under `src/modules/`, the SQL files in `migrations/`, configuration loading in
`src/config/`, and the container build in `oci-build/Dockerfile`. Where a statement here and another document disagree,
the code is authoritative.

## 1. Purpose and scope

mokosh-server is the API server of a professional services automation (PSA) platform for managed service providers
(MSPs). It is a multi-tenant JSON-over-HTTP service backed by PostgreSQL. Each tenant is one MSP organization. The
users are the MSP's staff (administrators, managers, technicians, dispatchers, sales, finance), the MSP's client
contacts (through a separate contact portal plane), and platform administrators who operate the deployment.

It provides: service desk ticketing with SLAs and workflow rules; time tracking and timesheets; projects; calendar and
dispatch; contracts and rate cards; invoicing, quotes, credit notes, payments and expenses; assets and documentation; a
knowledge base; client company and contact management; notifications; reporting; and integrations with payment
processors, accounting systems, RMM tools, contact directories, an OIDC identity provider and object storage.

It does not serve a user interface. Any path that matches no route answers `404` with a small HTML page stating that
the host is an API endpoint (`not_a_frontend` in `src/api/router.rs`). The browser client is a separate repository that
shares the data-transfer types in the workspace crate `crates/mokosh-types`. Identity provisioning for the hosted
deployment profile is delegated to an external OIDC provider referred to in this document as the identity provider
(the `bunyip` provider name and `BUNYIP_*` variables in the code).

## 2. Architecture

### 2.1 Workspace

| Member | Kind | Role |
|---|---|---|
| `mokosh-server` (root package) | library `mokosh_server` plus binaries `mokosh-server` and `mokosh-bootstrap` | The application. Cargo features `multi-tenant` and `server` are both on by default. |
| `crates/mokosh-types` | library | Wire types shared with the browser client: auth, billing, contacts, forms, integrations, members, mileage, tenants, tickets, time tracking, sorting and validation helpers. |
| `crates/build-metadata` | library | Build-script logic called from the root `build.rs`; supplies the version banner data (git hash, describe string, build date). |
| `crates/mokosh-test-macros`, `crates/mokosh-test` | proc-macro and library | Test support only: the `#[mokosh_test]` attribute clones each test's database from one migrated template database. Dev-dependencies of the root package. |

Rust edition 2021; the toolchain is pinned in `rust-toolchain.toml` (channel `1.98.1`, with clippy and rustfmt).

### 2.2 Technology stack

- HTTP: axum 0.8 on tokio, tower and tower-http (CORS, tracing, gzip and brotli compression).
- Database: PostgreSQL through sqlx 0.8 (`runtime-tokio`, `postgres`, `migrate`); money values use `rust_decimal`.
- Authentication: `jsonwebtoken` (HS256 for server-issued tokens, asymmetric algorithms for identity-provider tokens),
  `argon2` for password and token hashing, `zxcvbn` for password strength, RFC 6238 TOTP built on `hmac` and `sha1`.
- Encryption and signatures: `aes-gcm` (AES-256-GCM) for secrets at rest, `hmac`, `sha2` and `constant_time_eq` for
  webhook signatures.
- Outbound: `reqwest` with rustls, `lettre` for SMTP (native TLS, pooled), a hand-written SigV4 signer for S3 storage,
  `quick-xml` for CardDAV responses, `calcard` for vCard parsing.
- Documents: `printpdf` renders PDFs for invoices, quotes, credit notes and statements (embedded Noto Sans fonts).
  `minijinja` renders knowledge-base templates. `rrule` expands recurring appointments at read time.
- Operations: `governor` for rate limiting, `moka` for caches, `ip2location` and a shared IP-enrichment crate for
  IP geolocation and proxy enrichment, `tracing` with `tracing-subscriber` for logs.
- Three shared first-party crates are git dependencies pinned by revision: Stripe signature verification and event
  parsing, IP enrichment, and the provider status report contract.

### 2.3 Runtime shape

`mokosh-server` is one long-running process. `src/main.rs` runs, in order:

1. If `argv[1]` names an operator subcommand (section 4.2), run it and exit.
2. Initialise `tracing` with `RUST_LOG` (default filter `info`), load a `.env` file, read the hosting profile
   (`MOKOSH_DEPLOYMENT_MODE`), and refuse to boot if a retired storage variable name is set.
3. Select the configuration provider and resolve every declared configuration key into one generation.
4. Build `AppConfig`; refuse to boot outside development/test if the essential deployment variables are unset or the
   secrets are weak (section 6.1).
5. Provision the two database roles if the migrator role cannot yet log in (needs `MOKOSH_ADMIN_DATABASE_URL`), open
   the two connection pools, and run migrations when `RUN_MIGRATIONS` is true (the default). A migration failure ends
   startup with a non-zero exit.
6. Create the first platform administrator when `ADMIN_EMAIL` and `ADMIN_PASSWORD` are set and no platform admin
   exists. A failure here is logged as a warning and boot continues.
7. Initialise the application-tier secret providers, the deployment's OAuth client pairs (Google, Microsoft, Xero,
   Intuit), the cached product name, the mailer (the transport is verified at boot and a failure ends startup), the
   identity-provider token verifier, and the authentication provider chain.
8. Start the background scheduler (section 2.5), spawn the one-shot data movers, load the optional IP databases.
9. Build the router and serve it on `HOST:PORT` (defaults `0.0.0.0:8080`) with client connect info. There is no
   graceful-shutdown handler.

### 2.4 Request pipeline

Top-level router, outermost layer first: security headers, CORS, response compression, request tracing, JSON body
sanitising. The JSON sanitiser (`src/utils/text.rs`) cleans string values in JSON request bodies and forwards the parsed
tree to the `Json` extractor; it skips non-JSON bodies, bodies over 25 MiB, and the signature-verified prefixes
`/api/v1/bunyip/`, `/api/v1/rmm/alerts`, `/api/v1/rmm/status`, `/api/v1/stripe/`, `/api/v1/paypal/` and
`/api/v1/webhooks/`, whose bytes must reach the handler unchanged.

Route trees mounted by `create_api_router`:

| Mount | Contents | Layers |
|---|---|---|
| `/api/v1` | Staff API | error-envelope normaliser, shared extensions, contact-token middleware, staff auth middleware, first-visit demo seeding |
| `/api/v1/public` | Unauthenticated endpoints | per-IP rate limit (60 per minute), error-envelope normaliser |
| `/api/v1/contact` | Contact portal API | contact-token middleware, error-envelope normaliser |
| `/api/v1/bunyip` | Identity-provider webhooks and back-channel logout | error-envelope normaliser |
| `/api/v1/stripe`, `/api/v1/paypal`, `/api/v1/webhooks` | Payment and accounting webhooks | error-envelope normaliser |

Authentication is performed by middleware, which only records an `AuthState` in the request extensions. A route is
protected by declaring an extractor in the handler signature (`RequireAuth`, `RequireAdmin`, `RequireManager`,
`RequireFinance`, `RequireSuperAdmin`, the per-module gates, `DeploymentOperator`, `RequirePlatformAdmin`,
`RequireContactAuth`). A handler with none of these is open.

Tenant isolation: services open work with `Database::begin_with_tenant(tenant_id)`, which starts a transaction on the
request-serving pool and sets `app.current_tenant` for that transaction. Row level security policies read that setting
(section 5.2).

Errors: every failure is an `AppError` rendered as a JSON envelope `{"error": {"code", "message", "errors"?}}`. The
`normalize_error_envelope` layer rewrites plain-text extractor rejections into the same envelope. Rate-limit
rejections answer `429` with `Retry-After`. A deleted account answers `410` with code `ACCOUNT_DELETED`. An expired
token answers `401` with a `WWW-Authenticate: Bearer` challenge that distinguishes expired, invalid and ended-session
credentials.

### 2.5 Background jobs

All periodic jobs run on the shared scheduler (`src/scheduler/mod.rs`): one tokio task per job, fixed interval, missed
ticks skipped, the first tick fires immediately at startup, tick errors are logged at `warn` and the loop continues.

| Job | Interval | Behaviour |
|---|---|---|
| Notification dispatcher | 5 s | Drains pending `notifications` rows with `SKIP LOCKED`; delivers `in_app` and `email`; any other channel is marked failed with "no transport registered". |
| RMM sync | 60 s | For each active RMM connection past its sync interval, pulls devices, upserts device mappings and assets, records `sync_status` and `last_error`. |
| Contact sync runner | 60 s (also woken on demand) | Executes queued contact import runs. |
| SLA sweep | 60 s | Enqueues at-risk and breach notifications once per milestone (ledger `sla_notifications`). |
| Calendar reminders | 60 s | Sends appointment reminders. |
| Scheduled reports, scheduled dashboards | 60 s each | Run cron-scheduled saved reports and dashboards and email the recipient. |
| Feature-toggle refresh, asset signature detector refresh | 60 s each | Reload in-memory snapshots from the database. |
| Contract lifecycle | 1 h | Renews (when `auto_renew`) or expires active contracts past `end_date`. |
| Recurring invoicing | 1 h | Creates one draft invoice per due billing period of each active recurring contract, idempotent through `contract_invoice_runs`. |
| Invoice reminders | 1 h | Sends invoice reminders. |
| Grant invitation expiry sweep | 1 h | Expires stale grant invitations. |
| Status retention | 6 h | Prunes old status observations. |

One-shot tasks started at boot (`scheduler/one_shot.rs`): move knowledge-base attachments, tenant logos, branding assets
and payment-gateway credentials to their current storage layout, and clean up a retired Google client secret.

### 2.6 Provider seams

Five capabilities are selected by name and resolved once at boot (`src/utils/deployment.rs`). Defaults come from the
hosting profile set by `MOKOSH_DEPLOYMENT_MODE` (`self-hosted` or `saas`):

| Capability | Providers | self-hosted default | saas default |
|---|---|---|---|
| Configuration | `environment` | `environment` | `environment` |
| Tenant secrets | `database`, `infisical` | `database` | `database` |
| Authentication | `local`, `bunyip` | `local` | `bunyip`, `local` |
| Email | `log`, `smtp`, `bunyip` | `log` | `smtp` |
| Object storage | `local`, `s3` | `local` | `local` |

Further seams: application-tier secrets (`APP_SECRET_BACKEND`: `environment`, `file`, `database`, `infisical`, `bunyip`),
and the payment provider interface (`stripe`, `paypal`). An unrecognised provider name ends startup naming the legal
values. The configuration seam also contains `file`, `database` and `bunyip` providers, which only the operator CLI
chain builder (`CONFIG_PROVIDERS`) constructs; the server process itself reads configuration from `environment`.

## 3. Providers and secrets

A provider is one implementation of a capability the application needs; a kind groups the providers that implement
one trait. `docs/providers.md` is the contract for the model itself (tiers, priority, the boot classification, the
migrate/purge CLI shape); this section states what the code in `src/app_secrets/`, `src/secrets/`, `src/infisical/`,
`src/storage/`, `src/providers/`, `src/cli/` and `src/bin/mokosh-bootstrap.rs` actually does, in normative,
per-requirement form. A requirement here is enforced at the `// SPEC-3.<n>` comment the id's own text names; where no
single site enforces it (a cross-cutting rule, or a rule that is the absence of a thing), the requirement names the
file and the id is not cited inline.

### 3.1 Application-tier secrets (src/app_secrets/)

An application-tier secret belongs to the whole deployment, not to a tenant. It is read through `AppSecrets`, never
through a provider directly, and resolves from exactly one provider per secret.

- **SPEC-3.1**: `GovernedSecret` declares exactly 11 variants (`SmtpPassword` and five client-id/client-secret pairs:
  Google, Microsoft, Xero, QuickBooks, plus the standalone `XeroWebhookKey` and `QuickbooksVerifierToken`); a pair
  joins the registry as two independent variants, each resolving from its own provider, so a half-configured pair is
  a boot error naming the missing half rather than a silently incomplete credential (src/app_secrets/mod.rs).
- **SPEC-3.2**: `GovernedSecret::parse_name` matches case-insensitively against `GovernedSecret::ALL` and rejects any
  other input with an error naming every legal value; it never falls back to a default (src/app_secrets/mod.rs).
- **SPEC-3.3**: `AppSecretProviderKind` has exactly 5 variants (`environment`, `file`, `database`, `infisical`,
  `bunyip`); `AppSecretsSelection::from_env` is the sole reader of `APP_SECRET_BACKEND`, independent of the tenant
  tier's `SECRET_BACKEND` (split by PMS-1424 because the tenant tier accepts only write-capable providers); a blank
  value takes the hosting profile's default, a set value is parsed strictly, and an unrecognised value is a hard
  error naming the legal list rather than a fallback (src/app_secrets/mod.rs).
- **SPEC-3.4**: `classify_built` returns exactly one of five classifications per secret: `Used` (declared provider
  holds it, nothing else does), `Missing` (no built provider holds it), `Shadowed` (the declared provider holds it
  and at least one other built provider also does), `Misplaced` (the declared provider does not hold it but another
  built provider does), or `Unavailable` (the declared provider could not be built at all, distinct from a built
  provider answering "no value"); `enforce` logs `Used` and `Shadowed` at info/warn, logs `Missing` at warn with the
  secret's `feature()` sentence, and returns `AppError::Configuration` naming the secret and provider for `Misplaced`
  and `Unavailable`, which fails process boot (src/app_secrets/mod.rs).
- **SPEC-3.5**: `AppSecrets::declared_for` resolves a secret's serving provider from its own per-secret declaration
  first (PMS-1537, e.g. the Google OAuth pair declared to `bunyip`), falling back to the process-wide declared
  provider only when the secret has no declaration of its own (src/app_secrets/mod.rs).
- **SPEC-3.6**: `init_from_env` builds the environment provider unconditionally, the file provider only when
  `APP_SECRETS_DIR` resolves to a non-empty value, the database provider unconditionally, the Infisical provider only
  when `INFISICAL_ADDRESS` resolves to a non-empty value, and the bunyip provider only when
  `BunyipSecretsConfig::from_env` returns `Ok(Some(_))`; it then runs the full survey and `enforce`, so a `Misplaced`
  or `Unavailable` secret stops boot (src/app_secrets/mod.rs).
- **SPEC-3.7**: the environment provider (`EnvironmentProvider`) reads only `{NAME}_FILE`, never the plain variable
  of the same name; a blank path, a missing file, or a file whose trimmed contents are empty all read as unheld; an
  unreadable path is logged at `error` and also reads as unheld; the provider is read-only (src/app_secrets/env.rs).
- **SPEC-3.8**: the file provider (`FileProvider`) reads `{APP_SECRETS_DIR}/{secret.secret_file()}`; a missing
  directory or a missing file inside an existing directory both read as unheld silently, while an existing but
  unreadable file is logged at `error`; `set` writes the file (creating it if absent) and `delete` treats an
  already-absent file as success (src/app_secrets/file.rs).
- **SPEC-3.9**: the database provider (`DatabaseProvider`) loads every `GovernedSecret` row once at construction into
  an in-memory cache guarded by a `RwLock` and never re-queries the database on `get`/`has`; a row that fails to
  decrypt, or that decrypts to an empty string, is treated as unheld rather than as a load failure; a row named
  something outside `GovernedSecret::ALL` is skipped with a `warn` log (src/app_secrets/database.rs).
- **SPEC-3.10**: the database provider's `set` encrypts with AES-256-GCM and upserts via
  `ON CONFLICT (name) DO UPDATE`, updating the in-memory cache only after the write succeeds, so a failed write
  leaves the prior cached value serving; `delete` is idempotent (src/app_secrets/database.rs).
- **SPEC-3.11**: the database provider's writes and its initial load both use the privileged migrator pool, never
  the tenant-scoped request pool, because `app_secrets` carries no row-level security and no tenant GUC
  (src/app_secrets/database.rs).
- **SPEC-3.12**: `BunyipSecretsConfig::from_env` returns `Ok(None)` when `BUNYIP_SECRETS_URL` is blank; when the URL
  is set but either `BUNYIP_SECRETS_CLIENT_ID` or `BUNYIP_SECRETS_CLIENT_SECRET` is blank, it returns
  `AppError::Configuration` naming both required variables and the `bunyip-api machine-client register` remedy
  (src/app_secrets/bunyip.rs).
- **SPEC-3.13**: `BunyipProvider::load` fetches exactly one bunyip key, `mokosh/google_oauth_client`, once, via
  `GET {base_url}/v1/host/secrets/{key}` with HTTP Basic auth; the response's `data.value` is itself a JSON string
  that must parse into a `{client_id, client_secret}` pair, and a parse failure at either JSON layer is a fatal
  configuration error naming the key; HTTP 401, 403 and 404 each produce a distinct remedy message, and any other
  non-success status produces a generic message naming the status and body (src/app_secrets/bunyip.rs).
- **SPEC-3.14**: `BunyipProvider` answers only for `GoogleContactsClientId` and `GoogleContactsClientSecret`; every
  other `GovernedSecret` reads as unheld from it; it is read-only, and its `Debug` implementation prints only the
  count of secrets held, never a value (src/app_secrets/bunyip.rs).
- **SPEC-3.15**: the application-tier Infisical provider (`InfisicalProvider`) reads from the fixed folder `/app`,
  distinct from the tenant tier's `/mokosh/integrations`, so the two tiers cannot collide inside one Infisical
  project; it fetches every governed secret once at `load()`, treating a 404 as unheld and any other network or
  auth failure during load as a fatal boot error (src/app_secrets/infisical.rs).

### 3.2 Tenant-tier secrets (src/secrets/)

A tenant-tier secret belongs to one MSP tenant: a payment-gateway credential, a contact-sync connection's token.

- **SPEC-3.16**: `SecretKey` is constructible only through its named constructors (`contact_sync`, `oauth_client`,
  `integration`, `payment_gateway`), each of which takes a tenant id that is never part of `SecretKind`, so a key
  cannot be built that omits its tenant; `SecretKey::name()` renders as exactly
  `{KIND_PREFIX}__{tenant_uuid.simple()}__{DISCRIMINATOR_UPPER}`, a format both the `secrets` table row name and the
  Infisical secret name depend on (src/secrets/mod.rs).
- **SPEC-3.17**: `validate_discriminator` rejects a discriminator that is empty, longer than 48 bytes, or contains
  anything other than lowercase ASCII letters, digits or underscore, which is what stops a crafted value from
  injecting a path or name into the stored key (src/secrets/mod.rs).
- **SPEC-3.18**: a `ContactSync` key's discriminator is `{provider}_{connection_id.simple()}`, so two sync
  connections for the same provider under the same tenant never share a secret name (src/secrets/mod.rs).
- **SPEC-3.19**: `SecretProvider::get` returns `Ok(None)` to mean "not configured" and `Err` to mean "provider
  unreachable"; the two must never collapse into each other, and `put_if_absent` returns `true` only when its own
  call performed the write, `false` when a value already existed, which is the compare-and-set contract a
  gateway-credential move depends on; `delete` of an already-absent secret is not an error (src/secrets/mod.rs).
- **SPEC-3.20**: `SecretProviderKind::parse_name` accepts only `database` and `infisical`; a name that is valid for
  the application tier only (`file`, `environment`, `bunyip`) produces a distinct error naming `APP_SECRET_BACKEND`
  as the variable that would have accepted it, separate from the generic "not a known provider" error for an
  unrelated typo; a blank value is never a legal input to this function, since the caller resolves blank against the
  hosting profile's default before calling it (src/secrets/mod.rs).
- **SPEC-3.21**: `SecretsConfig::from_env` is the sole reader of `SECRET_BACKEND` for the tenant tier
  (src/secrets/mod.rs).
- **SPEC-3.22**: the database tenant-secrets provider runs every `get`/`put`/`put_if_absent`/`delete` inside a
  transaction opened with `begin_with_tenant(key.tenant_id())`, so row-level security independently confines the row
  to its tenant; `put` is an upsert, `put_if_absent` is `ON CONFLICT (tenant_id, name) DO NOTHING RETURNING 1`
  returning `true` iff this call inserted the row, and `delete` treats zero rows affected as success
  (src/secrets/database.rs).
- **SPEC-3.23**: the Infisical tenant-secrets provider reads and writes under the fixed folder
  `/mokosh/integrations`; `InfisicalSecretsConfig::from_env` requires `INFISICAL_ADDRESS`, `INFISICAL_PROJECT_ID`,
  `INFISICAL_CLIENT_ID` and `INFISICAL_CLIENT_SECRET` (blank counts as missing), and `INFISICAL_ENVIRONMENT`
  defaults to `dev` when unset or blank (src/secrets/infisical.rs).
- **SPEC-3.24**: the Infisical tenant-secrets provider caches both a present value and a confirmed absence for a
  fixed 5-minute TTL keyed by secret name; a cache miss (including an expired entry) that also fails at the network
  level is always `Err`, never collapsed into `Ok(None)`, so an Infisical outage surfaces as an error on every read
  rather than reading as "not configured" (src/secrets/infisical.rs).
- **SPEC-3.25**: `put`/`delete` on the Infisical tenant-secrets provider write through to Infisical first, then
  invalidate (never update in place) the cache entry for that name; `put_if_absent` bypasses the cache entirely for
  its existence check, making it a check-then-act rather than a true atomic compare-and-set, since Infisical exposes
  no create-only write (src/secrets/infisical.rs).

### 3.3 Infisical client and first-run bootstrap (src/infisical/)

- **SPEC-3.26**: `InfisicalClient::new`/`connect` perform no network I/O and do not authenticate at construction;
  authentication happens lazily on the first API call, and the underlying HTTP client is built with a 30-second
  request timeout (src/infisical/client.rs).
- **SPEC-3.27**: `base_url` has any trailing `/` stripped exactly once at construction, so route building never
  produces a double slash (src/infisical/client.rs).
- **SPEC-3.28**: Universal Auth login POSTs `{base_url}/api/v1/auth/universal-auth/login` with
  `Content-Type: application/x-www-form-urlencoded` and a `clientId=<urlencoded>&clientSecret=<urlencoded>` body,
  never a JSON body; a non-2xx response produces the error text
  `"Infisical authentication failed ({status}): {body}"` (src/infisical/client.rs).
- **SPEC-3.29**: a cached access token is treated as invalid, and refreshed, once `now + 300s >= expires_at`, i.e.
  5 minutes before its stated expiry rather than at exact expiry; `ensure_authenticated` checks validity under a
  read lock first and re-checks after acquiring the write lock, so two concurrent callers never both re-authenticate
  when one caller's read-lock check already found a valid token (src/infisical/client.rs).
- **SPEC-3.30**: `send_with_retry` retries a request exactly once, and only when the first attempt returns HTTP 401:
  it clears the cached token, re-authenticates, and resends the identical request; a 401 on the retry is not retried
  again and falls through to the normal error path (src/infisical/client.rs).
- **SPEC-3.31**: `check_response` classifies a non-success status as exactly one of: 401 clears the cached token and
  returns the fixed text `"Infisical authentication failed"` with no body echoed; 403 returns
  `"Infisical access denied: insufficient permissions"`; 404 returns `AppError::NotFound` naming the resource; any
  other status returns `AppError::external_service` naming the status and body (src/infisical/client.rs).
- **SPEC-3.32**: `get_secret` treats HTTP 404 as `Ok(None)` and propagates every other failure as `Err`, so an
  unreachable Infisical is never silently read as an absent secret; `put_secret` attempts `PATCH` first and falls
  back to `POST` only on `AppError::NotFound`, an ordering that must not be reversed; `delete_secret` treats
  `AppError::NotFound` as success (src/infisical/client.rs).
- **SPEC-3.33**: `InfisicalClient`'s `Debug` implementation redacts `client_secret` as the literal string
  `"[REDACTED]"` and no logging call in this file (`debug!`/`info!`/`warn!`) ever includes the client secret or a
  bearer token value (src/infisical/client.rs).
- **SPEC-3.34**: `bootstrap_infisical` performs its setup against a fresh Infisical instance as 7 numbered API calls
  in this exact order: admin signup, select-organization, create project, create machine identity, promote
  membership to admin, attach Universal Auth, create client secret; one of these steps (folder pre-creation, see
  SPEC-3.35) issues additional calls not counted in that number (src/infisical/bootstrap.rs).
- **SPEC-3.35**: folder pre-creation runs between project creation and identity creation, using the org-scoped admin
  token, because the Universal Auth identity created afterward has secret-write permission but not folder-create
  permission; the folders created are exactly `/` to `mokosh`, `/mokosh` to `tenants`, `/mokosh` to `integrations`,
  in that order; a folder-create call whose error text contains `"already exists"` or `"409"` is treated as success,
  making the step idempotent on a partially set up project (src/infisical/bootstrap.rs).
- **SPEC-3.36**: every bootstrap HTTP request sends the fixed header `User-Agent: mokosh-bootstrap/{CARGO_PKG_VERSION}`,
  because Infisical rejects some endpoints (at least `select-organization`) with a 401 "User-Agent header is
  required" when it is absent (src/infisical/bootstrap.rs).
- **SPEC-3.37**: the Universal Auth attach call sets both `clientSecretTrustedIps` and `accessTokenTrustedIps` to the
  CIDR `0.0.0.0/0`, never the bare IP `0.0.0.0`, because a bare IP is read as `/32` and trips Infisical's paid-plan
  IP-restriction feature; it requests an access token TTL and max TTL of 2,592,000 seconds (30 days) with no use-limit
  (src/infisical/bootstrap.rs).
- **SPEC-3.38**: membership promotion to admin runs before the Universal Auth attach and client-secret creation
  steps; skipping it would make every runtime secret-write call fail with 403, since the default role grants nothing
  (src/infisical/bootstrap.rs).
- **SPEC-3.39**: `BootstrapInput.environment_slug`, when `None`, defaults to the literal `"dev"` for both the
  returned `BootstrapOutput.environment` and the folder-creation calls (src/infisical/bootstrap.rs).
- **SPEC-3.40**: `run_dev_bootstrap` writes exactly 6 keys into the target `.env`-style file
  (`INFISICAL_PROJECT_ID`, `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET`, `INFISICAL_ENVIRONMENT`,
  `INFISICAL_ADMIN_EMAIL`, `INFISICAL_ADMIN_PASSWORD`) and must never write `INFISICAL_ADDRESS`, because the
  host-reachable URL used by the CLI differs from the in-network URL the server container uses, and the latter is
  expected to already exist in the generated `.env` (src/infisical/dev.rs).
- **SPEC-3.41**: `upsert_env_file` preserves every existing line verbatim except a line whose key (the substring up
  to the first `=`) exactly matches one of the keys being written, which is replaced in place; a key that matches no
  existing line is appended at the end; a line is never matched inside a comment (trimmed content starting with `#`)
  or a blank line; the file always ends with a trailing newline, and a non-existent target file is created rather
  than treated as an error (src/infisical/dev.rs).

### 3.4 Object storage (src/storage/)

- **SPEC-3.42**: every `ObjectKey::relative_path()` puts the tenant id as the first path component, except the two
  `Legacy*` `ObjectKind` variants, which must not, because they address pre-existing layouts from before tenant
  scoping was added (src/storage/mod.rs).
- **SPEC-3.43**: a file-extension segment (`TenantLogo`/`LegacyTenantLogo`) must be 1-16 ASCII alphanumeric or `-`
  characters or the request is rejected as bad input; a digest segment (`BrandingLogo`) must be exactly 64 ASCII hex
  characters or the request is rejected as an internal error, since a malformed digest there can only come from a
  bug or an attack, not user input (src/storage/mod.rs).
- **SPEC-3.44**: `LocalProvider::read` on a missing object returns `AppError::NotFound`; `LocalProvider::open` on the
  same missing-object condition returns `AppError::Internal`; callers that need the legacy-path fallback behavior
  use `read`, and the asymmetry between the two methods is deliberate, not a bug to unify (src/storage/mod.rs).
- **SPEC-3.45**: `LocalProvider::delete` is best-effort: a missing file is swallowed and reports success, since every
  caller has already deleted the owning database row first; `LocalProvider::rename` is not best-effort and a missing
  source is a hard `AppError::Internal`, because the caller has just established the source exists and a silent
  success would wrongly mark an object as migrated (src/storage/mod.rs).
- **SPEC-3.46**: `StorageProviderKind::parse` accepts only `local` or `s3` and otherwise returns
  `AppError::Configuration` naming the bad value, never falling back to `local`; `resolve` takes the hosting
  profile's default only when the input is blank, and an unparseable non-blank value is always a hard error, never a
  silent fallback (src/storage/mod.rs).
- **SPEC-3.47**: `storage::shared()` builds the process-wide provider exactly once behind a `OnceLock`; on a path
  that never called `init_from_env` first (test or CLI code), a build failure there panics rather than returning an
  error, because there is no request or startup caller to answer with one (src/storage/mod.rs).
- **SPEC-3.48**: `DEFAULT_ROOT` (`./attachments`) must remain a relative path, never an absolute one, because the
  container image's working directory and non-root user depend on relativity (src/storage/mod.rs).
- **SPEC-3.49**: `Retention` is declared per `ObjectKind` (`WhileReferenced`, or `Years(7)` for `FinancialDocument`)
  and is not enforced by any reaper; the test suite fails the moment a sweep/expire function appears, so this
  requirement states the current, deliberately advisory-only state (src/storage/mod.rs).
- **SPEC-3.50**: every storage configuration variable name is `STORAGE_`-prefixed and declared centrally; as of
  PMS-1443 the previously-deprecated aliases (`STORAGE_BACKEND`, `ATTACHMENT_DIR`, bare `S3_*`) no longer supply a
  value at all, and `check_boot_env` instead refuses to boot if any of them is set to a non-blank value, naming every
  retired-to-replacement pair at once; a forwarded-but-blank variable is treated as unset by both checks
  (src/storage/env.rs).
- **SPEC-3.51**: `STORAGE_S3_ACCESS_KEY_ID` and `STORAGE_S3_SECRET_ACCESS_KEY` are the only two storage settings
  marked secret, and `supplied_by()` reports only which variable name supplied a setting, never its value, so
  `provider-status` cannot leak a credential through this path (src/storage/env.rs).
- **SPEC-3.52**: `FileLedger::record`/`record_in_tx` upsert (`ON CONFLICT (id) DO UPDATE`) rather than insert-only,
  because a tenant logo is written to the same row id on every replace; `record_in_tx` runs inside the caller's own
  transaction when storing a financial document, so the ledger row and the issuing transaction commit or roll back
  together (src/storage/ledger.rs).
- **SPEC-3.53**: `FileLedger::forget` is best-effort: a failure to remove a ledger row for an object whose blob
  delete may already have failed does not fail the caller's request (src/storage/ledger.rs).
- **SPEC-3.54**: `S3Config::parse` requires `STORAGE_S3_ENDPOINT`, `STORAGE_S3_BUCKET`, `STORAGE_S3_ACCESS_KEY_ID`
  and `STORAGE_S3_SECRET_ACCESS_KEY` to each resolve to a non-blank value, naming the specific missing variable
  otherwise; the endpoint must parse as an `http`/`https` URL with a host and no query string or fragment;
  `STORAGE_S3_PATH_STYLE` accepts only the literals `true`/`1`/`yes` or `false`/`0`/`no` (any other non-empty value
  is a hard error); the bucket name must satisfy S3's naming rules (length 3-63, lowercase ascii/digit/`-`/`.`, no
  leading/trailing `-`/`.`, no `..`) (src/storage/s3.rs).
- **SPEC-3.55**: `S3Config`'s `Debug` implementation redacts `secret_access_key`; the HTTP client used for every S3
  request has a 10-second connect timeout and a 300-second total request timeout; every request is signed with
  SigV4 using the hand-rolled `sigv4` submodule (src/storage/s3.rs).
- **SPEC-3.56**: `S3Provider::read` maps HTTP 404 to `AppError::NotFound` (so a caller can fall back to a legacy
  path); `S3Provider::open` maps the identical HTTP 404 to `AppError::Internal`, mirroring the same asymmetry as the
  local provider (SPEC-3.44); `delete` treats `200`, `204` and `404` all as success (src/storage/s3.rs).
- **SPEC-3.57**: `S3Provider::rename` performs a server-side copy (`x-amz-copy-source`) and then deletes the source;
  an HTTP 200 copy response whose body contains the literal substring `<Error>` is still treated as a failure, since
  S3 can return 200 with an XML error body for a copy that started and then failed; a missing source at the copy
  step is a hard `AppError::Internal`, matching the local provider's non-best-effort rename rule (src/storage/s3.rs).
- **SPEC-3.58**: the configured S3 endpoint URL is not passed through the outbound-URL SSRF guard used elsewhere,
  because it is trusted operator configuration like `INFISICAL_ADDRESS`, and a private-network object store is the
  expected case rather than an attack (src/storage/s3.rs).

### 3.5 Provider status reporting (src/providers/)

- **SPEC-3.59**: `providers::status::collect()` is the single process-wide reader that builds one
  `ProviderKindReport` per kind for exactly six kinds, always in this fixed order: configuration, application
  secrets, tenant secrets, storage, authentication, email; it never calls a provider's value-returning accessor
  (`get`/`value`), only `has`/`served_by` (src/providers/status/mod.rs).
- **SPEC-3.60**: the report's `hosting_profile` field is always exactly the string `self-hosted` or `saas`, derived
  from the lenient (non-fatal) `DeploymentMode::from_env`, since a status report must render even when the value is
  unrecognised (src/providers/status/mod.rs).
- **SPEC-3.61**: for the configuration kind, `serving` is the first provider, in priority order, that `served_by`
  reports holding any registry key; `keys` comes exclusively from `config::check_staleness()`; `staleness_state_name`
  maps the four staleness states to exactly the wire strings `unchanged`, `appeared`, `disappeared` and
  `changed_provider` (src/providers/status/mod.rs).
- **SPEC-3.62**: for the application-secrets kind, when no process-wide `AppSecrets` has been initialized the report
  shows empty enabled/serving/keys rather than a fabricated shape; when initialized, `serving` is always
  `secrets.declared()`, the declared provider, independent of which providers were actually built
  (src/providers/status/mod.rs).
- **SPEC-3.63**: the tenant-secrets kind never enumerates per-key rows (`keys` is always empty), because enumerating
  a tenant secret would require a tenant scope the collector does not hold (src/providers/status/mod.rs).
- **SPEC-3.64**: the storage kind lists every variable in `storage_env::ALL` regardless of whether it is set, and
  never exposes the value of a storage variable, only which variable name supplied it and whether it is set
  (src/providers/status/mod.rs).
- **SPEC-3.65**: the authentication kind reports `local` as always reachable; `bunyip`'s reachability is
  approximated as "`OIDC_ISSUER` and `OIDC_AUDIENCE` are both non-empty," matching the verifier's own construction
  check, with a distinct reason string when not reachable (src/providers/status/mod.rs).
- **SPEC-3.66**: the email kind reads the selection recorded at boot first, so the report cannot disagree with what
  the process actually runs, and falls back to inferring from `SMTP_HOST` presence only when boot recorded nothing;
  neither path ever opens an SMTP connection (src/providers/status/mod.rs).
- **SPEC-3.67**: `collect_deviations` reports one deviation per kind whose resolved provider list differs from the
  hosting profile's default, naming both the profile default and the explicit list; identical lists produce zero
  deviations (src/providers/status/mod.rs).
- **SPEC-3.68**: `GenerationHeader.actor` renders as exactly the literal string `System` for a system-initiated
  refresh or `Operator(<login>)` for an operator-initiated one, never any credential material
  (src/providers/status/mod.rs).
- **SPEC-3.69**: the JSON and HTML renderings must name the exact same set of kind ids; the JSON envelope's top level
  is `{schema_version: "1", generated_at, report: {hosting_profile, kinds}}` (src/providers/status/renderer_json.rs,
  src/providers/status/mod.rs).
- **SPEC-3.70**: the HTML page declares `<meta name="robots" content="noindex">` and renders one `<section
  id="<kind>">` per kind; every dynamically inserted value passes through HTML escaping, so no raw markup from a
  provider name or reason string ever reaches the page unescaped (src/providers/status/renderer_html.rs).
- **SPEC-3.71**: `RequireAdminOrBunyipMachine` tries exactly two credential shapes in order: an HTTP Basic credential
  matching `BUNYIP_STATUS_CLIENT_ID`/`BUNYIP_STATUS_CLIENT_SECRET` compared in constant time, then a staff admin
  session; a Basic credential that does not match both halves is refused with 401 immediately and never falls
  through to the staff-session check even if a valid admin session is also present; when either configured
  credential variable is unset or empty, the machine path is disabled entirely and every request falls through to
  the staff-session check (src/providers/status/auth.rs).
- **SPEC-3.72**: a malformed `Authorization: Basic` header (bad base64, non-UTF-8, missing colon) is classified
  distinctly from a wrong credential and also falls through to the staff-session check, rather than being treated as
  a failed machine-credential attempt (src/providers/status/auth.rs).
- **SPEC-3.73**: the unauthenticated public summary (`summarize()`) exposes exactly five kinds -- configuration,
  application secrets, storage, authentication, email -- and permanently excludes tenant secrets, because a
  tenant-chosen provider has no single per-instance identity to report; for each exposed kind it carries only the
  list of enabled provider names, nothing else observable (src/providers/status/public_summary.rs).
- **SPEC-3.74**: every string leaf anywhere in the serialized public summary must be one of the hosting-profile
  strings, the schema version `"1"`, or one of the nine known short provider identifiers (`environment`, `file`,
  `database`, `bunyip`, `infisical`, `local`, `smtp`, `log`, `s3`); no numeric or boolean leaf may appear anywhere in
  the summary; this whitelist is the security boundary for the endpoint being unauthenticated
  (src/providers/status/public_summary.rs).
- **SPEC-3.75**: `GET /api/v1/providers` is mounted unauthenticated, as a peer of `/version` and `/health`, by
  design, and does nothing beyond `collect()` then `summarize()` then serializing the result
  (src/providers/status/public_summary_route.rs).
- **SPEC-3.76**: exactly three admin endpoints are mounted: `GET /admin/providers/status` (JSON) and `GET
  /admin/providers/status.html` (HTML), both gated by `RequireAdminOrBunyipMachine`; `POST
  /admin/providers/status/refresh`, gated by a staff admin session only (never the machine credential), because the
  refresh handler must record an operator login as the refresh actor and a machine caller has no operator identity
  to record (src/providers/status/route.rs).
- **SPEC-3.77**: the refresh endpoint calls `try_refresh` with no required keys; on `RefreshOutcome::Applied` the
  response is 200 with `{status: "applied", generation_number}`; on `RefreshOutcome::Rejected` it is 409 with
  `{status: "rejected", previous_generation_number, reason}` (src/providers/status/route.rs).

### 3.6 Operator CLI (src/cli/, src/bin/mokosh-bootstrap.rs)

- **SPEC-3.78**: `mokosh-server`'s operator-subcommand dispatch recognizes exactly these first-argument tokens:
  `bootstrap-infisical`, `qa-seed`, `qa-teardown`, `showcase-seed`, `showcase-refresh`, `showcase-teardown`,
  `provider-status`, `provider-set`, `provider-migrate`, `provider-purge`, `verify-providers`; any other token
  (including none) starts the HTTP server instead of dispatching (src/cli/mod.rs).
- **SPEC-3.79**: `bootstrap-infisical` requires `INFISICAL_ADMIN_EMAIL` and `INFISICAL_ADMIN_PASSWORD`, naming the
  missing variable if either is absent, and otherwise falls back to fixed defaults for every other input (address
  `http://localhost:28002`, project `mokosh`, identity `mokosh-machine`, environment `dev`, env file `.env`, admin
  name `Mokosh Admin`) (src/cli/mod.rs).
- **SPEC-3.80**: `qa-seed`/`qa-teardown` resolve the tenant id from `--tenant <uuid>` first, falling back to
  `MOKOSH_QA_TENANT_ID`; `showcase-*` subcommands use the same resolution order against `MOKOSH_SHOWCASE_TENANT_ID`;
  absence of both sources is a distinct error from a value that fails to parse as a UUID (src/cli/mod.rs).
- **SPEC-3.81**: `provider-status`, `provider-migrate`, `provider-set` and `provider-purge` each accept only a fixed
  set of flags and reject any other argument by name; `--help`/`-h` on any of these four returns an `Err` carrying
  the usage text as its message, which still exits the process non-zero (src/cli/providers.rs).
- **SPEC-3.82**: `provider-migrate` requires both `--from` and `--to`; naming the identical provider for both (after
  trimming) is an error rather than a silent no-op; its per-secret outcome is always exactly one of `"skipped:
  source does not hold this key"`, `"skipped: target already holds this key"`, `"moved (write + readback +
  compare)"`, or `"failed: {e}"`; it never deletes from the source provider, on success or failure
  (src/cli/providers.rs).
- **SPEC-3.83**: `provider-set` requires `--secret <NAME>` and `--from-env <VAR>`, with no `--to` flag; it
  distinguishes an unset source environment variable from one that is set but empty, with two different error
  messages, and never writes an empty value; it resolves the write target through the secret's own per-secret
  declaration (SPEC-3.5), not the process-wide selection (src/cli/providers.rs).
- **SPEC-3.84**: `provider-purge` requires `--provider <name>`; `--confirm` is optional and defaults to a dry run;
  there is no `--force`/`--overwrite`/`--yes-really` flag anywhere in this command, enforced by a source-scan test
  over the file's own non-comment code; without `--confirm` it never calls `delete`, even on a key that would
  otherwise be eligible (src/cli/providers.rs).
- **SPEC-3.85**: `provider-purge`'s secrets-tier interlock refuses a key when the named provider is the one
  currently declared/selected to serve it, or when the key is not verified live (via `.has()`) in the provider
  currently serving it; only when both checks pass does it proceed to the writability and confirm checks; a
  non-writable target (e.g. `environment`) is never deleted from and is reported with a hint naming the `{NAME}_FILE`
  path for that provider (src/cli/providers.rs).
- **SPEC-3.86**: every serialized provider-status/migrate/set/purge report passes through a redaction check that
  panics if the literal substring `{value}` or `{v}` appears anywhere in the serialized JSON, as a hard runtime
  guard against a value placeholder reaching an operator-facing report (src/cli/providers.rs).
- **SPEC-3.87**: `build_secret_providers` (shared by all four `provider-*` commands) always builds the environment
  provider; builds the file provider only when `APP_SECRETS_DIR` is set and non-empty; always attempts the database
  provider, reporting a failure as absent via a warning rather than propagating it; builds the Infisical provider
  only when `INFISICAL_ADDRESS` is set and non-empty, again warn-and-absent on failure; builds the bunyip provider
  only when `BunyipSecretsConfig::from_env()` returns `Ok(Some(_))`, warn-and-absent on build failure or on an
  incomplete three-variable set (src/cli/providers.rs).
- **SPEC-3.88**: `boot_shared_state` (shared by all four `provider-*` commands) requires `DATABASE_URL` and
  `ENCRYPTION_KEY` to be set; it uses `MOKOSH_APP_DATABASE_URL`, falling back to `DATABASE_URL`, for the
  request-serving pool, and always uses `DATABASE_URL` for the privileged/migrator pool (src/cli/providers.rs).
- **SPEC-3.89**: `verify-providers --help`/`-h` prints help and exits the process directly with status 0, which
  differs from every other operator subcommand's `--help`, whose usage text flows back as an `Err` and therefore a
  non-zero exit (src/cli/verify.rs).
- **SPEC-3.90**: `verify-providers` reproduces `main`'s own boot order (configuration, then application-tier
  secrets, then storage, then email) before collecting the provider-status report, and fails if `DATABASE_URL` or
  `ENCRYPTION_KEY` is unset; a failure to read the database-stored email override falls back to
  `MailerConfig::from_env()` with a warning rather than failing the whole run (src/cli/verify.rs).
- **SPEC-3.91**: `verify-providers` classifies a kind's row as `Fail` when any enabled provider is unreachable, when
  nothing is serving, or when no provider was built at all; the email row is additionally verified with an actual
  SMTP NOOP bounded by a 10-second timeout, and a pre-existing build failure for email is never overwritten by a
  passing verify, while a passing build result is overwritten by the verify's own verdict; the overall process exits
  non-zero whenever any row's verdict is `Fail` (src/cli/verify.rs).
- **SPEC-3.92**: `mokosh-bootstrap` loads `.env.infisical` then `.env` before parsing arguments, silently ignoring
  either file's absence; its subcommand set (`bootstrap-infisical`, `qa-seed`, `qa-teardown`, `dev-seed-portal`,
  `normalize-company-industries`, `--version`/`-V`, `--help`/`-h`/no-args) is disjoint from `mokosh-server`'s
  operator set apart from the three names both share: it never implements a `provider-*` command or
  `verify-providers`, and `mokosh-server` never implements `dev-seed-portal` or `normalize-company-industries`
  (src/bin/mokosh-bootstrap.rs).
- **SPEC-3.93**: `mokosh-bootstrap`'s `dev-seed-portal` runs pending database migrations before seeding, so it
  tolerates a fresh database with no `tenants` table yet; an unknown subcommand prints an error naming the
  unrecognised token, then the help text, then exits with `ExitCode::FAILURE` (src/bin/mokosh-bootstrap.rs).

## 4. Interfaces

### 4.1 HTTP API

All paths are relative to the server root. Bodies and responses are JSON unless stated (attachments, logos and PDFs are
binary; uploads are `multipart/form-data`). List endpoints take `PaginationParams` query parameters and return a
paginated envelope. Errors use the envelope in section 2.4.

Credentials: staff and platform routes take `Authorization: Bearer <token>`. Contact portal routes take a bearer token
or the `mokosh:contact_token` cookie. Webhook and machine endpoints authenticate themselves as described after the
route tables. Routes below are listed as registered; the guard on each is the extractor in its handler:

| Area | Guard observed in handlers |
|---|---|
| Auth, tickets, contacts and companies, notifications, SLA, teams, search, dashboards, saved reports | `RequireAuth`; configuration writes add `RequireAdmin`; some add `RequireManager` |
| Billing, quotes, expenses, invoice-issuer mappings | module gate `billing`; many routes also `RequireFinance` |
| Contracts | module gate `contracts`; many routes also `RequireFinance` |
| Projects | module gate `projects`; some `RequireAdmin` |
| Calendar, dispatch | module gate `calendar`; some `RequireManager` |
| Assets, asset catalog, company documentation | module gate `assets`; some `RequireAdmin` |
| Knowledge base | module gate `knowledge_base`; some `RequireManager` |
| RMM connections, mappings, alert rules | module gate `rmm_integration`; `RequireAdmin` on writes |
| Reports | module gate `reports`; billing and clients reports also `RequireFinance` |
| Time entries, timers, workday, mileage, work types | module gate `time_tracking`; timesheet and approval routes use the `timesheets` gate |
| Workflow rules, ticket templates, email intake tokens, form definitions | `RequireAdminUser` (admin or super admin) |
| Audit log list and export, data export, import and demo seed, IP enrichment | `RequireAdmin` |
| Tenant list, create, suspend, activate | platform admin bearer |
| Per-tenant get, update, usage, module config | platform admin bearer or a member of that tenant (`TenantOrPlatformCaller`) |
| SMTP settings, product name, Google contacts client, feature switches | `DeploymentOperator`: a platform admin bearer or an admin of the system tenant |
| Provider status (JSON and HTML) | admin session, or the identity provider's machine credential as HTTP Basic; refresh needs an admin session |

A module gate answers `404` when the module is disabled for the tenant.

#### Service and status (no authentication)

```text
GET                    /api/v1/health
GET                    /api/v1/ready
GET                    /api/v1/version
GET                    /api/v1/version/check
GET                    /api/v1/providers
```

#### Authentication, sessions, users

```text
POST                   /api/v1/auth/login
POST                   /api/v1/auth/select-tenant
POST                   /api/v1/auth/switch-tenant/{tenant_id}
POST                   /api/v1/auth/logout
POST                   /api/v1/auth/logout-all
POST                   /api/v1/auth/refresh
POST                   /api/v1/auth/forgot-password
POST                   /api/v1/auth/reset-password
GET                    /api/v1/auth/set-password/context/{token}
GET                    /api/v1/auth/me
PUT                    /api/v1/auth/me
GET                    /api/v1/auth/memberships
POST                   /api/v1/auth/me/complete-onboarding
PUT                    /api/v1/auth/me/password
GET                    /api/v1/auth/me/sessions
DELETE                 /api/v1/auth/me/sessions/{session_id}
POST                   /api/v1/auth/me/mfa/setup
POST                   /api/v1/auth/me/mfa/enable
POST                   /api/v1/auth/me/mfa/disable
GET                    /api/v1/auth/me/api-keys
POST                   /api/v1/auth/me/api-keys
DELETE                 /api/v1/auth/me/api-keys/{key_id}
GET                    /api/v1/auth/directory
GET                    /api/v1/auth/users
POST                   /api/v1/auth/users
GET                    /api/v1/auth/users/{user_id}
PUT                    /api/v1/auth/users/{user_id}
```

#### Platform plane (platform admins)

```text
POST                   /api/v1/platform/login
PUT                    /api/v1/platform/me/password
POST                   /api/v1/platform/me/mfa/setup
POST                   /api/v1/platform/me/mfa/enable
POST                   /api/v1/platform/me/mfa/disable
```

#### Grant invitations

```text
GET                    /api/v1/grants/invitations/by-token/{token}
POST                   /api/v1/grants/invitations/by-token/{token}/accept
POST                   /api/v1/grants/invitations/by-token/{token}/decline
POST                   /api/v1/grants/invitations
GET                    /api/v1/grants/invitations
DELETE                 /api/v1/grants/invitations/{id}
GET                    /api/v1/my-grants/invitations
POST                   /api/v1/my-grants/invitations/{id}/accept
POST                   /api/v1/my-grants/invitations/{id}/decline
DELETE                 /api/v1/my-grants/{id}
```

#### Tenants, teams, members, invitations

```text
GET                    /api/v1/tenants
POST                   /api/v1/tenants
POST                   /api/v1/tenants/self-serve
POST                   /api/v1/tenants/additional
GET                    /api/v1/tenants/current
PUT                    /api/v1/tenants/current
PUT                    /api/v1/tenants/current/organization
PUT                    /api/v1/tenants/current/logo
DELETE                 /api/v1/tenants/current/logo
GET                    /api/v1/tenants/{tenant_id}
PUT                    /api/v1/tenants/{tenant_id}
POST                   /api/v1/tenants/{tenant_id}/suspend
POST                   /api/v1/tenants/{tenant_id}/activate
GET                    /api/v1/tenants/{tenant_id}/usage
GET                    /api/v1/tenants/{tenant_id}/modules/{module}
PUT                    /api/v1/tenants/{tenant_id}/modules/{module}
GET, POST              /api/v1/teams
GET, PUT, DELETE       /api/v1/teams/{team_id}
GET, POST              /api/v1/teams/{team_id}/members
PUT, DELETE            /api/v1/teams/{team_id}/members/{user_id}
GET                    /api/v1/me/teams
GET                    /api/v1/members
GET, POST              /api/v1/invitations
DELETE                 /api/v1/invitations/{id}
```

#### Contacts, companies, sites

```text
GET                    /api/v1/contacts/companies
POST                   /api/v1/contacts/companies
GET                    /api/v1/contacts/companies/website-probe
GET                    /api/v1/contacts/companies/{company_id}
PUT                    /api/v1/contacts/companies/{company_id}
DELETE                 /api/v1/contacts/companies/{company_id}
GET                    /api/v1/contacts/companies/{company_id}/deletion-preview
GET                    /api/v1/contacts/companies/{company_id}/contacts
GET                    /api/v1/contacts/companies/{company_id}/sites
GET, POST              /api/v1/contacts/companies/{company_id}/portal-roles
GET, PUT, DELETE       /api/v1/contacts/companies/{company_id}/portal-roles/{role_id}
GET                    /api/v1/contacts/contacts
POST                   /api/v1/contacts/contacts
GET                    /api/v1/contacts/contacts/field-values
GET                    /api/v1/contacts/contacts/{contact_id}
PUT                    /api/v1/contacts/contacts/{contact_id}
DELETE                 /api/v1/contacts/contacts/{contact_id}
GET                    /api/v1/contacts/contacts/portal-roles
POST                   /api/v1/contacts/contacts/{contact_id}/grant-portal-access
POST                   /api/v1/contacts/contacts/{contact_id}/resend-portal-invite
POST                   /api/v1/contacts/contacts/{contact_id}/revoke-portal-access
GET, PUT               /api/v1/contacts/contacts/{contact_id}/portal-roles
GET                    /api/v1/contacts/contacts/{contact_id}/access-requests
POST                   /api/v1/contacts/contacts/access-requests/{request_id}/resolve
GET, POST              /api/v1/contacts/company-industries
PUT, DELETE            /api/v1/contacts/company-industries/{id}
POST                   /api/v1/contacts/sites
GET                    /api/v1/contacts/sites/{site_id}
PUT                    /api/v1/contacts/sites/{site_id}
DELETE                 /api/v1/contacts/sites/{site_id}
GET                    /api/v1/contacts/{contact_id}/notes
GET                    /api/v1/portal-roles
POST                   /api/v1/portal-roles
GET                    /api/v1/portal-roles/capabilities
GET                    /api/v1/portal-roles/{id}
PUT                    /api/v1/portal-roles/{id}
DELETE                 /api/v1/portal-roles/{id}
GET                    /api/v1/companies/{company_id}/documentation
PUT, DELETE            /api/v1/companies/{company_id}/{asset}
PUT, DELETE            /api/v1/tenants/current/branding/{asset}
```

#### Tickets

```text
GET                    /api/v1/tickets
POST                   /api/v1/tickets
GET                    /api/v1/tickets/{ticket_id}
GET                    /api/v1/tickets/{ticket_id}/sla
PUT                    /api/v1/tickets/{ticket_id}
PATCH                  /api/v1/tickets/{ticket_id}
DELETE                 /api/v1/tickets/{ticket_id}
POST                   /api/v1/tickets/{ticket_id}/assign
POST                   /api/v1/tickets/{ticket_id}/approvals/request
POST                   /api/v1/tickets/{ticket_id}/reopen
POST                   /api/v1/tickets/{ticket_id}/attachments
GET                    /api/v1/tickets/{ticket_id}/notes
POST                   /api/v1/tickets/{ticket_id}/notes
PUT                    /api/v1/tickets/{ticket_id}/notes/{note_id}
GET, POST              /api/v1/tickets/statuses
PUT, DELETE            /api/v1/tickets/statuses/{id}
GET, POST              /api/v1/tickets/priorities
PUT, DELETE            /api/v1/tickets/priorities/{id}
GET, POST              /api/v1/tickets/queues
PUT, DELETE            /api/v1/tickets/queues/{id}
GET, POST              /api/v1/tickets/types
PUT, DELETE            /api/v1/tickets/types/{id}
GET, POST              /api/v1/tickets/categories
PUT, DELETE            /api/v1/tickets/categories/{id}
GET, POST              /api/v1/tickets/saved-views
PUT, DELETE            /api/v1/tickets/saved-views/{id}
POST                   /api/v1/tickets/{ticket_id}/attachments/inline
GET, POST              /api/v1/tickets/{ticket_id}/notes/{note_id}/attachments
GET, DELETE            /api/v1/tickets/{ticket_id}/notes/{note_id}/attachments/{attachment_id}
GET, POST              /api/v1/ticket-templates
GET, PATCH, DELETE     /api/v1/ticket-templates/{id}
GET, POST              /api/v1/workflow-rules
GET, PATCH, DELETE     /api/v1/workflow-rules/{id}
GET                    /api/v1/tickets/{id}/workflow-runs
GET, POST              /api/v1/tickets/{ticket_id}/approvals
GET, POST              /api/v1/time-entries/{entity_id}/approvals
GET, POST              /api/v1/change-requests/{entity_id}/approvals
GET, POST              /api/v1/quotes/{entity_id}/approvals
GET                    /api/v1/approvals/pending
GET                    /api/v1/approvals/pending/count
POST                   /api/v1/approvals/{id}/decision
DELETE                 /api/v1/approvals/{id}
```

#### Time tracking, mileage

```text
GET, POST              /api/v1/work-types
PUT, DELETE            /api/v1/work-types/{id}
GET, POST              /api/v1/time-entries
GET                    /api/v1/time-entries/summary
GET, PUT, DELETE       /api/v1/time-entries/{id}
GET                    /api/v1/timesheets
POST                   /api/v1/timesheets/{user_id}/{week_start}/submit
POST                   /api/v1/timesheets/{user_id}/{week_start}/withdraw
POST                   /api/v1/timesheets/{user_id}/{week_start}/approve
POST                   /api/v1/timesheets/{user_id}/{week_start}/reject
GET                    /api/v1/timers/active
POST                   /api/v1/timers/start
POST                   /api/v1/timers/{id}/stop
GET                    /api/v1/workday
POST                   /api/v1/workday/clock-in
POST                   /api/v1/workday/clock-out
POST                   /api/v1/workday/break/start
POST                   /api/v1/workday/break/end
PUT, DELETE            /api/v1/workday/segments/{id}
GET, POST              /api/v1/time-rounding-rules
PUT, DELETE            /api/v1/time-rounding-rules/{id}
GET, POST              /api/v1/mileage-entries
GET, PUT, DELETE       /api/v1/mileage-entries/{id}
```

#### Projects

```text
GET, POST              /api/v1/projects
GET                    /api/v1/projects/summary
GET, PUT, DELETE       /api/v1/projects/{id}
GET, POST              /api/v1/projects/{id}/phases
PUT, DELETE            /api/v1/phases/{phase_id}
GET, POST              /api/v1/task-statuses
PUT, DELETE            /api/v1/task-statuses/{id}
GET, POST              /api/v1/project-types
PUT, DELETE            /api/v1/project-types/{id}
GET, POST              /api/v1/projects/{id}/tasks
GET, PUT, DELETE       /api/v1/tasks/{id}
POST, DELETE           /api/v1/tasks/{id}/depends-on/{other}
```

#### Calendar and dispatch

```text
GET, POST              /api/v1/appointments
GET                    /api/v1/calendar/appointments
GET, PUT, DELETE       /api/v1/appointments/{id}
GET, PUT               /api/v1/users/{user_id}/availability
GET, POST              /api/v1/time-off
GET, DELETE            /api/v1/time-off/{id}
POST                   /api/v1/time-off/{id}/approval
GET, POST              /api/v1/on-call-schedules
PUT, DELETE            /api/v1/on-call-schedules/{id}
GET                    /api/v1/on-call/now
GET, POST              /api/v1/scheduling-templates
GET, PUT, DELETE       /api/v1/scheduling-templates/{id}
GET                    /api/v1/dispatch
```

#### Contracts, SLA

```text
GET, POST              /api/v1/contracts
GET, PUT, DELETE       /api/v1/contracts/{id}
GET, POST              /api/v1/contracts/{id}/items
PUT, DELETE            /api/v1/contract-items/{id}
GET                    /api/v1/contracts/{id}/hour-balance
GET, POST              /api/v1/rate-cards
GET, PUT, DELETE       /api/v1/rate-cards/{id}
GET, POST              /api/v1/rate-cards/{id}/items
DELETE                 /api/v1/rate-card-items/{id}
GET, POST              /api/v1/sla/policies
GET, PUT, DELETE       /api/v1/sla/policies/{id}
GET, POST              /api/v1/sla/policies/{id}/targets
DELETE                 /api/v1/sla/targets/{id}
GET, POST              /api/v1/sla/business-hours
PUT, DELETE            /api/v1/sla/business-hours/{id}
GET, POST              /api/v1/sla/holiday-calendars
PUT, DELETE            /api/v1/sla/holiday-calendars/{id}
POST                   /api/v1/sla/tickets/{id}/evaluate
```

#### Billing

```text
GET, POST              /api/v1/invoices
GET                    /api/v1/invoices/summary
POST                   /api/v1/invoices/from-time-entries
GET, PUT               /api/v1/invoices/{invoice_id}
POST                   /api/v1/invoices/{invoice_id}/write-off
POST                   /api/v1/invoices/{invoice_id}/void
POST                   /api/v1/invoices/{invoice_id}/amend
GET                    /api/v1/invoices/{invoice_id}/pdf
GET                    /api/v1/invoices/{invoice_id}/delivery-options
POST                   /api/v1/invoices/{invoice_id}/pay
GET                    /api/v1/invoices/{invoice_id}/payments
GET                    /api/v1/invoices/{invoice_id}/payment-readiness
GET, POST              /api/v1/products
GET, PUT, DELETE       /api/v1/products/{product_id}
GET                    /api/v1/statements
GET                    /api/v1/statements/pdf
GET, POST              /api/v1/credit-notes
GET                    /api/v1/credit-notes/{credit_note_id}
GET                    /api/v1/credit-notes/{credit_note_id}/pdf
POST                   /api/v1/credit-notes/{credit_note_id}/void
GET, POST              /api/v1/payments
DELETE                 /api/v1/payments/{payment_id}
GET, PUT               /api/v1/payment-gateways
GET                    /api/v1/payment-gateways/webhook-endpoints
GET                    /api/v1/payment-gateways/webhook-deliveries
DELETE                 /api/v1/payment-gateways/{provider}
POST                   /api/v1/payment-gateways/{provider}/check
GET, POST              /api/v1/tax-rates
PUT, DELETE            /api/v1/tax-rates/{id}
GET                    /api/v1/tax-rates/lookup
GET, POST              /api/v1/payment-terms
PUT, DELETE            /api/v1/payment-terms/{id}
GET                    /api/v1/invoice-issuer-mappings/companies
PUT                    /api/v1/invoice-issuer-mappings/companies/{provider}/{company_id}
GET                    /api/v1/invoice-issuer-mappings/products
PUT                    /api/v1/invoice-issuer-mappings/products/{provider}/{product_id}
GET                    /api/v1/invoice-issuer-mappings/vendors
PUT                    /api/v1/invoice-issuer-mappings/vendors/{provider}/{vendor_id}
GET                    /api/v1/invoice-issuer-mappings/expense-accounts
PUT                    /api/v1/invoice-issuer-mappings/expense-accounts/{provider}/{category_id}
GET                    /api/v1/invoice-issuer-mappings/people
PUT                    /api/v1/invoice-issuer-mappings/people/{provider}/{user_id}
GET                    /api/v1/integrations/invoice-issuer/{provider}
POST                   /api/v1/integrations/invoice-issuer/{provider}/authorize
POST                   /api/v1/integrations/invoice-issuer/{provider}/disconnect
PUT                    /api/v1/integrations/invoice-issuer/{provider}/bills
PUT                    /api/v1/integrations/invoice-issuer/{provider}/payment-account
GET, POST              /api/v1/quotes
GET, PUT, DELETE       /api/v1/quotes/{quote_id}
POST                   /api/v1/quotes/{quote_id}/send
GET                    /api/v1/quotes/{quote_id}/delivery-options
POST                   /api/v1/quotes/{quote_id}/convert
POST                   /api/v1/quotes/{quote_id}/accept
POST                   /api/v1/quotes/{quote_id}/decline
GET                    /api/v1/quotes/{quote_id}/pdf
POST                   /api/v1/quotes/{quote_id}/lines
PUT, DELETE            /api/v1/quotes/{quote_id}/lines/{line_id}
GET, POST              /api/v1/vendors
GET, PUT, DELETE       /api/v1/vendors/{id}
GET, POST              /api/v1/expense-categories
PUT                    /api/v1/expense-categories/{id}
GET, POST              /api/v1/bills
GET                    /api/v1/bills/{id}
POST                   /api/v1/bills/{id}/approve
POST                   /api/v1/bills/{id}/void
GET, POST              /api/v1/bills/{id}/payments
GET, POST              /api/v1/expenses
GET                    /api/v1/expenses/{id}
POST                   /api/v1/expenses/{id}/submit
POST                   /api/v1/expenses/{id}/approve
POST                   /api/v1/expenses/{id}/reject
POST                   /api/v1/expenses/{id}/reimburse
```

#### Assets, documentation

```text
GET, POST              /api/v1/asset-types
PUT, DELETE            /api/v1/asset-types/{id}
GET, POST              /api/v1/assets
POST                   /api/v1/assets/search
POST                   /api/v1/assets/search/facets
POST                   /api/v1/assets/bulk-create
POST                   /api/v1/assets/exists
GET, PUT, PATCH, DELETE /api/v1/assets/{id}
GET, POST              /api/v1/assets/{id}/relationships
DELETE                 /api/v1/asset-relationships/{id}
GET                    /api/v1/assets/{id}/impact
POST                   /api/v1/assets/{id}/report-issue
GET, POST              /api/v1/assets/{id}/configuration-items
GET, DELETE            /api/v1/configuration-items/{id}
GET, POST              /api/v1/assets/{id}/credentials
GET, DELETE            /api/v1/credentials/{id}
GET                    /api/v1/assets/{id}/audit-log
GET, POST              /api/v1/asset-models
GET                    /api/v1/asset-models/signature-detector
GET, PUT, DELETE       /api/v1/asset-models/{id}
GET, POST              /api/v1/asset-templates
GET, PUT, DELETE       /api/v1/asset-templates/{id}
```

#### Knowledge base

```text
GET, POST              /api/v1/kb/categories
PUT, DELETE            /api/v1/kb/categories/{id}
GET, POST              /api/v1/kb/articles
GET, PUT, DELETE       /api/v1/kb/articles/{id}
GET, PUT, DELETE       /api/v1/kb/articles/{id}/draft
GET                    /api/v1/kb/articles/{id}/versions
POST                   /api/v1/kb/articles/{id}/versions/{version_number}/restore
POST                   /api/v1/kb/articles/{id}/render
POST                   /api/v1/kb/articles/{id}/helpful
POST                   /api/v1/kb/articles/{id}/not_helpful
GET                    /api/v1/kb/articles/{id}/vote
GET                    /api/v1/kb/top-ticket-driving-articles
GET                    /api/v1/kb/articles/{id}/measured-duration
GET                    /api/v1/kb/articles/{id}/tickets
GET, POST              /api/v1/kb/articles/{id}/comments
PUT, DELETE            /api/v1/kb/comments/{id}
POST                   /api/v1/kb/comments/{id}/resolve
POST                   /api/v1/kb/comments/{id}/unresolve
GET, POST              /api/v1/kb/articles/{id}/attachments
DELETE                 /api/v1/kb/articles/{id}/attachments/{attachment_id}
GET                    /api/v1/kb/attachments/{attachment_id}
```

#### Notifications, forms, email intake

```text
GET, POST              /api/v1/notification-channels
PUT, DELETE            /api/v1/notification-channels/{id}
GET, POST              /api/v1/notification-templates
PUT, DELETE            /api/v1/notification-templates/{id}
GET, PUT               /api/v1/me/notification-preferences
GET                    /api/v1/notifications
POST                   /api/v1/notifications/{id}/read
GET, POST              /api/v1/notification-rules
PUT, DELETE            /api/v1/notification-rules/{id}
POST                   /api/v1/notifications/dispatch
POST                   /api/v1/notifications/preview
GET, POST              /api/v1/forms
GET, PUT               /api/v1/forms/drafts
DELETE                 /api/v1/forms/drafts/{id}
GET, PATCH             /api/v1/forms/{id}
GET                    /api/v1/forms/{id}/submissions
GET, POST              /api/v1/form-request-links
POST                   /api/v1/email-intake
GET, POST              /api/v1/intake-tokens
DELETE                 /api/v1/intake-tokens/{id}
GET                    /api/v1/email-intake-log/{id}
```

#### Integrations, RMM, status monitoring, contact sync

```text
GET                    /api/v1/integrations
GET                    /api/v1/integrations/{provider}
PUT                    /api/v1/integrations/{provider}
POST                   /api/v1/integrations/{provider}/connect
POST                   /api/v1/integrations/{provider}/disconnect
GET, POST              /api/v1/rmm/connections
GET, PUT, DELETE       /api/v1/rmm/connections/{id}
POST                   /api/v1/rmm/connections/{id}/test
GET, POST              /api/v1/rmm/device-mappings
PUT, DELETE            /api/v1/rmm/device-mappings/{id}
GET, POST              /api/v1/rmm/alert-rules
PUT, DELETE            /api/v1/rmm/alert-rules/{id}
POST                   /api/v1/rmm/alerts
POST                   /api/v1/rmm/status
GET                    /api/v1/status/systems/{id}/current
GET                    /api/v1/status/companies/{company_id}/backup
GET                    /api/v1/reports/status/backup-success-rate
GET                    /api/v1/reports/status/uptime
GET                    /api/v1/integrations/contact-sync
POST                   /api/v1/integrations/contact-sync/google/authorize
POST                   /api/v1/integrations/contact-sync/google/disconnect
POST                   /api/v1/integrations/contact-sync/icloud/connect
POST                   /api/v1/integrations/contact-sync/icloud/disconnect
POST                   /api/v1/integrations/contact-sync/microsoft/authorize
POST                   /api/v1/integrations/contact-sync/microsoft/disconnect
PUT                    /api/v1/integrations/contact-sync/selection
PUT                    /api/v1/integrations/contact-sync/schedule
POST                   /api/v1/integrations/contact-sync/preview
GET, POST              /api/v1/integrations/contact-sync/runs
GET                    /api/v1/integrations/contact-sync/runs/{run_id}
POST                   /api/v1/integrations/contact-sync/runs/{run_id}/cancel
GET                    /api/v1/integrations/contact-sync/review-queue
POST                   /api/v1/integrations/contact-sync/review-queue/resolve
GET, POST              /api/v1/integrations/contact-sync/vcard/uploads
POST                   /api/v1/integrations/contact-sync/vcard/uploads/{file_id}/preview
POST                   /api/v1/integrations/contact-sync/vcard/uploads/{file_id}/import
GET                    /api/v1/contacts/contacts/{contact_id}/sync
DELETE                 /api/v1/contacts/contacts/{contact_id}/sync/locks/{field}
POST                   /api/v1/contacts/contacts/{contact_id}/sync/unlink
POST                   /api/v1/contacts/contacts/{contact_id}/sync/remove-imported-data
```

#### CRM pipeline, search, reports, dashboards

```text
GET, POST              /api/v1/crm/opportunities
GET, PUT, DELETE       /api/v1/crm/opportunities/{id}
POST                   /api/v1/crm/opportunities/{id}/close
GET                    /api/v1/search
GET                    /api/v1/reports
GET                    /api/v1/reports/dashboard
GET                    /api/v1/reports/tickets
GET                    /api/v1/reports/time
GET                    /api/v1/reports/request-types
GET                    /api/v1/reports/billing
GET                    /api/v1/reports/projects
GET                    /api/v1/reports/clients
GET                    /api/v1/reports/custom/schema
POST                   /api/v1/reports/custom
GET                    /api/v1/reports/{report}/export
GET, POST              /api/v1/reports/saved
GET, PATCH, DELETE     /api/v1/reports/saved/{id}
POST                   /api/v1/reports/saved/{id}/execute
GET, POST              /api/v1/reports/saved/{id}/schedules
GET, PATCH, DELETE     /api/v1/reports/schedules/{schedule_id}
GET, POST              /api/v1/dashboards
GET                    /api/v1/dashboards/default
GET, PATCH, DELETE     /api/v1/dashboards/{id}
GET, POST              /api/v1/dashboards/{id}/schedules
GET, PATCH, DELETE     /api/v1/dashboards/schedules/{schedule_id}
```

#### Settings, features, audit, data transfer, operator

```text
GET, PUT               /api/v1/settings
GET                    /api/v1/settings/modules
GET, PUT               /api/v1/settings/modules/{module}
GET, PUT               /api/v1/settings/email
POST                   /api/v1/settings/email/test-send
POST                   /api/v1/settings/email/verify
GET, PUT               /api/v1/settings/google-contacts-client
GET, PUT               /api/v1/settings/app-name
GET                    /api/v1/settings/{category}
GET, PUT, DELETE       /api/v1/settings/{category}/{key}
GET                    /api/v1/settings/feature-toggles
PUT                    /api/v1/settings/feature-toggles/{key}
GET                    /api/v1/audit-log
GET                    /api/v1/audit-log/export.csv
GET                    /api/v1/audit-log/entity/{entity_type}/{entity_id}
GET                    /api/v1/data/export
POST                   /api/v1/data/import
POST                   /api/v1/data/seed-demo
GET                    /api/v1/ip-enrichment
GET                    /api/v1/admin/providers/status
GET                    /api/v1/admin/providers/status.html
POST                   /api/v1/admin/providers/status/refresh
```

#### Contact portal (prefix /api/v1/contact)

```text
POST                   /api/v1/contact/auth/login
POST                   /api/v1/contact/auth/refresh
POST                   /api/v1/contact/auth/logout
POST                   /api/v1/contact/auth/set-password
POST                   /api/v1/contact/auth/login-link
POST                   /api/v1/contact/auth/login-link/redeem
GET, PUT               /api/v1/contact/auth/me
PUT                    /api/v1/contact/auth/me/password
POST                   /api/v1/contact/auth/me/mfa/setup
POST                   /api/v1/contact/auth/me/mfa/enable
POST                   /api/v1/contact/auth/me/mfa/disable
GET                    /api/v1/contact/auth/me/sessions
DELETE                 /api/v1/contact/auth/me/sessions/{session_id}
GET, PATCH             /api/v1/contact/companies/self/branding
POST                   /api/v1/contact/access-requests
GET                    /api/v1/contact/dashboard/summary
GET                    /api/v1/contact/portal/{handle}/host
GET                    /api/v1/contact/portal/{slug}/resolve-to-portal-id
GET, POST              /api/v1/contact/payment-methods
DELETE                 /api/v1/contact/payment-methods/{id}
PUT                    /api/v1/contact/payment-methods/{id}/default
PUT, DELETE            /api/v1/contact/companies/self/{asset}
```

#### Public, unauthenticated (prefix /api/v1/public, 60 requests per minute per client IP)

```text
GET                    /api/v1/public/config
GET                    /api/v1/public/tenants/{tenant_id}/logo
GET                    /api/v1/public/companies/{company_id}/{asset}
GET                    /api/v1/public/tenants/{tenant_id}/{asset}
GET                    /api/v1/public/kb/attachments/{attachment_id}
GET                    /api/v1/public/tickets/attachments/{attachment_id}
GET, POST              /api/v1/public/request-forms/{token}
GET                    /api/v1/public/contact-sync/google/callback
GET                    /api/v1/public/contact-sync/microsoft/callback
GET                    /api/v1/public/invoice-issuer/{provider}/callback
```

#### Inbound webhooks and machine endpoints (self-authenticated)

```text
POST                   /api/v1/bunyip/webhooks/account-deleted
POST                   /api/v1/bunyip/webhooks/mokosh-grant-changed
POST                   /api/v1/bunyip/oauth2/backchannel-logout
POST                   /api/v1/stripe/webhooks/{tenant_id}
POST                   /api/v1/paypal/webhooks/{tenant_id}
POST                   /api/v1/webhooks/xero
POST                   /api/v1/webhooks/quickbooks
```


Self-authenticating routes:

- `POST /api/v1/rmm/alerts` and `POST /api/v1/rmm/status`: HMAC-SHA256 of the raw body in the `X-Signature` header, compared
  in constant time against the stored connection secret; no bearer.
- `POST /api/v1/email-intake` and the intake log: tenant intake bearer token from `tenant_intake_tokens`.
- `POST /api/v1/bunyip/webhooks/*`: `X-Webhook-Signature`, hex HMAC-SHA256 of the body with `BUNYIP_WEBHOOK_SECRET`.
  Replays are idempotent.
- `POST /api/v1/bunyip/oauth2/backchannel-logout`: mounted only when the identity-provider verifier is configured;
  verifies the logout token and records the ended session; rate limited.
- `POST /api/v1/stripe/webhooks/{tenant_id}` and `/api/v1/paypal/webhooks/{tenant_id}`: the tenant's active provider
  verifies the delivery over the raw body (`Stripe-Signature` HMAC, or PayPal verification of the transmission headers)
  before parsing; a delivery from a provider that is not the tenant's active one is refused.
- `POST /api/v1/webhooks/xero` (`x-xero-signature`) and `/quickbooks` (`intuit-signature`): base64 HMAC-SHA256 over the raw
  body.

CORS: allowed methods GET, POST, PUT, DELETE, PATCH, OPTIONS; allowed request headers `Authorization`, `Content-Type`,
`Accept`, `X-Forwarded-Host`; credentials allowed; preflight cache 600 s. Allowed origins come from `CORS_ORIGIN`
(exact origins, or a scheme-locked `https://*.example.com` wildcard on the leftmost label); a malformed entry fails
startup.

### 4.2 Command line

`mokosh-server` with no argument serves. With a first argument from this list it runs the task and exits non-zero on
error:

| Subcommand | Arguments | Purpose |
|---|---|---|
| `bootstrap-infisical` | env `INFISICAL_ADMIN_EMAIL`, `INFISICAL_ADMIN_PASSWORD` (required); `INFISICAL_ADMIN_FIRST_NAME`, `INFISICAL_ADMIN_LAST_NAME`, `INFISICAL_URL`, `INFISICAL_PROJECT_NAME`, `INFISICAL_IDENTITY_NAME`, `INFISICAL_ENVIRONMENT`, `MOKOSH_ENV_FILE` | First-run setup of a secret-manager instance; writes the resulting credentials into an env file. |
| `qa-seed`, `qa-teardown` | `--tenant <uuid>` or env `MOKOSH_QA_TENANT_ID`; env `DATABASE_URL` | Load or remove the QA walkthrough dataset; refuses any tenant not marked QA. |
| `showcase-seed`, `showcase-refresh`, `showcase-teardown` | `--tenant <uuid>` or env `MOKOSH_SHOWCASE_TENANT_ID`; env `DATABASE_URL` | Create, reset or remove the showcase dataset; refuses any tenant not marked showcase. |
| `provider-status` | `--json`, `--text` | Presence matrix: every declared key per provider and which provider serves it; values are never printed. |
| `provider-set` | `--secret <NAME>`, `--from-env <VAR>`, `--json`, `--text` | Write one application-tier secret, read from the named environment variable, into the provider the deployment declares, then read it back and compare; takes effect after a restart. |
| `provider-migrate` | `--from <provider>`, `--to <provider>`, `--json`, `--text` | Copy every key the source provider holds into the target with read-back comparison; never clears the source. |
| `provider-purge` | `--provider <name>`, `--confirm`, `--json`, `--text` | Delete every key a disabled provider holds, only where the key is verified live in the serving provider; a dry run unless `--confirm`. |
| `verify-providers` | `--json`, `--text` | Boot each provider seam and report whether it serves; sends an SMTP NOOP for the email row; exits non-zero on any failure. |

`mokosh-bootstrap` (`src/bin/mokosh-bootstrap.rs`) is a second binary shipped in the image with subcommands
`bootstrap-infisical`, `qa-seed`, `qa-teardown`, `dev-seed-portal` (portal fixture tenants and contacts for development),
`normalize-company-industries` (map free-text industries onto the canonical set across tenants) and `--version`.

## 5. Data model

### 5.1 Storage and migrations

PostgreSQL. SQL migrations live in `migrations/` as `NNN_name.sql` files (starting at `002_tenants.sql`) and are embedded
into the binary with `sqlx::migrate!` and copied into the image at `/app/migrations`. They are applied at boot on the
privileged pool when `RUN_MIGRATIONS` is true. Applied migrations missing from the directory are ignored
(`set_ignore_missing(true)`). Migrations create the extensions `uuid-ossp`, `pg_trgm`, `citext` and `pgcrypto`.

Two database roles are used: `mokosh_migrator` (login, `BYPASSRLS`, owns the schema, runs DDL, migrations, bootstrap,
cross-tenant workers and the explicitly pre-authentication paths) and `mokosh_app` (login, `NOSUPERUSER NOBYPASSRLS`,
serves requests, owns nothing). Both are created idempotently at first boot from `MOKOSH_ADMIN_DATABASE_URL` when the
migrator role cannot yet log in. Each pool allows 20 connections (minimum 2), a 30 s acquire timeout, 600 s idle timeout
and 1800 s maximum lifetime.

### 5.2 Tenant isolation

Tenant-scoped tables carry `tenant_id`, enable and force row level security, and have a policy named `tenant_isolation`
comparing `tenant_id` with `current_setting('app.current_tenant')`. The setting is applied per transaction by
`begin_with_tenant`. Because `mokosh_app` does not bypass RLS, a query run without the setting sees no tenant rows.
Cross-tenant and pre-authentication reads (login, webhooks, workers) use the migrator pool.

### 5.3 Tables by domain

Tables created by the migrations (`CREATE TABLE`), grouped:

- Tenancy and identity: `tenants`, `tenant_settings`, `module_config`, `feature_toggles`, `users`, `user_sessions`,
  `api_keys`, `password_reset_tokens`, `user_oauth_identities`, `identities`, `tenant_memberships`,
  `tenant_membership_entitlements`, `platform_admins`, `teams`, `team_members`, `tenant_invitations`,
  `mokosh_bunyip_grants`, `mokosh_grant_invitations`, `login_approvals`, `user_login_devices`.
- Clients and portal: `companies`, `company_industries`, `contacts`, `contact_phones`, `contact_companies`, `sites`,
  `portal_roles`, `contact_role_assignments`, `contact_sessions`, `portal_setup_tokens`, `portal_refresh_tokens`,
  `portal_password_reset_tokens`, `portal_login_intents`, `portal_access_requests`, `portal_delegations`,
  `portal_exports`, `contact_notification_preferences`, `contact_payment_methods`.
- Contact import: `contact_sync_connections`, `contact_sync_links`, `contact_field_locks`, `contact_sync_candidates`,
  `contact_sync_oauth_states`, `contact_sync_suppressions`, `contact_sync_runs`, `contact_import_files`.
- Service desk: `tickets`, `ticket_sequences`, `ticket_queues`, `ticket_statuses`, `ticket_priorities`, `ticket_types`,
  `ticket_categories`, `ticket_notes`, `ticket_attachments`, `ticket_automation_rules`, `ticket_templates`,
  `ticket_saved_views`, `ticket_approvals`, `change_requests`, `workflow_rules`, `workflow_rule_runs`,
  `email_mailboxes`, `email_parse_rules`, `email_intake_log`, `tenant_intake_tokens`.
- SLA: `business_hours`, `holiday_calendars`, `sla_policies`, `sla_targets`, `sla_notifications`.
- Time, projects, calendar: `work_types`, `time_entries`, `time_rounding_rules`, `active_timers`, `work_day_segments`,
  `mileage_entries`, `projects`, `project_phases`, `project_types`, `task_statuses`, `tasks`, `task_dependencies`,
  `appointments`, `appointment_reminders`, `user_availability`, `time_off`, `on_call_schedules`,
  `scheduling_templates`.
- Commercial: `contracts`, `contract_items`, `contract_hour_balances`, `contract_invoice_runs`, `rate_cards`,
  `rate_card_items`, `invoices`, `invoice_lines`, `invoice_sequences`, `invoice_company_sequences`, `invoice_reminders`,
  `payments`, `payment_refunds`, `payment_terms`, `payment_gateway_configs`, `payment_webhook_deliveries`, `tax_rates`,
  `products`, `credit_notes`, `credit_note_lines`, `credit_note_sequences`, `quotes`, `quote_lines`, `quote_sequences`,
  `opportunities`, `vendors`, `expense_categories`, `bills`, `bill_lines`, `bill_payments`, `expenses`, `expense_lines`,
  `integrations`, `invoice_issuer_company_mappings`, `invoice_issuer_product_mappings`,
  `invoice_issuer_vendor_mappings`, `invoice_issuer_expense_account_mappings`, `invoice_issuer_user_mappings`,
  `invoice_issuer_oauth_states`.
- Assets and knowledge: `asset_types`, `assets`, `asset_relationships`, `asset_models`, `asset_templates`,
  `asset_tag_counters`, `configuration_items`, `credential_vault`, `asset_audit_log`, `kb_categories`, `kb_articles`,
  `kb_article_versions`, `kb_article_drafts`, `kb_article_votes`, `kb_article_attachments`, `kb_article_comments`,
  `kb_comment_mentions`.
- Forms: `form_definitions`, `form_fields`, `form_definition_drafts`, `form_submissions`, `form_request_tokens`.
- Notifications and reporting: `notification_channels`, `notification_templates`, `user_notification_preferences`,
  `notifications`, `notification_rules`, `saved_reports`, `scheduled_reports`, `saved_dashboards`,
  `scheduled_dashboards`, `audit_log`.
- Integrations and operations: `rmm_connections`, `rmm_device_mappings`, `rmm_alert_rules`, `monitored_systems`,
  `status_observations`, `secrets` (tenant secret provider rows), `app_secrets` and `app_config` (deployment-level
  provider rows), `files` (storage ledger).

### 5.4 Constraints worth knowing

- Check constraints pin enumerations in SQL as well as Rust, for example opportunity `stage` to six values with `outcome`
  set exactly when the stage is `won` or `lost`, and RMM `provider` to `tactical_rmm`, `mesh_central`, `datto`,
  `connectwise`, `ninja_rmm`. Of those only `tactical_rmm` has an adapter (section 8); the others answer with a stub that
  records an error.
- Numbering (tickets, invoices, quotes, credit notes, per-company invoices, asset tags) comes from sequence tables, not
  from application counters.
- A tombstoned user keeps its row (`deleted_at`), its email is rewritten to a `deleted-<uuid>` form so the unique
  `(tenant_id, email)` constraint does not block a re-signup.

## 6. Configuration

Configuration keys are declared once in `src/config/registry.rs` and resolved at boot into a generation; a key not
declared there cannot be read through the configuration API. The server process reads them from the process environment
(plus a `.env` file). A key has a tier: bootstrap keys are resolved once and need a restart to change; application keys
are re-resolved on a refresh. A `{NAME}_FILE` form is read by the file-based application-secret provider only. Values are
never logged; boot records name keys and providers.

### 6.1 Boot-time refusals

Outside `ENVIRONMENT` values `development`, `dev` and `test` (any other value, including an unknown one, is treated as
deployed) the server refuses to start when:

- `JWT_SECRET`, `ENCRYPTION_KEY` or `BUNYIP_WEBHOOK_SECRET` is unset or equals its built-in development value.
- `JWT_SECRET` is shorter than 32 bytes.
- `ENCRYPTION_KEY` is not exactly 64 hexadecimal characters.
- Any of `MOKOSH_DEPLOYMENT_MODE`, `MOKOSH_APP_DATABASE_URL`, `BASE_URL`, `CLIENT_ORIGIN`, `SPA_BASE_URL` is unset or
  blank. All missing variables are reported in one message with purpose and an example.
- A retired storage variable name is set (section 6.5).
- `MOKOSH_DEPLOYMENT_MODE`, `CONFIG_BACKEND`, `SECRET_BACKEND`, `APP_SECRET_BACKEND`, `STORAGE_PROVIDER`, `MAIL_PROVIDER` or
  `AUTH_PROVIDERS` holds an unrecognised value, `MAIL_PROVIDER=smtp` has no `SMTP_HOST`, or the mailer transport fails
  its boot verification.
- An application secret is declared in one provider but held only by another ("misplaced").

### 6.2 Core

| Key | Purpose |
|---|---|
| `MOKOSH_DEPLOYMENT_MODE` | `self-hosted` (default when blank) or `saas`; selects provider defaults (section 2.6). Required outside dev/test. |
| `ENVIRONMENT` | Environment name; default `development`. |
| `DATABASE_URL` | Privileged (`mokosh_migrator`) connection string; used for migrations, bootstrap and cross-tenant paths. If unset, a localhost URL is used. |
| `MOKOSH_APP_DATABASE_URL` | Request-serving (`mokosh_app`) connection string. If unset the pool falls back to `DATABASE_URL`, which makes row level security inert; required outside dev/test. |
| `MOKOSH_ADMIN_DATABASE_URL`, `MOKOSH_MIGRATOR_PASSWORD`, `MOKOSH_APP_PASSWORD` | Used only when the roles must be created at first boot. |
| `RUN_MIGRATIONS` | Run migrations at boot; default true. |
| `HOST`, `PORT` | Listen address; defaults `0.0.0.0` and `8080`. |
| `BASE_URL` | Base of platform-owned emailed links. Required outside dev/test. |
| `CLIENT_ORIGIN` | Browser origin of the client host; default for `CORS_ORIGIN` and the base for invitation and reset links. Required outside dev/test. |
| `SPA_BASE_URL` | Browser origin of the application client, base for emailed links to client-only pages; defaults to `CLIENT_ORIGIN`. Required outside dev/test. |
| `CORS_ORIGIN` | Comma-separated allowed origins; default `[CLIENT_ORIGIN]`. |
| `PUBLIC_API_BASE_URL` | This deployment's public API base, used to make tenant logos absolute in email; unset omits the logo from email. |
| `ABUSE_CONTACT_EMAIL` | Address shown in request-form emails for reporting abuse; unset omits the line. |
| `PORTAL_COOKIE_DOMAIN` | `Domain` attribute of the portal refresh cookie; unset leaves it host-scoped. |
| `MOKOSH_MAX_TENANTS` | Positive integer cap on tenant creation; blank, unparseable or non-positive means uncapped. |
| `MOKOSH_UPDATE_CHECK_URL` | Manifest URL for `/version/check`; unset disables the check. |
| `RUST_LOG` | Log filter; default `info`. |

### 6.3 Secrets and encryption

| Key | Purpose |
|---|---|
| `JWT_SECRET` | HS256 signing key for server-issued tokens (contact and staff). |
| `ENCRYPTION_KEY` | AES-256-GCM key for secrets at rest (64 hex characters; a raw 32-byte key is accepted in dev/test only). |
| `BUNYIP_WEBHOOK_SECRET` | Shared HMAC secret for identity-provider webhooks. |
| `SECRET_BACKEND` | Tenant secret provider: `database` (default) or `infisical`. |
| `INFISICAL_PROJECT_ID`, `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET`, `INFISICAL_ENVIRONMENT`, `INFISICAL_ADDRESS` | Secret-manager connection; `INFISICAL_ADDRESS` also drives the `/ready` probe (blank reports `skipped`). |
| `APP_SECRET_BACKEND` | Authoritative application-tier secret provider: `environment`, `file`, `database`, `infisical`, `bunyip`. |
| `APP_SECRETS_DIR` | Directory read by the `file` application-secret provider; unset disables that provider. |
| `BUNYIP_SECRETS_URL`, `BUNYIP_SECRETS_CLIENT_ID`, `BUNYIP_SECRETS_CLIENT_SECRET` | Connection for the `bunyip` application-secret provider. |
| `SMTP_PASSWORD`, `GOOGLE_CONTACTS_CLIENT_ID`, `GOOGLE_CONTACTS_CLIENT_SECRET`, `MICROSOFT_CONTACTS_CLIENT_ID`, `MICROSOFT_CONTACTS_CLIENT_SECRET`, `XERO_CLIENT_ID`, `XERO_CLIENT_SECRET`, `XERO_WEBHOOK_KEY`, `QUICKBOOKS_CLIENT_ID`, `QUICKBOOKS_CLIENT_SECRET`, `QUICKBOOKS_VERIFIER_TOKEN` | Governed application secrets. On `saas` the Google pair is read from the `bunyip` provider by default. A half-configured client id/secret pair fails boot. |

### 6.4 Authentication and identity provider

| Key | Purpose |
|---|---|
| `AUTH_PROVIDERS` | Comma list from `local`, `bunyip`; default per profile. A provider left out is skipped as if unconfigured. |
| `OIDC_ISSUER`, `OIDC_AUDIENCE` | Enable identity-provider token verification; both required for the verifier to mount. |
| `OIDC_JWKS_CACHE_TTL_SECS`, `OIDC_LEEWAY_SECONDS` | JWKS cache lifetime (default 600) and clock leeway (default 30). |
| `OIDC_DEFAULT_TENANT_ID` | Tenant used for provider identities with no placement; defaults to a fixed default tenant id. |
| `OIDC_BACKCHANNEL_CLIENT_ID` | Expected audience client id for back-channel logout tokens. |
| `ALLOW_UNINVITED_BUNYIP_SIGNUP` | Boolean; allow a first-sight, email-verified provider identity to get a personal tenant; default false. |
| `LOGIN_APPROVAL_ENABLED` | Boolean; enable the suspicious-login approval gate; default false. |
| `ADMIN_EMAIL`, `ADMIN_PASSWORD` | Create the first platform admin when none exists. |
| `BUNYIP_API_BASE_URL`, `BUNYIP_DIRECTORY_CLIENT_ID`, `BUNYIP_DIRECTORY_CLIENT_SECRET` | Directory lookup client for grant invitations; a partial set disables it with a warning. |
| `BUNYIP_STATUS_CLIENT_ID`, `BUNYIP_STATUS_CLIENT_SECRET` | Machine credential accepted as HTTP Basic by the JSON provider status endpoint. |
| `BUNYIP_CONFIG_URL`, `BUNYIP_CONFIG_CLIENT_ID`, `BUNYIP_CONFIG_CLIENT_SECRET`, `CONFIG_PROVIDERS`, `CONFIG_FILE_DIR`, `CONFIG_BACKEND` | Configuration provider selection and chain inputs; the server process accepts only `environment` through `CONFIG_BACKEND`. |
| `ORGANIZATIONS_ENABLED` | Boolean flag declared with defaults false (self-hosted) and true (saas); no code path reads its value. |
| `MOKOSH_SEED_TENANT_ID` | UUID of the template tenant whose configuration is copied into newly provisioned tenants; default `00000000-0000-0000-0000-000000000001`. A malformed value is a configuration error. |
| `MOKOSH_DEMO_SEED` | Truthy value enables automatic first-visit demo seeding outside `production`. |

### 6.5 Mail, storage, network

| Key | Purpose |
|---|---|
| `MAIL_PROVIDER` | `log`, `smtp` or `bunyip`; unset means `smtp` when `SMTP_HOST` is set, otherwise the profile default. |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_FROM`, `SMTP_TLS` | Relay settings; `SMTP_TLS` is `implicit`, `starttls` or `none`; a username without a password is an error. A database-stored email setting, when present, overrides these and can be changed at runtime. |
| `BUNYIP_MAILER_URL`, `BUNYIP_MAILER_CLIENT_ID`, `BUNYIP_MAILER_CLIENT_SECRET` | Connection for the `bunyip` mail provider. |
| `STORAGE_PROVIDER` | `local` (default) or `s3`. |
| `STORAGE_ROOT` | Local provider root directory; default `./attachments`. |
| `STORAGE_S3_ENDPOINT`, `STORAGE_S3_BUCKET`, `STORAGE_S3_REGION`, `STORAGE_S3_PATH_STYLE`, `STORAGE_S3_ACCESS_KEY_ID`, `STORAGE_S3_SECRET_ACCESS_KEY` | S3-compatible provider settings; region defaults to `us-east-1`. |
| `STORAGE_BACKEND`, `ATTACHMENT_DIR`, `S3_ENDPOINT`, `S3_BUCKET`, `S3_REGION`, `S3_PATH_STYLE`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY` | Retired names. Setting any of them refuses boot with the replacement named. |
| `ATTACHMENT_MAX_BYTES`, `KB_ATTACHMENT_MAX_BYTES`, `TENANT_LOGO_MAX_BYTES`, `BRANDING_TENANT_FAVICON_MAX_BYTES`, `BRANDING_TENANT_BACKGROUND_MAX_BYTES`, `BRANDING_COMPANY_LOGO_MAX_BYTES`, `BRANDING_COMPANY_FAVICON_MAX_BYTES`, `BRANDING_COMPANY_BACKGROUND_MAX_BYTES` | Upload size caps. Defaults: ticket attachments 25 MiB, KB attachments 5 MiB, logos 1 MiB, favicons 512 KiB, backgrounds 2 MiB. |
| `IP2LOCATION_DB_PATH` | IP2Location `.BIN` for login-country resolution; unset disables login-location alerts and the approval gate's country check. |
| `IP2PROXY_DB_PATH` | IP2Proxy `.BIN` for the admin enrichment lookup; unset disables it. |
| `TRUSTED_PROXY_CIDR` | Comma-separated CIDRs of proxies whose `X-Forwarded-For` is honoured; default loopback, RFC 1918, ULA and link-local ranges. |
| `OUTBOUND_PRIVATE_ALLOWLIST` | Hosts and CIDRs that tenant-supplied outbound URLs may reach despite being private. |
| `STRIPE_API_BASE`, `PAYPAL_API_BASE` | Override the payment API base URL (test stubs); PayPal otherwise selects its sandbox or live host from the credential. |

## 7. Service desk

Requirements for the service desk modules: `src/modules/tickets`, `ticket_templates`, `sla`, `workflows`, `forms`, `email_intake`, `calendar`, `projects`, `approvals`, `notifications`. Each `SPEC-7.<n>` below is cited at its implementing or enforcing site with a `// SPEC-7.<n>` comment in the file's own comment syntax.

### 7.1 Tickets

- **SPEC-7.1**: Ticket_number is formatted "T{:06}" from the tenant's next sequence value.
- **SPEC-7.2**: An omitted status_id/priority_id/queue_id resolves to the tenant's is_default row.
- **SPEC-7.3**: Every FK reference on the request is validated against the caller's own tenant.
- **SPEC-7.4**: A parent_ticket_id that already has a non-null parent is rejected; nesting is one level only.
- **SPEC-7.5**: The insert, the audit write, and run_ticket_created all run inside this one transaction.
- **SPEC-7.6**: On-create automation and SLA evaluation run after commit, outside any open transaction, falling back to the tenant's default due business days when no policy matches.
- **SPEC-7.7**: Only fields actually present in the request get an UPDATE; an omitted field is never overwritten (PATCH semantics).
- **SPEC-7.8**: Closed_at/resolved_at are set via now() only the first transition into an is_closed status, guarded by closed_at.is_none() so a later transition does not overwrite the original timestamp.
- **SPEC-7.9**: A checkbox-only change is skipped from the audit log, since it carries no customer-visible content change.
- **SPEC-7.10**: Run_ticket_status_changed/run_ticket_priority_changed fire inside the same transaction as the field UPDATE, only when the value actually changes.
- **SPEC-7.11**: On-update automation and SLA re-evaluation run after commit, outside any open transaction.
- **SPEC-7.12**: A foreign-key violation (SQLSTATE 23503) on delete is mapped to 400, not a generic 500.
- **SPEC-7.13**: Attachment blobs are purged from object storage only after the delete transaction commits.
- **SPEC-7.14**: Assign_ticket updates assigned_to_id but, unlike every other mutation here, writes no audit log row.
- **SPEC-7.15**: TicketSlaResponse exposes only sla_due_date/first_response_due/first_response_at/resolution_due/resolved_at/closed_at/status/status_name; no policy id, escalation chain, or calendar is exposed.
- **SPEC-7.16**: SLA status is computed by the single shared compute_sla_status helper everywhere a ticket's SLA state is rendered, so the agent view, portal view, and sweep worker cannot disagree (PMS-893); also, this mapping computes SLA status through the same shared compute_sla_status helper used by the agent view, portal view, and the background SLA sweep worker, so they cannot disagree (PMS-893).
- **SPEC-7.17**: Reopen_ticket requires the TICKETS_REOPEN capability on the contact plane; the shared implementation clears closed_at/resolved_at and moves the ticket to a non-closed status.
- **SPEC-7.18**: Reopen_portal_ticket is idempotent; reopening an already-open ticket does not error.
- **SPEC-7.19**: Every create_* that sets is_default=true first clears is_default on every other row for the tenant and lookup kind, enforcing a single default row per tenant per kind.
- **SPEC-7.20**: A parent_id that would create a cycle in the category hierarchy is rejected, detected via this recursive CTE.
- **SPEC-7.21**: Every lookup delete_* maps SQLSTATE 23503 (still referenced by a ticket) to 409 via this shared handler, rather than a 500.
- **SPEC-7.22**: List_tickets builds its WHERE clause exclusively through this enumeration of every supported filter field; a field not named here is rejected, never silently ignored.
- **SPEC-7.23**: List_tickets sort keys accepted from the client are limited to this allow-list; a key outside it is rejected (422) rather than translated into an arbitrary SQL expression.
- **SPEC-7.24**: The priority sort key orders by tp.sort_order (rank), never by id or name, because sorting by name would put "High" above "Urgent".
- **SPEC-7.25**: These mapped keys must stay exactly equal, in order, to mokosh_types::sort::TICKETS, and no SQL expression may itself be an accepted wire key; enforced by the pms897_tests unit tests below, not the compiler.
- **SPEC-7.26**: First_response_at is set via COALESCE(first_response_at, now()) the first time a note is added, and left untouched on every subsequent note.
- **SPEC-7.27**: A mail-send failure here is logged via tracing::warn! and never fails the note-creation request, since the note row already committed.
- **SPEC-7.28**: This literal must stay byte-identical to the seeded SQL migration 148 template; enforced by scripts/check-no-duplicate-mail-copy.nu.
- **SPEC-7.29**: The agent view orders notes created_at DESC (newest first).
- **SPEC-7.30**: The portal/customer view orders notes created_at ASC (oldest first, thread order), distinct from the agent view.
- **SPEC-7.31**: List_notes_by_contact orders notes created_at DESC (newest first).
- **SPEC-7.32**: Update_note applies two orthogonal gates, a WHO gate (NoteEditPolicy) returning 403 on failure and a WHAT/row-state gate (note_edit_block) returning 409 on failure.
- **SPEC-7.33**: A public note with is_email_sent true is refused for edit, since the customer holds the original in their inbox and an edited row would disagree with the customer's own evidence.
- **SPEC-7.34**: A note with created_by_contact_id set is refused for edit regardless of note_type, because it is the customer's own words.
- **SPEC-7.35**: A TimeEntry note is refused for edit, directing the edit to the underlying time entry instead.
- **SPEC-7.36**: An internal note, a resolution note, and a public note that has never been emailed are permitted (return None) when none of the refusal branches below apply.
- **SPEC-7.37**: Parse accepts only "off"/"author_or_admin"/"author_or_manager" and returns None otherwise; the unset-tenant default is AuthorOrAdmin.
- **SPEC-7.38**: AuthorOrAdmin permits author or admin, AuthorOrManager permits author or can_manage_users, Off never permits anyone including the author.
- **SPEC-7.39**: Set_status/set_priority/assign_to/set_queue/add_note run inside the one shared transaction used for the triggering ticket mutation (PMS-1246).
- **SPEC-7.40**: Webhook/send_notification are collected as DeferredAction values here rather than dispatched, so the network call happens only after the triggering transaction has committed (PMS-1379).
- **SPEC-7.41**: The outbound URL passes guard_outbound_url (SSRF guard) before the first request and again before following each redirect hop.
- **SPEC-7.42**: Redirect-following stops and fails after WEBHOOK_MAX_HOPS (5) hops.
- **SPEC-7.43**: An action referencing a missing required parameter is skipped (not applied, not erroring the whole rule evaluation) and the skip is logged.
- **SPEC-7.44**: Supported condition operators are exactly equals/not_equals/contains/starts_with/ends_with/is_null/is_not_null over status/priority/company_id/assigned_to_id/source/is_billable; any other operator or field does not silently match.
- **SPEC-7.45**: The default maximum attachment size is DEFAULT_MAX_BYTES (25 MiB); the inline-image maximum is INLINE_MAX_BYTES (5 MiB), both enforced at upload time.
- **SPEC-7.46**: The inline-image byte cap in effect at any moment is computed as a floor against the tenant's configured max, never exceeding INLINE_MAX_BYTES.
- **SPEC-7.47**: Inline image upload restricts MIME type to an allowlist (PNG, JPEG, WebP, GIF); SVG is refused.
- **SPEC-7.48**: This WHERE clause filters strictly on is_inline = true; an attachment with is_inline = false is never servable through this public route regardless of any other parameter.
- **SPEC-7.49**: Read_public_inline uses the BYPASSRLS migrator pool (tenant-less lookup), justified by the SAFETY note above per the repo's pool-safety convention.
- **SPEC-7.50**: The attachment download streams the blob via ReaderStream/Body::from_stream, never buffering the whole file into memory.
- **SPEC-7.51**: An attachment response carries a strong ETag of the exact form "{uuid}-{filesize}" and honors If-None-Match per RFC 9110 weak-comparison semantics, returning 304 on a match.
- **SPEC-7.52**: The private (agent-facing) response returns 500 if the blob is missing from storage despite a DB row existing; also, the public inline-image response returns 404 (not 500) when the blob is missing from storage, and omits Content-Disposition while adding X-Content-Type-Options: nosniff below.
- **SPEC-7.53**: Every stored attachment is addressed by (tenant_id, attachment_id) UUID, never by a filesystem path, when read back through the object storage seam.
- **SPEC-7.54**: A FileLedger row is recorded for every stored attachment blob, for tenant storage-usage rollups.
- **SPEC-7.55**: An attachment filename passes through sanitize_filename before being persisted or echoed back to a client.
- **SPEC-7.56**: Assert_ticket_visible_to_company/assert_portal_ticket_visible return 404, never 403, when a contact requests a ticket outside their own company.
- **SPEC-7.57**: Every saved-view CRUD method scopes rows strictly to (tenant_id, user_id); another user's saved view in the same tenant is 404, never 403.
- **SPEC-7.58**: Portal callers are gated per-action by this DB-loaded capability check, never by trusting the JWT's own claims (the JWT is UI-only).
- **SPEC-7.59**: Every ticket mutation opens its transaction with Database::begin_with_tenant(tenant_id), setting the RLS GUC app.current_tenant for its duration.

### 7.2 Ticket templates

- **SPEC-7.60**: Every ticket-template route (list/get/create/update/delete) requires the RequireAdminUser extractor; there is no agent-level access to this surface.
- **SPEC-7.61**: Name is validated 1-200 chars and subject 1-500 chars on create; is_active defaults to true (default_true) when the key is omitted.
- **SPEC-7.62**: The nullable FK fields (category_id/priority_id/type_id) and description/body use double_option, so an absent key leaves the field untouched while an explicit null clears it.
- **SPEC-7.63**: Get/update/delete all return 404 with the exact literal "Ticket template" when the row is absent or belongs to another tenant.
- **SPEC-7.64**: Every TicketTemplatesService method opens its own Database::begin_with_tenant(tenant_id) transaction (PMS-683), never sharing the caller's.
- **SPEC-7.65**: Update does a read-modify-write, merging each field via unwrap_or(current.field) before issuing one full UPDATE of every column.
- **SPEC-7.66**: List orders results by name ASC and applies the active_only filter only when the caller passes true; false (the admin default) returns retired templates too.
- **SPEC-7.67**: Create INSERTs and commits, then re-fetches the row through get() rather than relying on RETURNING to build the response.

### 7.3 SLA policies and the sweep worker

- **SPEC-7.68**: Requires auth and rejects an unsupported sort query param before the listing query runs.
- **SPEC-7.69**: Scoped to the caller's tenant and ordered by is_default DESC, name ascending.
- **SPEC-7.70**: Non-admin callers are rejected by RequireAdmin before reaching the service.
- **SPEC-7.71**: Name must be 1-100 characters or validation fails before the service is ever called.
- **SPEC-7.72**: Clear is_default on every other tenant policy first, so at most one policy per tenant is ever default.
- **SPEC-7.73**: Writes an audit record inside the same transaction as the insert, with `after` set to the row snapshot.
- **SPEC-7.74**: 404 when no row with that id exists for the caller's tenant.
- **SPEC-7.75**: Exclude the target row (id <> $2) when clearing other defaults, so the update never un-defaults the row it is itself promoting.
- **SPEC-7.76**: 404 when the UPDATE affects 0 rows, and the transaction is never committed in that case.
- **SPEC-7.77**: Requires RequireAdmin (routes.rs) and 404s when 0 rows are deleted.
- **SPEC-7.78**: Rejects a payload where both hours are present and first_response_hours > resolution_hours; equal values are allowed and either field being absent leaves the pair unconstrained.
- **SPEC-7.79**: First_response_hours and resolution_hours, when present, must each pass validate_sla_target_hours (positive, <= 2dp).
- **SPEC-7.80**: Defaults to "24x7" when absent from the request JSON.
- **SPEC-7.81**: Tenant scoping via the policy join (INNER JOIN sla_policies ON tenant_id = $1 AND p.id = $2) so a caller cannot enumerate another tenant's targets by guessing a policy id.
- **SPEC-7.82**: Upsert_target requires RequireAdmin and validates the body before the service's tenant-ownership check and write.
- **SPEC-7.83**: ON CONFLICT (sla_policy_id, priority_id) DO UPDATE means at most one target row exists per pair; a second call for the same pair overwrites rather than duplicates.
- **SPEC-7.84**: Scopes the delete through the owning policy's tenant and 404s when 0 rows are deleted.
- **SPEC-7.85**: Timezone defaults to the literal string "UTC" when omitted.
- **SPEC-7.86**: Accepts JSON null or {} as "no windows" and rejects (422) any other non-object top-level value, keyed onto field "schedule".
- **SPEC-7.87**: Rejects an unknown weekday key using the same clock::parse_weekday_key the read path uses, so the two cannot drift.
- **SPEC-7.88**: Each weekday's value must be null, a single {start,end} object, or an array of such objects; any other shape is rejected.
- **SPEC-7.89**: A window missing a string start/end, an unparseable time, or end <= start (including end == start) is rejected.
- **SPEC-7.90**: Parses with clock::parse_hhmm, the same time parser the read path uses; also, rejects an unknown weekday key using the same clock::parse_weekday_key the read path uses, so the two cannot drift.
- **SPEC-7.91**: Accepts null or [] as no holidays, and rejects (422) a non-array value.
- **SPEC-7.92**: Each entry must be a bare string or an object with a string "date" field, and the date must parse as %Y-%m-%d.
- **SPEC-7.93**: Clears is_default on every other row of the tenant before inserting, and the insert's audit record is written inside this same transaction below.
- **SPEC-7.94**: Excludes the target row (id <> $2) above when clearing other defaults, and 404s below on 0 rows affected.
- **SPEC-7.95**: Requires RequireAdmin (routes.rs) and 404s when 0 rows are deleted.
- **SPEC-7.96**: Writes an audit record inside the insert transaction (body validated by the handler before this call).
- **SPEC-7.97**: Scoped to tenant and ordered by name ascending.
- **SPEC-7.98**: Update and delete both require RequireAdmin (routes.rs) and 404 when 0 rows are affected.
- **SPEC-7.99**: A non-positive budget returns `start` unchanged, for both Always and BusinessHours.
- **SPEC-7.100**: The budget is converted to whole seconds, rounded to the nearest second; sub-second precision is not tracked.
- **SPEC-7.101**: Always computes start + budget as plain wall-clock addition, ignoring the schedule and holidays.
- **SPEC-7.102**: "24x7" (case-insensitive) maps to Always; every other string, including unrecognized values, maps to BusinessHours, matching the column default.
- **SPEC-7.103**: An all-closed schedule (no working windows on any weekday) degrades to plain wall-clock addition rather than attempting the day-walk, to avoid an infinite loop.
- **SPEC-7.104**: The walk operates on a cursor converted to the schedule's local timezone; all boundary comparisons are performed in that local time, and the result is converted back to UTC below.
- **SPEC-7.105**: A holiday date (interpreted in the schedule's local timezone, not UTC) is skipped by jumping to local midnight of the next day, before checking the weekday's windows.
- **SPEC-7.106**: A weekday with no configured windows is skipped the same way as a holiday.
- **SPEC-7.107**: Before the window opens, fast-forward to its open instant (no budget consumed) and re-enter the loop so the same window is evaluated as "inside".
- **SPEC-7.108**: If remaining fits in the window, the cursor advances by exactly remaining and the walk terminates in that same window (pinned boundary: the last second of a window is allowed, no bump to the next day).
- **SPEC-7.109**: Otherwise the whole window is consumed and the walk continues to the next window/day; a budget landing past close rolls over to the next working day's open instant plus the remainder.
- **SPEC-7.110**: Hard cap on iterations as a termination guard against pathological data; each pass either consumes from a window or skips a closed/holiday day, so the cap bounds the calendar span. ~30 years of days is far beyond any realistic SLA budget yet guarantees termination even on a near-empty schedule. This is a silent cap, not an error: a schedule that still has remaining budget after the cap returns whatever `cursor` last reached.
- **SPEC-7.111**: Multiple (split-shift) windows per day are sorted by start and consumed in order within a day.
- **SPEC-7.112**: A DST fall-back (ambiguous local time, two valid UTC instants) resolves to the earliest of the two via .earliest().
- **SPEC-7.113**: A DST spring-forward gap (no valid local instant) walks forward minute by minute, up to 180 minutes, until a valid local instant is found; if none is found it falls back to interpreting the naive datetime as UTC below.
- **SPEC-7.114**: A holiday date (interpreted in the schedule's local timezone, not UTC) is skipped by jumping to local midnight of the next day, before checking the weekday's windows.
- **SPEC-7.115**: An unparseable or unknown IANA timezone string maps to UTC rather than erroring.
- **SPEC-7.116**: Accepts numeric-string keys "0"-"6" (0=Sunday) or lowercase full/abbreviated English names, skipping (not erroring on) any other key.
- **SPEC-7.117**: Accepts "HH:MM" or "HH:MM:SS"; also, drops (returns None) a window where end <= start, a zero-length or inverted window that never contributes a working window.
- **SPEC-7.118**: Accepts a bare "YYYY-MM-DD" string or a {"date": ...} object per entry, silently skipping any entry that is neither shape or whose date string fails %Y-%m-%d parsing.
- **SPEC-7.119**: Evaluate_for_ticket requires RequireAdmin; the handler recomputes and persists the ticket's SLA due fields via the service.
- **SPEC-7.120**: Silent no-op (Ok(()), no write) when the ticket id does not exist for the tenant.
- **SPEC-7.121**: The applicable policy is the ticket's own sla_id when set; when NULL it is the tenant's is_default = TRUE policy (LIMIT 1, so more than one default row would be an unspecified pick among them).
- **SPEC-7.122**: No policy resolved (explicit sla_id not found, or no default policy) is a no-op with no write to the ticket.
- **SPEC-7.123**: No sla_targets row for (policy_id, priority_id) is a no-op with no write.
- **SPEC-7.124**: A NULL operational_hours column defaults to "business_hours" here, which differs from the "24x7" request-DTO default used when a client omits the field on write.
- **SPEC-7.125**: A missing business_hours_id, or a business_hours row that no longer exists, degrades to an all-closed schedule and an empty holiday set, which clock::due_at further degrades to 24x7 wall-clock arithmetic.
- **SPEC-7.126**: Holiday dates are the union of every holiday_calendars row referenced by the business-hours row's holidays UUID[] column, scoped to the tenant; an empty or NULL array yields no holidays without an extra query.
- **SPEC-7.127**: Each due field is computed independently via clock::due_at only when its hours value is non-NULL and parses to f64; otherwise that due field is left unset (None -> NULL).
- **SPEC-7.128**: The final UPDATE runs in a fresh, separate tenant-scoped transaction from the read above, committed independently.
- **SPEC-7.129**: Converts via a string round-trip; a value whose string form cannot parse as f64 is treated as None rather than erroring.
- **SPEC-7.130**: SlaSweepWorker runs on a 60-second fixed interval.
- **SPEC-7.131**: Returns Ok(0) immediately, performing no DB query, when no NotificationsService is wired (the `new`.
- **SPEC-7.132**: Scans ALL tenants in one query on the BYPASSRLS migrator pool, not a per-tenant GUC-scoped connection, because the scan is itself the cross-tenant enumeration that builds the tenant work list.
- **SPEC-7.133**: Selects only open tickets (resolved_at IS NULL AND closed_at IS NULL AND status not closed) that have at least one due field set.
- **SPEC-7.134**: No assignee means the ticket is skipped entirely for this tick: no milestone evaluated, no notification attempted.
- **SPEC-7.135**: First_response is skipped entirely (both breach and at-risk) once first_response_at IS NOT NULL; resolution has no such satisfied flag and is always evaluated when resolution_due is set.
- **SPEC-7.136**: A milestone with due = NULL is skipped, performing no evaluation.
- **SPEC-7.137**: Fires *_breached when now >= due, otherwise *_at_risk when now >= due - sla_at_risk_lead, otherwise no alert this tick. Breach takes precedence: once past due there is no point emitting the at-risk alert for the same field.
- **SPEC-7.138**: Computes lead = 20% of (due - created_at) via integer milliseconds (floor division, not rounded), then clamps to [5 minutes, 24 hours].
- **SPEC-7.139**: Returns exactly the 5-minute floor (not a clamped computed negative/zero lead) when due <= created_at.
- **SPEC-7.140**: Claims the (ticket_id, kind) pair via an INSERT ... ON CONFLICT (ticket_id, kind) DO NOTHING inside a tenant-scoped transaction, scoped to the ticket's own tenant, then commits.
- **SPEC-7.141**: Rows_affected() == 0 (already claimed by a prior tick or a racing replica/worker) skips the dispatch for that milestone entirely.
- **SPEC-7.142**: Ledger-first dedupe. The ledger row is already committed, so this milestone will not be retried. Log loudly; a missed heads-up is preferable to a tight retry loop hammering the queue.
- **SPEC-7.143**: A successful dispatch is logged at INFO with ticket_id, kind and fanout (n), and dispatched is incremented by n.
- **SPEC-7.144**: The dispatch context JSON includes recipient_user_id, ticket_id, kind, due (RFC3339), entity_type: "ticket", and entity_id.
- **SPEC-7.145**: Uses TenantId::from_trusted(t.tenant_id), where t.tenant_id is the value the cross-tenant scan itself projected off the tickets row (DB-derived, not user input): the sanctioned use of the trusted- construction escape hatch for this worker.
- **SPEC-7.146**: Run_tick returns the total count of notifications dispatched across the whole tick; this logs at INFO with field `dispatched` only when dispatched > 0 (a zero-dispatch tick logs nothing beyond the per-tick tracing span).

### 7.4 Workflow automation rules

- **SPEC-7.147**: Trigger_event is validated as a string of length 1..=50.
- **SPEC-7.148**: Name is validated as a string of length 1..=200.
- **SPEC-7.149**: Actions defaults to {} when omitted from the create request; also, conditions defaults to {} when omitted from the create request.
- **SPEC-7.150**: Is_active defaults to true when omitted from the create request; also, priority defaults to 100 when omitted from the create request.
- **SPEC-7.151**: On update, name (when Some) must still satisfy length 1..=200; also, req.validate() re-runs the UpdateWorkflowRuleRequest validators (including name's length 1..=200 when Some) before the service call.
- **SPEC-7.152**: Only these three trigger names are recognised by the service.
- **SPEC-7.153**: Rejects any trigger_event not in RECOGNISED_TRIGGERS with 400 and this exact message; the joined list preserves RECOGNISED_TRIGGERS' declared array order (created, status_changed, priority_changed), not alphabetical.
- **SPEC-7.154**: This DTO has no trigger_event field at all, so an existing rule's trigger event is immutable after creation (it cannot be changed via update).
- **SPEC-7.155**: GET /api/v1/workflow-rules requires an admin user and lists every rule for the caller's tenant, ordered priority ASC, created_at ASC; also, returns every rule for tenant_id, ordered priority ASC, created_at ASC.
- **SPEC-7.156**: GET /api/v1/workflow-rules/{id} requires an admin user and scopes the lookup to the caller's tenant; a missing row surfaces as 404 "Workflow rule"; also, scopes the lookup to tenant_id AND id, returning 404 "Workflow rule" when no row matches.
- **SPEC-7.157**: POST /api/v1/workflow-rules requires an admin user and runs DTO validation before calling the service, which binds the new row to the caller's tenant_id and created_by_id; also, inserts the row bound to the caller's tenant_id and created_by_id = user_id.
- **SPEC-7.158**: PATCH /api/v1/workflow-rules/{id} requires an admin user and applies only the non-null fields in the request body; also, applies COALESCE per-field updates (only non-null fields in the request body overwrite existing columns); updated_at is always set to NOW().
- **SPEC-7.159**: Returns 404 "Workflow rule" when no row with this tenant_id/id exists, checked via a separate SELECT id before the UPDATE.
- **SPEC-7.160**: DELETE /api/v1/workflow-rules/{id} requires an admin user; on success it returns {"deleted": true}; also, deletes the row scoped to tenant_id AND id, and returns 404 "Workflow rule" when rows_affected() == 0.
- **SPEC-7.161**: Requires an admin user and returns every workflow_rule_runs row for this ticket, scoped to the caller's tenant, ordered ran_at DESC; also, returns every workflow_rule_runs row for entity_type/entity_id scoped to the caller's tenant, ordered ran_at DESC.
- **SPEC-7.162**: Every CRUD/list query runs inside begin_with_tenant(tenant_id), so tenant_isolation RLS (migration 095) enforces scoping alongside the WHERE predicates.
- **SPEC-7.163**: Same unresolved-creator logging as list, tagged "workflows.get", without erroring; also, when created_by_name is unresolved (the joined user is gone), log it with context "workflows.list" but still return the row with created_by_name: None rather than erroring.
- **SPEC-7.164**: Selects only rules with trigger_event = 'ticket.created' AND is_active = true for tenant_id, ordered priority ASC, created_at ASC, and evaluates them in that order.
- **SPEC-7.165**: Non-object conditions are treated as "match nothing" (returns false), explicitly to avoid a malformed/typo'd conditions blob silently firing every rule.
- **SPEC-7.166**: An empty conditions object ({}) matches every ticket for this trigger.
- **SPEC-7.167**: Condition matching is AND across keys: every key present must independently match, else the whole rule fails to match (short-circuits on first non-match).
- **SPEC-7.168**: Within a key, matching is IN-array semantics: the key's JSON value must be a JSON array; if it is not an array, the whole match fails.
- **SPEC-7.169**: Recognised condition keys for ticket.created are exactly priority_id, queue_id, company_id, type_id, source; any other key name fails closed (evaluates to false), even a typo'd key like "pri0rity_id".
- **SPEC-7.170**: Priority_id, queue_id, company_id compare the ticket's UUID field against the condition array via string-parse-then-equality; non-UUID or non-string elements are silently ignored (never match, never error).
- **SPEC-7.171**: Type_id only matches if the ticket's type_id is Some and that UUID is in the array; if type_id is None, this key never matches.
- **SPEC-7.172**: Source matches by exact string equality against the array's string elements (not UUID parsing).
- **SPEC-7.173**: For each matched rule, unconditionally inserts a workflow_rule_runs row with applied_actions set to the rule's full actions blob (not just the ones that fired) and error set to the stringified AppError when apply_create_actions returned Err, else NULL.
- **SPEC-7.174**: A rule that does not match its conditions produces no workflow_rule_runs row at all; this continue skips both action application and run-row insertion.
- **SPEC-7.175**: Returns Ok(()) unconditionally as long as the rule-querying and run-row-inserting SQL succeeds; a failing action never propagates as an Err here.
- **SPEC-7.176**: Reads the tenant's cascade-cap setting via read_workflow_rule_max_depth and delegates to run_status_changed_at_depth starting at depth = 0.
- **SPEC-7.177**: Reads the tenant's cascade-cap setting via read_workflow_rule_max_depth and delegates to run_priority_changed_at_depth starting at depth = 0.
- **SPEC-7.178**: The cap comes from tenant_settings (category = 'workflows', key = 'rule_max_depth'); absent defaults to 3, present is clamped to 1..=10.
- **SPEC-7.179**: Read_workflow_rule_max_depth takes the raw &mut PgConnection of this already-open tenant-scoped transaction (not a fresh begin_with_tenant) to avoid deadlocking on the app.current_tenant GUC SET; the 1..=10 clamp means a value of 1 disables nested/cascaded rule firing entirely.
- **SPEC-7.180**: Selects only rules matching trigger_event = 'ticket.priority_changed' AND is_active = true for the tenant, ordered priority ASC, created_at ASC; also, selects only rules matching trigger_event = 'ticket.status_changed' AND is_active = true for the tenant, ordered priority ASC, created_at ASC.
- **SPEC-7.181**: Recognises keys from_status_id, to_status_id, priority_id, queue_id, company_id, type_id; any other key fails the match. Non-object or non-array-valued conditions fail closed the same way as the create matcher, and an empty object matches everything.
- **SPEC-7.182**: Recognises keys from_priority_id, to_priority_id, status_id, queue_id, company_id, type_id, with the same AND/IN/fail-closed/empty-matches-all semantics as matches_status_changed.
- **SPEC-7.183**: Depth-cap refusal mirrors the status-changed path; a rule matched exactly at depth == max_depth is refused, recorded with a "cycle cap reached at depth {max_depth}" run row, and the loop continues to the next rule; also, the recursion guard compares depth (u32, starting at 0) with >= against max_depth; a rule matched exactly at depth == max_depth is refused and never applied, so only depth 0..max_depth-1 can apply actions that cascade further.
- **SPEC-7.184**: For depth < max_depth, applies the actions and unconditionally inserts a run row recording success or the stringified error.
- **SPEC-7.185**: A transition rule that does not match its conditions produces no run row (same as the create-trigger path); also, a transition rule that does not match its conditions produces no run row.
- **SPEC-7.186**: Applies actions in this fixed order regardless of key order in the JSON object: assign_to_user_id, assign_to_team_id, set_priority_id (no-cascade), set_status_id (no-cascade), add_tag, add_internal_note; returns Ok(()) if actions is not a JSON object (silently does nothing).
- **SPEC-7.187**: Each action sub-step below runs even if an earlier sub-step already failed (no early return on an individual action failure); only the FIRST failure is retained via first_error.get_or_insert_with, and that one message becomes the workflow_rule_runs.error for this rule-run.
- **SPEC-7.188**: Assign_to_user_id / assign_to_team_id actions parse a UUID from the string value and UPDATE assigned_to_id / team_id; an absent key or non-string value is a no-op; a SQL failure and a UUID-parse failure produce distinct error messages ("... failed: {e}" vs "... parse: {e}").
- **SPEC-7.189**: On the ticket.created path, set_priority_id / set_status_id update the column directly via these no-cascade variants and never fire the corresponding ticket.priority_changed / ticket.status_changed trigger, because ticket creation is the originating event, not a transition.
- **SPEC-7.190**: Add_tag requires a string value and appends it via array_append, guarded by NOT ($1 = ANY(tags)) so a duplicate tag is not appended twice; an absent or non-string key is a no-op.
- **SPEC-7.191**: Looks up the OLDEST active user with role super_admin, admin, or manager as the note's created_by_id, not the user who triggered the workflow and not the rule's created_by_id; a SQL failure on this lookup itself sets error "add_internal_note creator lookup: {e}".
- **SPEC-7.192**: If no eligible admin-tier user exists, this if-let guard skips the INSERT entirely: no note inserted and no error recorded, even though the rule matched and configured this action.
- **SPEC-7.193**: Inserts into ticket_notes with note_type = 'internal'; a SQL failure here sets error "add_internal_note failed: {e}".
- **SPEC-7.194**: Applies non-cascading actions first, in this order: assign_to_user_id, assign_to_team_id, add_tag, add_internal_note. set_priority_id / set_status_id are not in this list and the "no_cascade" setters used by the create path are never called at all on the transition path.
- **SPEC-7.195**: Set_priority_id is evaluated before set_status_id so a rule that changes both ends up firing priority_changed first.
- **SPEC-7.196**: Set_priority_id / set_status_id are no-ops when the new value equals the current value (no UPDATE, no cascade, no error); otherwise each UPDATEs the column then recurses into the matching transition runner at depth + 1 inside the same transaction, with errors "set_priority_id/set_status_id failed/parse" and a wrapped cascade error ("priority cascade: {e}" / "status cascade: {e}") retained only if first_error is still None.
- **SPEC-7.197**: Returns Err(AppError::Internal(msg)) with msg equal to the single retained first_error string if any action (including a cascade) failed, else Ok(()).
- **SPEC-7.198**: Depth-cap refusal mirrors the status-changed path; a rule matched exactly at depth == max_depth is refused, recorded with a "cycle cap reached at depth {max_depth}" run row, and the loop continues to the next rule; also, the recursion guard compares depth (u32, starting at 0) with >= against max_depth; a rule matched exactly at depth == max_depth is refused and never applied, so only depth 0..max_depth-1 can apply actions that cascade further.
- **SPEC-7.199**: Ticket.created never calls run_ticket_status_changed / run_ticket_priority_changed; this is a hard structural guarantee (not depth-limited) because the create is the originating event, the next mutation is the operator's.
- **SPEC-7.200**: Boxed with Box::pin to satisfy Rust's requirement that recursive async fns have a statically-sized future.
- **SPEC-7.201**: Read_workflow_rule_max_depth takes the raw &mut PgConnection of this already-open tenant-scoped transaction (not a fresh begin_with_tenant) to avoid deadlocking on the app.current_tenant GUC SET; the 1..=10 clamp means a value of 1 disables nested/cascaded rule firing entirely.
- **SPEC-7.202**: The != guard before each UPDATE prevents a rule that targets the ticket's current value from cascading or recursing, closing a trivial infinite-loop vector.
- **SPEC-7.203**: The only loop guard across the recursive status/priority cascade is the numeric depth counter; there is no de-duplication or cycle-detection against rule identity or ticket-state history, so a cascade that keeps alternating between two values runs until max_depth is hit.
- **SPEC-7.204**: This INSERT (and the rule-listing SELECTs in run_ticket_created / run_status_changed_at_depth / run_priority_changed_at_depth) use `.await?`, so a SQL-level failure here propagates up through the whole recursive call chain and can abort the caller's outer transaction, unlike action-level failures which are always absorbed into a run row's error column instead.

### 7.5 Forms, request links and drafts

- **SPEC-7.205**: GET /forms requires only authentication and lists every definition for the caller's tenant, including retired ones, unless active_only=true narrows the result; also, lists every definition for the tenant ordered by name ASC, including retired ones, unless active_only narrows to is_active = true (default false).
- **SPEC-7.206**: GET /forms/{id} requires authentication; a missing definition for the caller's tenant is a 404, not any other status; also, a missing definition for the caller's tenant is 404 "Form definition".
- **SPEC-7.207**: POST /forms (create a definition) requires an admin user, not merely authentication.
- **SPEC-7.208**: PATCH /forms/{id} (update a definition) requires an admin user.
- **SPEC-7.209**: No DELETE /forms/{id} and no POST /forms/{id}/submissions route; both stay unmounted and 405 rather than being routed.
- **SPEC-7.210**: GET /forms/{id}/submissions requires only authentication (any authenticated agent, not admin-only); also, returns every submission for the definition's tenant, ordered by created_at DESC.
- **SPEC-7.211**: A slug already in use by the same tenant fails with Conflict and the exact message below, rather than a generic duplicate-key error.
- **SPEC-7.212**: After a successful create, the caller's "new form" draft (keyed by form_definition_id = None) is deleted best-effort; a failure here only logs a warning; also, after a successful update, the caller's draft for this specific form_definition_id is deleted best-effort.
- **SPEC-7.213**: CreateFormDefinitionRequest.name/slug length and format, fields >= 1 entry (DTO layer, before the service runs), and is_active default.
- **SPEC-7.214**: UpdateFormDefinitionRequest.contact_info keeps the same 200-char cap via double_option, and fields (when present) must have >= 1 entry.
- **SPEC-7.215**: CreateFormDefinitionRequest.name/slug length and format, fields >= 1 entry (DTO layer, before the service runs), and is_active default; also, UpdateFormDefinitionRequest.contact_info keeps the same 200-char cap via double_option, and fields (when present) must have >= 1 entry.
- **SPEC-7.216**: An absent key leaves the corresponding column untouched (COALESCE / CASE), while description, contact_info and kb_article_id use "double option" deserialization so an explicit JSON null clears the column but an absent key does not.
- **SPEC-7.217**: When `fields` is present, the entire existing field set is deleted and replaced wholesale, never merged; submissions already stored keep their own payload and are unaffected.
- **SPEC-7.218**: Rule-vs-field consistency is re-checked whenever either `fields` or `rules` is present in the request, using the post-update value of each (the other side falls back to the existing stored value).
- **SPEC-7.219**: A duplicate field name (case-sensitive exact match) within one definition is rejected with code "duplicate".
- **SPEC-7.220**: A field_type that resolves to FieldType::Unknown is rejected at write time with code "unknown_field_type".
- **SPEC-7.221**: A Select field with no options, or an empty options list, is rejected with code "required".
- **SPEC-7.222**: Min_length > max_length (when both are set) is rejected with code "range".
- **SPEC-7.223**: All field-set errors are collected and returned together as a single 422 validation error, not just the first.
- **SPEC-7.224**: Nested per-field DTO checks on CreateFormFieldRequest: name/label length and format, min_length/max_length bounds.
- **SPEC-7.225**: Nested per-field DTO checks on CreateFormFieldRequest: name/label length and format, min_length/max_length bounds.
- **SPEC-7.226**: Nested per-field DTO checks on CreateFormFieldRequest: name/label length and format, min_length/max_length bounds.
- **SPEC-7.227**: Enforced only when the field type honours_length() (Text, Textarea, Email); a bound set on any other type is inert, not an error.
- **SPEC-7.228**: The only authorable rule kind is RequiredIf; any other/unnamed rule kind is rejected at write time with code "unknown_rule_kind".
- **SPEC-7.229**: A rule's `field` that does not match any known field name is rejected with code "unknown_field".
- **SPEC-7.230**: A rule's `when_field` that does not match any known field name is rejected with code "unknown_field".
- **SPEC-7.231**: Equals is bounded to the condition field's domain (Select options, Boolean true/false) and unbounded for any other type; see equals_outside_domain.
- **SPEC-7.232**: Equals is bounded to the condition field's domain (Select options, Boolean true/false) and unbounded for any other type; see equals_outside_domain.
- **SPEC-7.233**: Equals is bounded to the condition field's domain (Select options, Boolean true/false) and unbounded for any other type; see equals_outside_domain.
- **SPEC-7.234**: The read path is deliberately tolerant. A stored rule this.
- **SPEC-7.235**: A rule naming a field that does not exist on the definition is inert here. The service rejects such a rule at write time, so this is defence in depth.
- **SPEC-7.236**: An unparseable stored field_type falls back to Text rather than panicking (unreachable given the CHECK constraint).
- **SPEC-7.237**: A rules JSON value that fails to deserialize falls back to an empty rule list rather than failing the read, so an unreadable rule shape still opens.
- **SPEC-7.238**: A non-object JSON payload is rejected with a field error on "payload".
- **SPEC-7.239**: Every payload key that does not match a known field name is rejected (not silently dropped) with code "unknown_field".
- **SPEC-7.240**: A string answer is trimmed; if the trimmed result is empty, it is treated as absent (same as a missing key or JSON null) and the trimmed (not raw) value is what gets stored when present.
- **SPEC-7.241**: A boolean field answered `false` IS an answer. Treating it as.
- **SPEC-7.242**: A field is required when either its own is_required flag is true or a RequiredIf rule targeting it currently matches.
- **SPEC-7.243**: String compared trimmed-equal; boolean compared via its to_string() ("true"/"false"); number compared via its to_string(); any other/missing value never matches.
- **SPEC-7.244**: All field errors are collected and returned together, e.g. three missing required fields report three errors, not just the first.
- **SPEC-7.245**: A present-but-absent-after-normalisation value is simply omitted from the stored payload (never stored as an empty string); a missing required field produces code "required"; also, a string answer is trimmed; if the trimmed result is empty, it is treated as absent (same as a missing key or JSON null) and the trimmed (not raw) value is what gets stored when present.
- **SPEC-7.246**: Boolean requires a JSON boolean value; otherwise code "type".
- **SPEC-7.247**: Text/Textarea/Email require a JSON string (code "type" via as_string), honour min_length/max_length counted in Unicode characters, not bytes (check_length).
- **SPEC-7.248**: Email additionally must pass validate_email; otherwise code "email".
- **SPEC-7.249**: A stored field type this build cannot name. It cannot have.
- **SPEC-7.250**: The value must be a string parseable as NaiveDate in exactly %Y-%m-%d; otherwise code "date_format".
- **SPEC-7.251**: With date_not_in_past = true, a date strictly before `today` is rejected with code "date_in_past"; a date equal to today is allowed.
- **SPEC-7.252**: Select requires the value to be a string present (exact match) in field.options (empty slice if options is None); otherwise code "option".
- **SPEC-7.253**: Text/Textarea/Email require a JSON string (code "type" via as_string), honour min_length/max_length counted in Unicode characters, not bytes (check_length); also, length bounds count CHARACTERS, not bytes, so a limit means the same thing.
- **SPEC-7.254**: GET/POST /request-forms/{token} are mounted outside authentication middleware and outside the portal tree; the only identity presented is the token itself.
- **SPEC-7.255**: 30 requests/minute per IP, in-memory and not shared across replicas, applied before the token is resolved.
- **SPEC-7.256**: Resolving the token is the only point of failure for this route, so a malformed, guessed, expired or already-submitted token all fail the same way from here.
- **SPEC-7.257**: Resolves the token, submits the body's payload via submit_via_request_link, and returns 201 Created with the receipt on success.
- **SPEC-7.258**: Issuing a request link requires only authentication, not admin.
- **SPEC-7.259**: Issuing is rate-limited per issuing user; exceeding it fails the request with a rate-limited error rather than sending another link.
- **SPEC-7.260**: IssueRequestLinkRequest is DTO-validated before the service call: recipient_email (if present) must be a valid email, people (if present) in 1..=50.
- **SPEC-7.261**: Issuing a link against a retired (is_active = false) definition fails with Conflict and this exact message.
- **SPEC-7.262**: Company_id must resolve to a company in the caller's own tenant (looked up inside the tenant transaction); otherwise NotFound("Company").
- **SPEC-7.263**: Contact_id must resolve to a contact in the caller's tenant (else NotFound("Contact")); a contact with no email and no recipient_email override fails with a BadRequest naming the fix.
- **SPEC-7.264**: With no contact_id, recipient_email must be present, otherwise BadRequest requiring either one.
- **SPEC-7.265**: People defaults to 1 when absent and must be within 1..=MAX_PEOPLE_PER_LINK (50), rejected here as defense-in-depth beyond the DTO-level 1..=50 validator.
- **SPEC-7.266**: A parent container ticket is created at issue time only when people > 1; the default people == 1 creates no parent ticket at all (parent_ticket_id stays None).
- **SPEC-7.267**: A parent container ticket is created at issue time only when people > 1; the default people == 1 creates no parent ticket at all (parent_ticket_id stays None).
- **SPEC-7.268**: The token is {token_id}.{secret}, token_id a UUID and secret a 64-character random token; only the Argon2 hash of the secret is ever persisted.
- **SPEC-7.269**: Expires_at is issue time plus REQUEST_LINK_TTL_DAYS (7 days).
- **SPEC-7.270**: The inserted row sets uses_allowed = uses_remaining = people and parent_ticket_id to the created parent (or NULL for a single-person link).
- **SPEC-7.271**: The emailed link is {app_url}/request-forms/{token_id}.{secret}.
- **SPEC-7.272**: Email delivery is best-effort and happens AFTER the transaction commits, mirroring the portal setup-link path: a failed send must not roll back the already-persisted token row, since that row is what makes a resend possible.
- **SPEC-7.273**: With no notifications dispatcher wired, or when dispatch fails, the already-persisted token is kept and only a warning is logged; a failed or skipped send never undoes the issued link, since the row is what makes a resend possible.
- **SPEC-7.274**: The issue response never includes the token, only the row's own audit-trail fields; only the recipient ever holds the credential.
- **SPEC-7.275**: GET /form-request-links requires only authentication and lists links for the caller's tenant, optionally filtered to one company_id; also, list_request_links returns this tenant's issued links ordered newest-first, optionally filtered to one company, and never includes the token itself.
- **SPEC-7.276**: A malformed token (no '.', empty secret, non-UUID token_id), a token_id with no matching row, and a matching row whose secret fails verification all return the same generic "Invalid or expired request link" error, so a guessed token cannot be distinguished from a stale one.
- **SPEC-7.277**: A token with nothing left (uses_remaining <= 0) resolves to Gone (410), reported as "already been submitted".
- **SPEC-7.278**: An expired token (expires_at <= now) resolves to the same generic invalid/expired BadRequest as a malformed or non-matching token.
- **SPEC-7.279**: The token row is looked up by primary key on the BYPASSRLS migrator pool, before the tenant is known, because this lookup is what resolves the tenant; the secret is verified below before anything about the row is returned, and every later query runs tenant-scoped via begin_with_tenant.
- **SPEC-7.280**: A successful resolution returns the tenant via TenantId::from_trusted (the pre-auth escape hatch, since this lookup is what establishes the tenant) along with the form, company, contact, issuing user and remaining-people counts.
- **SPEC-7.281**: Opening a link against a retired (is_active = false) definition fails with Gone (410), the same terminal shape as an already-submitted link.
- **SPEC-7.282**: The public response carries only name, description, org identity, people/person_number, rules and public field metadata; it never exposes internal ids, the authoring user, timestamps, or the KB article (an internal procedure, not something the client is entitled to read).
- **SPEC-7.283**: Person_number is the first unspent use, computed as people - uses_remaining + 1.
- **SPEC-7.284**: Submitting against a retired definition is rechecked here (not just at open time) and fails with Gone (410), guarding the race where the form is retired between GET and submit.
- **SPEC-7.285**: The public submission is validated with the exact same validate_submission as the authenticated surface, so a client and an agent get identical rules and identical per-field errors.
- **SPEC-7.286**: Submission is four separate transactions in order: insert the submission, claim the token's use (uses_remaining > 0 guard, moved ahead of ticket creation per PMS-1370 so a single-use link cannot produce two tickets), create the ticket in TicketService's own transaction, then stamp the submission with the ticket and token ids; a failure between the claim and the ticket commit leaves the use spent with no ticket, judged less harmful than two tickets for one use.
- **SPEC-7.287**: A token with nothing left to claim (no row updated) returns Gone before any ticket is created, which is what stops a single-use link from producing two tickets under concurrent submission; also, the claim is an UPDATE guarded by uses_remaining > 0; it also stamps used_at when the use drains to zero and sets submission_id to this submission only if one is not already recorded (COALESCE), so a later resubmission attempt never overwrites the first submission's id.
- **SPEC-7.288**: The claim is an UPDATE guarded by uses_remaining > 0; it also stamps used_at when the use drains to zero and sets submission_id to this submission only if one is not already recorded (COALESCE), so a later resubmission attempt never overwrites the first submission's id.
- **SPEC-7.289**: The ticket-service presence check happens AFTER the claim commits, so a missing ticket service still leaves the use spent rather than retried.
- **SPEC-7.290**: Company_id and contact_id on the created ticket come from the resolved TOKEN, never from the submitted payload, so a forwarded link cannot file a request against another company.
- **SPEC-7.291**: The created ticket's created_by_id is the issuing MSP user, never the client; also, the ticket's acting/created-by user is the MSP user who issued the link (resolved.created_by_id), never the client, since the submitter has no `users` row and created_by_id is NOT NULL.
- **SPEC-7.292**: Parent_ticket_id is the parent the link was issued with (None for a single-person link), and procedure_kb_article_id is the form definition's own kb_article_id, since the form definition IS the request type.
- **SPEC-7.293**: The receipt returns the created ticket's number and the token's remaining-uses count, nothing else from the submission.
- **SPEC-7.294**: The ticket title's summary is the first answered Text-type field in the form's own field order, falling back to "client request" when the form has no text field.
- **SPEC-7.295**: The ticket description renders each answered field as its own Markdown list item in the form's field order using its label, with an unanswered field dropped and a textarea answer's internal newlines kept as Markdown hard breaks.
- **SPEC-7.296**: All draft routes (list, upsert, delete) require an admin user, matching the create/update gating on definitions.
- **SPEC-7.297**: Registered before `/forms/{id}` so the literal path segment `drafts` is never captured as a form id by the `{id}` route.
- **SPEC-7.298**: Returns only drafts owned by the calling user, filtered by tenant (RLS) and user_id in the WHERE predicate, ordered by updated_at DESC.
- **SPEC-7.299**: A serialized payload over MAX_PAYLOAD_BYTES (262144) is rejected loudly with the exact size and limit, never silently truncated.
- **SPEC-7.300**: A payload that fails to serialize to JSON is rejected with a bad-request error naming the failure.
- **SPEC-7.301**: A form_definition_id must resolve to a definition in the caller's own tenant, otherwise NotFound("Form"); this exists even though RLS already scopes the draft row, to stop a caller filing a draft against another tenant's definition id and having it echoed back.
- **SPEC-7.302**: A single atomic INSERT ... ON CONFLICT ... DO UPDATE (never read-then-write), against one partial unique index per branch, so two overlapping autosave writes race into an UPDATE rather than a duplicate row or a conflict.
- **SPEC-7.303**: User_id is part of the DELETE predicate itself (not checked afterward); deleting 0 rows, including a draft owned by someone else, is a 404 "Draft", deliberately not a 403, so the caller cannot learn the draft id exists.
- **SPEC-7.304**: Best-effort; a database error here is only logged and never propagates to fail the caller's create/update request.
- **SPEC-7.305**: Returns only definitions with both is_active = TRUE and portal_visible = TRUE, ordered by name ASC; a retired or internal-only form never appears.
- **SPEC-7.306**: 404 "Form" for a form_id that does not exist, is retired, or is not portal_visible, so this endpoint cannot be used to enumerate internal forms by id.
- **SPEC-7.307**: Contact_info falls back to the organisation's phrase when the definition sets none.
- **SPEC-7.308**: People and person_number are always 1 on the portal path, since a portal form is filled in by one signed-in contact exactly once.

### 7.6 Email intake

- **SPEC-7.309**: Message_id must be 1-255 chars; the <...> wrapper is preserved verbatim.
- **SPEC-7.310**: From_email must be a syntactically valid email address of at most 254 chars.
- **SPEC-7.311**: From_name, when present, must be at most 200 chars.
- **SPEC-7.312**: Subject must be 1-500 chars and becomes the created ticket's title verbatim.
- **SPEC-7.313**: Body_html is never used to build the ticket description or the reply comment content; only body_text feeds those paths; also, body_text, never body_html, feeds the description body.
- **SPEC-7.314**: References defaults to an empty list when omitted; it is the concatenation of In-Reply-To + References header values.
- **SPEC-7.315**: Raw_headers defaults to {} when absent from the payload.
- **SPEC-7.316**: Attachments defaults to an empty list when absent; each element is nested-validated and req.validate() rejects the whole request if any entry fails its own constraints.
- **SPEC-7.317**: Req.validate() runs, mapped through AppError::from, before the bearer is resolved or intake runs; an invalid payload never reaches resolve_token or intake.
- **SPEC-7.318**: Authentication is a bearer token read directly off the request, not the normal user-session/cookie auth middleware.
- **SPEC-7.319**: Returns AppError::Unauthorized when the Authorization header is absent, is not valid header-string text, does not start with "Bearer " or "bearer " (other casings rejected), or has an empty token after stripping the prefix.
- **SPEC-7.320**: Matches token_hash against a SHA-256 hash of the bearer, requiring kind='email_intake' AND revoked_at IS NULL; an absent, revoked, or wrong-kind token fails with AppError::Unauthorized regardless of tenant.
- **SPEC-7.321**: Last_used_at is updated to NOW() unconditionally on every successful resolve, including a would-be dedup/threaded request.
- **SPEC-7.322**: This lookup and the paired last_used_at bump run on the BYPASSRLS migrator pool, not a tenant-scoped transaction, because resolving the tenant from an opaque bearer has no tenant context to set as the RLS GUC beforehand.
- **SPEC-7.323**: Evaluates, in order, (1) dedup by message_id, (2) threading by references (only if non-empty), (3) contact resolution, (4) creator lookup, (5) ticket creation; the first of (1)/(2) that hits short-circuits the rest; also, this module evaluates, in order, dedup by Message-Id, threading by references, contact resolution, creator lookup, and ticket creation; the first of dedup/threading that hits short-circuits the rest.
- **SPEC-7.324**: A dedup hit returns deduplicated=true, created=false, threaded=false, comment_added=false, attachments_stored=0 with the existing ticket's id/number, performing no further writes.
- **SPEC-7.325**: A gateway retry of an identical message_id on an already-created ticket is idempotent, returning the same ticket_id with deduplicated=true rather than erroring or creating a second ticket.
- **SPEC-7.326**: A concurrent-creation race on the same (tenant_id, message_id) is caught by the partial unique index backing tickets.email_message_id; on a unique-violation (SQLSTATE 23505) the dedup lookup is re-run and its result returned with deduplicated=true rather than propagating the DB error.
- **SPEC-7.327**: If the re-run dedup lookup after a unique-violation finds nothing (race window), the original database error is propagated unchanged.
- **SPEC-7.328**: Threading is only attempted when req.references is non-empty.
- **SPEC-7.329**: The threading lookup matches tickets.email_message_id = ANY(references) scoped to the caller's tenant, and when multiple tickets match more than one reference entry, selects the one with the latest created_at.
- **SPEC-7.330**: On a threading hit the response sets threaded=true, created=false, deduplicated=false and returns the matched ticket's id/number; the ticket itself is never mutated.
- **SPEC-7.331**: On a threading hit, the service attempts to resolve (or auto-create) a contact for from_email before deciding whether to append a reply comment.
- **SPEC-7.332**: An Err or Ok(None) from contact resolution is silently collapsed to "no contact" via .ok().flatten(); no reply comment is appended, comment_added=false, attachments_stored=0.
- **SPEC-7.333**: A failure from append_reply_comment is swallowed (not propagated), the response reports comment_added=false, attachments_stored=0, and the overall request still returns success with threaded=true.
- **SPEC-7.334**: Inserts into ticket_notes with note_type='public', content = the inbound body_text trimmed-and-checked (falling back to "(reply body empty)"), created_by_contact_id = the resolved contact, and created_by_id = the tenant's first active admin/manager, in a single begin_with_tenant transaction.
- **SPEC-7.335**: If the tenant has no active super_admin/admin/manager user, append_reply_comment fails with AppError::Configuration.
- **SPEC-7.336**: Attachments are only stored on the threading path if the reply comment append succeeded, and are then attached with note_id=Some(note_id) so they render under the reply note.
- **SPEC-7.337**: A reply's own message_id is never persisted onto the ticket or this note (only the creating email's message_id is ever written to tickets.email_message_id), so a gateway retry of the identical reply re-threads and appends a second, duplicate public note.
- **SPEC-7.338**: Contact lookup matches contacts by tenant_id and lower(email), case-insensitive on both the stored and inbound address.
- **SPEC-7.339**: If a matching contact is found and its company_id is non-null, that (contact_id, company_id) pair is used without consulting the tenant default-company setting.
- **SPEC-7.340**: If a matching contact is found but its company_id is null, the service falls back to the default_company_id tenant setting, logs a tracing::warn!, and uses the existing contact with the default company.
- **SPEC-7.341**: If no matching contact exists and email_intake/default_company_id is unset, resolution returns Ok(None) (no contact, no error raised at this layer).
- **SPEC-7.342**: If no matching contact exists and email_intake/default_company_id is set, the service auto-creates a contact with contact_type='primary', the lowercased from_email, and (first_name, last_name) derived from from_name.
- **SPEC-7.343**: Returns ("Contact", "") when from_name is None or blank after trim; otherwise splits on the first space, putting everything before it in first_name and the trimmed remainder in last_name, or puts the whole trimmed string in first_name with an empty last_name if there is no space or the remainder is blank.
- **SPEC-7.344**: After auto-creating a contact, ensure_primary_company_link is called in the same transaction so the primary contact_companies link matches the company_id mirror just written; a failure here rolls back the contact insert too.
- **SPEC-7.345**: When contact resolution yields no contact at all (Ok(None)), intake fails with AppError::BadRequest and this exact message.
- **SPEC-7.346**: Contact lookup, the default-company setting read, and the auto-create INSERT all run inside one begin_with_tenant (RLS tenant-GUC) transaction.
- **SPEC-7.347**: The creator (tickets.created_by_id) is the tenant's first active admin/manager, ordered by created_at.
- **SPEC-7.348**: If no such user exists, ticket creation fails with AppError::Configuration and no ticket is created.
- **SPEC-7.349**: The created ticket has source=Email, is_billable=false, contact_id/company_id from the resolved contact, email_message_id = the inbound message_id, title = the inbound subject verbatim, and description from build_description.
- **SPEC-7.350**: Produces "From: {from}\nReceived: {received}\n\n{body}" where {from} is "{name} <{email}>" when from_name is present and non-blank or else just {email}; {received} is Utc::now().to_rfc3339() (capture time, not any header date); and {body} is body_text or, if absent, "(no plaintext body provided)".
- **SPEC-7.351**: Ticket creation runs under AuditCtx::system(tenant_id.get()), attributed as a system actor for audit purposes, not the resolved creator user.
- **SPEC-7.352**: On successful creation the response sets created=true, deduplicated=false, threaded=false, comment_added=false.
- **SPEC-7.353**: File_name must be 1-255 chars; mime_type, if present, at most 100 chars; content_base64 must be non-empty.
- **SPEC-7.354**: Attachment bytes are decoded as standard (padded) base64 (RFC 4648) via STANDARD.decode.
- **SPEC-7.355**: A part whose content_base64 fails to decode is skipped (not counted in attachments_stored), logged via tracing::warn!, and does not fail the overall intake.
- **SPEC-7.356**: When mime_type is absent, the stored MIME type defaults to "application/octet-stream".
- **SPEC-7.357**: A part that fails to persist (e.g. exceeds the storage size cap) is skipped (not counted), logged via tracing::warn!, and does not fail the overall intake.
- **SPEC-7.358**: Attachments_stored equals the count of attachments actually persisted, which can be less than req.attachments.len() when a part was skipped, and is never greater.
- **SPEC-7.359**: On the create-ticket path, attachments are attributed to the resolved sender contact and attached with note_id=None.
- **SPEC-7.360**: Attachments are only stored on the threading path if the reply comment append succeeded, and are then attached with note_id=Some(note_id) so they render under the reply note.
- **SPEC-7.361**: Attachments from the retried payload are never stored on a dedup hit (attachments_stored=0 unconditionally), even if the payload includes attachments.
- **SPEC-7.362**: Every call to intake inserts an email_intake_log row before any dedup/threading/contact logic runs, so even a hard failure in later steps has an audit row.
- **SPEC-7.363**: Raw_body_html is written verbatim into email_intake_log.raw_body_html on every call, despite the models.rs doc comment calling the field "currently ignored by Phase 1.".
- **SPEC-7.364**: After intake_inner resolves, the log row is updated: on success ticket_id = the response's ticket_id and error = NULL; on failure ticket_id = NULL and error = the stringified AppError.
- **SPEC-7.365**: A failure to finalise (UPDATE) the log row is logged via tracing::warn! and does not change or mask the outcome already returned to the caller.
- **SPEC-7.366**: GET /email-intake-log/{id} requires an admin user and scopes the lookup to the caller's tenant.
- **SPEC-7.367**: GET /intake-tokens requires an admin user and returns every token (active and revoked) for the caller's tenant.
- **SPEC-7.368**: POST /intake-tokens requires an admin user and validates the request before calling the service; also, POST /intake-tokens validates kind (1-50 chars) and label (1-200 chars) before the service is called.
- **SPEC-7.369**: Create_token rejects any kind other than the literal "email_intake" with AppError::BadRequest.
- **SPEC-7.370**: A minted token's plaintext is 32 cryptographically random bytes, URL-safe-base64-without-padding encoded; only its SHA-256 hex hash is persisted to tenant_intake_tokens.token_hash.
- **SPEC-7.371**: The plaintext token is placed on this response exactly once; list_tokens and any subsequent read never return it; also, the plaintext token is present on this response exactly once; IntakeTokenResponse (list/get) has no token field.
- **SPEC-7.372**: DELETE /intake-tokens/{id} requires an admin user, scopes to the caller's tenant, and revokes idempotently.
- **SPEC-7.373**: Revoking a token that does not exist for the caller's tenant (wrong id, or belongs to another tenant) returns AppError::NotFound (rows_affected == 0).
- **SPEC-7.374**: Matches token_hash against a SHA-256 hash of the bearer, requiring kind='email_intake' AND revoked_at IS NULL; an absent, revoked, or wrong-kind token fails with AppError::Unauthorized regardless of tenant.
- **SPEC-7.375**: Every read/write to email_intake_log, contacts, tenant_settings, ticket_notes, and the non-auth-resolution paths of tenant_intake_tokens runs inside begin_with_tenant so the RLS tenant_isolation GUC is set; the one documented exception is the cross-tenant hash lookup (and its last_used_at bump) in resolve_token, which runs on the BYPASSRLS migrator pool.
- **SPEC-7.376**: TenantId::from_trusted mints the TenantId from the DB-read tenant_id column, since there is no request-session tenant claim to derive it from on this unauthenticated-by-user surface.
- **SPEC-7.377**: Admin-facing routes derive their TenantId via TenantId::from_trusted(u.tenant_id) from the authenticated admin user, not from any request body field.
- **SPEC-7.378**: No loop-detection or bounce-detection logic exists anywhere in this module; raw_headers is accepted and persisted to the audit log but never inspected for Auto-Submitted / X-Autoreply / Precedence / bounce-sender signals, so an auto-reply or relayed bounce is processed identically to a human reply.

### 7.7 Calendar, appointments and on-call

- **SPEC-7.379**: Create_appointment rejects an end_time that is not strictly after start_time.
- **SPEC-7.380**: Validates the effective range (request value, else stored), so a partial update cannot invert the stored range.
- **SPEC-7.381**: A non-blank recurrence_rule must parse as an RFC 5545 RRULE anchored on start_time.
- **SPEC-7.382**: Create_appointment rejects any referenced id that does not belong to this tenant; also, update_appointment rejects any referenced id that does not belong to this tenant.
- **SPEC-7.383**: A ranged read (both from and to, no appointment_type) expands recurring series and paginates the expanded set; otherwise it is a plain SQL-paginated list of stored rows.
- **SPEC-7.384**: Caps a single series' expanded occurrences at 1000; also, the series is anchored on the master's stored start_time, and a master whose recurrence_rule fails to parse is dropped (logged at warn) rather than failing the query.
- **SPEC-7.385**: Each expanded occurrence carries recurrence_parent_id set to the master's id and recurrence_rule cleared; the master row itself is never emitted.
- **SPEC-7.386**: Dispatch_view requires both from and to query parameters, and rejects to < from.
- **SPEC-7.387**: The dispatch board combines, for [from, to]: appointments (recurring expanded), weekly availability, approved time off, and current on-call coverage.
- **SPEC-7.388**: Delete_appointment returns 404 when no row matches (tenant_id, id); also, update_appointment returns 404 when no row matches (tenant_id, id).
- **SPEC-7.389**: The INSERT's ON CONFLICT DO NOTHING enforces at most one claimed row per (appointment_id, occurrence_start, reminder_minutes); returns true only when this call's insert won.
- **SPEC-7.390**: Due_reminders scans across all tenants (no tenant GUC) via the migrator pool; the window end is now + the largest configured reminder_minutes across the whole table, and no appointment having reminders configured (NULL max) short-circuits to an empty result.
- **SPEC-7.391**: An occurrence is never reported due once its start is at or before now; a negative reminder offset is skipped entirely.
- **SPEC-7.392**: With no NotificationsService wired, the tick dispatches nothing and performs no ledger writes.
- **SPEC-7.393**: The ledger row is claimed (INSERT) strictly before dispatch, so a crash between the two drops at most one reminder rather than risking a duplicate.
- **SPEC-7.394**: A dispatch failure after a successful ledger claim is logged as a warning and does not fail or retry the tick; the reminder stays recorded as attempted but is not counted in the dispatched total.
- **SPEC-7.395**: Dispatches appointment.reminder with recipient_user_id set to the appointment's assigned_to_id; also, runs as job name "calendar_reminders" on the shared scheduler at a 60s interval (interval configured at scheduler registration in src/main.rs).
- **SPEC-7.396**: A non-admin caller editing another user's availability is rejected with 403.
- **SPEC-7.397**: Full-replace is atomic (delete then insert in one transaction); a window with end_time <= start_time aborts the whole replace and the transaction rolls back any prior inserts in this call.
- **SPEC-7.398**: Day_of_week must be in [0,6]; violating it fails request validation before the service is called.
- **SPEC-7.399**: Create_time_off rejects end_date < start_date.
- **SPEC-7.400**: A non-admin caller creating a time-off request has user_id forced to their own id.
- **SPEC-7.401**: Approve_time_off rejects a status other than exactly "approved" or "rejected"; also, approving/rejecting time off requires RequireManager.
- **SPEC-7.402**: Only status = 'approved' time off rows block dispatch; pending and rejected requests never block.
- **SPEC-7.403**: On_call_now considers only schedules with is_active = true, resolving exactly one OnCallNowResponse per schedule.
- **SPEC-7.404**: Weekly picks user_ids[ISO_week(now) % len], daily picks user_ids[day_of_year(now) % len], any other rotation_type picks user_ids[0], and an empty user_ids resolves to null.
- **SPEC-7.405**: Create_on_call requires RequireManager in addition to RequireCalendar; also, delete_on_call requires RequireManager in addition to RequireCalendar; also, update_on_call requires RequireManager in addition to RequireCalendar.
- **SPEC-7.406**: Kind must be one of the values accepted by validate_scheduling_template_kind ("dispatch" | "calendar").
- **SPEC-7.407**: Duration_minutes must be >= 1; travel_before_minutes / travel_after_minutes must be >= 0.
- **SPEC-7.408**: Create_template rejects a default_ticket_id that does not belong to this tenant; also, update_template rejects a default_ticket_id that does not belong to this tenant.
- **SPEC-7.409**: A field omitted from the PUT body is left unchanged (COALESCE against the stored row), never nulled.

### 7.8 Projects, phases and tasks

- **SPEC-7.410**: Both data and count queries scope to tenant_id = $1.
- **SPEC-7.411**: Staff caller must be authenticated.
- **SPEC-7.412**: Contact caller must hold projects:read.
- **SPEC-7.413**: Server-stamped company_id overrides any client value, which also excludes NULL-company house projects from the contact view.
- **SPEC-7.414**: A contact caller gets ContactProjectResponse, never the staff ProjectResponse.
- **SPEC-7.415**: Server-stamped company_id overrides any client value, which also excludes NULL-company house projects from the contact view.
- **SPEC-7.416**: Status/q length caps enforced before the query runs.
- **SPEC-7.417**: Staff caller must be authenticated.
- **SPEC-7.418**: Contact caller must hold projects:read.
- **SPEC-7.419**: A company mismatch 404s, same as a missing project, so a probe cannot tell the two apart.
- **SPEC-7.420**: POST/PUT/DELETE projects and every phase/task-status/project-type/task/task-dependency route require RequireProjects, so a contact caller 401s on all of them.
- **SPEC-7.421**: DELETE /projects/{id} additionally requires admin.
- **SPEC-7.422**: Create/update/delete task-statuses require admin in addition to RequireProjects.
- **SPEC-7.423**: Create/update/delete project-types require admin; GET /project-types needs only RequireProjects.
- **SPEC-7.424**: GET /projects/summary requires RequireProjects.
- **SPEC-7.425**: The phase routes and the task-dependency routes have no SPA caller as of the 2026-09-22 parity record above.
- **SPEC-7.426**: Project name must be 1 to 80 characters.
- **SPEC-7.427**: Project_type defaults to "client" when omitted.
- **SPEC-7.428**: Status defaults to "planning" when omitted.
- **SPEC-7.429**: Billing_method defaults to "time_and_materials" when omitted.
- **SPEC-7.430**: Is_billable defaults to true when omitted.
- **SPEC-7.431**: Accepts a JSON number, a numeric string, or null; any other JSON type is rejected.
- **SPEC-7.432**: Budget_hours must be non-negative, at most 2 decimal places, and under the column's magnitude.
- **SPEC-7.433**: Budget_amount must be non-negative, at most 2 decimal places, and under the column's magnitude.
- **SPEC-7.434**: Default_due_business_days, if present, must be in 0..=365.
- **SPEC-7.435**: Project_type_id is resolved from the legacy project_type string, NULL if no matching project_types row.
- **SPEC-7.436**: The Create audit row is written in the same transaction as the INSERT, before = NULL.
- **SPEC-7.437**: The create response is the freshly re-read project, so derived fields are populated, not reconstructed.
- **SPEC-7.438**: Company_name via tenant-scoped correlated subquery; NULL if no company_id or the company row is gone.
- **SPEC-7.439**: Project_manager_name via tenant-scoped correlated subquery, NULLIF(TRIM(...), '').
- **SPEC-7.440**: Actual_hours sums duration_minutes/60.0 over non-rejected time entries.
- **SPEC-7.441**: Actual_amount sums total_amount over the same non-rejected entry set.
- **SPEC-7.442**: A missing or foreign-tenant project id 404s.
- **SPEC-7.443**: Independently-numbered placeholders per query, so an added filter never reuses an index between the two.
- **SPEC-7.444**: Default sort is created_at; order_by rejects any key outside mokosh_types::sort::PROJECTS.
- **SPEC-7.445**: Q filters name ILIKE '%<q>%', applied as the last optional condition in both queries.
- **SPEC-7.446**: Before/after snapshots are taken inside one transaction, for the audit diff.
- **SPEC-7.447**: Every field uses COALESCE($n, column), so an omitted field in the request leaves the stored value unchanged.
- **SPEC-7.448**: Zero rows affected (missing or foreign-tenant id) 404s.
- **SPEC-7.449**: A description-only change that is purely a checklist checkbox toggle writes no audit row.
- **SPEC-7.450**: Name (1 to 80 chars), default_due_business_days (0..=365), and budget_hours/budget_amount follow the same validation as create.
- **SPEC-7.451**: Deletes only the row matching both tenant_id and id; zero rows affected 404s.
- **SPEC-7.452**: Counts_by_status and total_budget are computed in one transaction, so both describe the same instant; also, counts_by_status and total_budget are computed together in one transaction so both describe the same instant.
- **SPEC-7.453**: Billing_method defaults to "time_and_materials" and is_billable defaults to true when the stored column is NULL (predating a NOT NULL default).
- **SPEC-7.454**: 404s if the project does not exist for the tenant, 409s if its status is "cancelled" (British spelling, matching the migration 007 CHECK).
- **SPEC-7.455**: Runs inside the caller's tenant-scoped transaction, shared with the subsequent phase/task INSERT.
- **SPEC-7.456**: Any status other than "cancelled" permits the attach; there is no other status-based gate.
- **SPEC-7.457**: Lists only phases scoped to tenant_id and project_id, ordered by sort_order, paginated.
- **SPEC-7.458**: Phase name must be 1 to 100 characters.
- **SPEC-7.459**: Phase status defaults to "not_started" when omitted.
- **SPEC-7.460**: Audit row written in the same transaction, and the returned phase is built from the request, not re-read.
- **SPEC-7.461**: A full-field UPDATE (not COALESCE'd) scoped by tenant_id and id; no matching row 404s; no audit row is written on update.
- **SPEC-7.462**: Does not call ensure_project_open, so a phase under a now-cancelled project can still be edited.
- **SPEC-7.463**: Deletes by tenant_id + id; zero rows affected 404s; no audit row is written on delete.
- **SPEC-7.464**: Lists rows scoped to tenant_id, ordered by sort_order, name, paginated.
- **SPEC-7.465**: Name must be 1 to 50 characters, color 1 to 7 characters; is_completed and sort_order default to false/0 when omitted.
- **SPEC-7.466**: Create audit row written in the same transaction as the INSERT; response is built from the request, not re-read.
- **SPEC-7.467**: A full-field UPDATE scoped by tenant_id + id; zero rows affected 404s; no audit row is written on update.
- **SPEC-7.468**: Deletes by tenant_id + id; zero rows affected 404s; no audit row written, and no FK-violation mapping (contrast with delete_project_type).
- **SPEC-7.469**: Lists rows scoped to tenant_id, ordered by sort_order, name, paginated.
- **SPEC-7.470**: Name must be 1 to 50 characters; is_active defaults to true, is_default/sort_order default to false/0; is_system is never settable from the wire.
- **SPEC-7.471**: Creating a default clears is_default on every other tenant row first, in the same transaction.
- **SPEC-7.472**: Updating to is_default = true clears is_default on every other tenant row except the one being updated, in the same transaction.
- **SPEC-7.473**: A Create audit row is written; the new row's is_system is always false (API-created types are never system rows).
- **SPEC-7.474**: Zero rows is 404 "Project type"; no audit row is written on update.
- **SPEC-7.475**: A missing row 404s; a row with is_system = true 409s and the DELETE is never attempted.
- **SPEC-7.476**: A foreign-key violation (23503, a project still references this type) maps to 409 instead of propagating a 500.
- **SPEC-7.477**: Status_name and status_is_completed are resolved via a tenant-scoped correlated subquery against task_statuses, not a join.
- **SPEC-7.478**: Title must be 1 to 255 characters.
- **SPEC-7.479**: Priority defaults to "medium" when omitted.
- **SPEC-7.480**: Estimated_hours, if present, must pass the shared hours validator.
- **SPEC-7.481**: Rejects an inverted start_date/due_date range with a 422 keyed onto due_date (equal dates and either side None are accepted).
- **SPEC-7.482**: Applies the identical cross-field date check when both dates are supplied in the same PUT.
- **SPEC-7.483**: An omitted due_date defaults from today + N business days, where N is the project's default_due_business_days override (0 disables it) if set, else the tenant-wide scheduling default; a supplied due_date is used as-is.
- **SPEC-7.484**: Creating a task shares the ensure_project_open guard from phase creation, so a task cannot be attached to a cancelled or missing project.
- **SPEC-7.485**: The Create audit row is written in the same transaction as the INSERT, before = NULL.
- **SPEC-7.486**: The create response is the freshly re-read task, so derived fields (status_name, assigned_to_name, actual_hours, logged_hours) are populated, not reconstructed.
- **SPEC-7.487**: Assigned_to_name is a tenant-scoped correlated subquery against users, NULL when unassigned.
- **SPEC-7.488**: Actual_hours and logged_hours are computed identically, summing duration_minutes/60.0 for every time entry whose approval_status is not 'rejected' (PMS-944: approval state is not a fact about whether the work happened).
- **SPEC-7.489**: Tasks are scoped to tenant_id and project_id, ordered by sort_order then created_at, paginated.
- **SPEC-7.490**: This query (and its row mapping) is identical to get_task's single-row query below.
- **SPEC-7.491**: A missing or foreign-tenant task id 404s.
- **SPEC-7.492**: Before/after snapshots are taken inside one transaction, for the audit diff.
- **SPEC-7.493**: An effective start/due range combining the request's supplied fields with the stored row's existing values is validated before the UPDATE runs, so a partial PUT cannot invert the range against unsupplied stored dates.
- **SPEC-7.494**: Every field except completed_at uses COALESCE($n, column), so an omitted field in the request leaves the stored value unchanged.
- **SPEC-7.495**: Completed_at is inferred from the supplied status_id's is_completed flag via a CASE, not a second read: moving to a completed status stamps it (if not already stamped), moving to a non-completed status clears it, and an omitted status_id leaves it untouched.
- **SPEC-7.496**: Completed_at only stamps NOW() the first time (COALESCE keeps an existing timestamp), so re-saving an already-completed task does not move its completion time.
- **SPEC-7.497**: Zero rows affected (missing or foreign-tenant id) 404s.
- **SPEC-7.498**: Unlike update_project's task-marker-only skip, every task update writes an audit row, with no equivalent description-only exemption.
- **SPEC-7.499**: As with create, the update response is the freshly re-read task, not reconstructed from the request.
- **SPEC-7.500**: Deletes by tenant_id + id; zero rows affected 404s; no audit row is written on delete.
- **SPEC-7.501**: Priority defaults to "medium" and sort_order defaults to 0 when the stored column is NULL.
- **SPEC-7.502**: A task cannot depend on itself; rejected before any transaction opens.
- **SPEC-7.503**: A recursive CTE walks the existing depends_on chain from the candidate dependency back toward the task; if task_id is already reachable, adding the edge would close a cycle and is rejected with 409.
- **SPEC-7.504**: The recursive chain and its join are scoped to tenant_id = $1 at every step, so a cross-tenant dependency chain can never mask or create a cycle.
- **SPEC-7.505**: ON CONFLICT DO NOTHING makes re-adding an existing (task_id, depends_on_task_id) edge a silent no-op rather than a duplicate row or an error.
- **SPEC-7.506**: On the no-op path above, this re-read finds no row with the freshly generated dep_id (the existing row kept its own id), so `after` is None and a Create audit row is still written with before = after = None.
- **SPEC-7.507**: Deletes the edge by tenant_id, task_id and depends_on_task_id; this is idempotent (no error, no audit row) whether or not the edge existed.
- **SPEC-7.508**: The cycle check and the self-dependency check are the only guards; there is no FK existence pre-check for task_id or depends_on before the INSERT (a foreign-tenant or missing task id surfaces as a database FK error, not an AppError).

### 7.9 Approvals

- **SPEC-7.509**: From_str rejects any string outside these four variants; the DB CHECK on the target column enforces the same set; also, the approvals surface supports exactly these four parent entity kinds (ticket, change_request, quote, time_entry).
- **SPEC-7.510**: The legacy ticket_id column is populated only for a Ticket target; every other target inserts NULL, which is also why ApprovalResponse.ticket_id is Some only when target is "ticket".
- **SPEC-7.511**: Entity_reference resolves to ticket_number/quote_number only, and is NULL for change_request/time_entry and for a deleted parent.
- **SPEC-7.512**: Entity_label falls back to the time_entry duration/date string via `||` so a deleted parent propagates NULL.
- **SPEC-7.513**: The app layer requires exactly one of the three approver kinds set, before any DB write.
- **SPEC-7.514**: Returns 404 ("Ticket") when no row in tickets matches (id, tenant_id), before any approver validation or insert.
- **SPEC-7.515**: The time-entry, change-request, and quote create/list routes each run this first, returning 404 with the human noun (never the raw table name) when the parent is absent in the caller's tenant.
- **SPEC-7.516**: Reachable only when RequireTimesheets succeeds; a tenant with timesheets disabled sees whatever 404/403 that extractor itself produces.
- **SPEC-7.517**: A non-null approver_contact_id must name a portal contact of this tenant; checked here (not left to the FK) because the FK bypasses RLS.
- **SPEC-7.518**: The legacy ticket_id column is populated only for a Ticket target; every other target inserts NULL, which is also why ApprovalResponse.ticket_id is Some only when target is "ticket".
- **SPEC-7.519**: Approver_role is capped at 50 chars and notes at 4000 chars; req.validate() runs in the route handler before the service.
- **SPEC-7.520**: This INSERT omits status, decided_by_id, decided_by_contact_id, and decided_at, so a new row always starts as the DB defaults: status 'pending' and those columns NULL.
- **SPEC-7.521**: This existence check and create_for_entity's insert run as separate transactions (the tx below is dropped before calling in), so the two are not atomic with each other.
- **SPEC-7.522**: Always inserts requested_by_id NULL, requested_by_contact_id = contact_id, approver_role fixed to 'admin'; a caller-specified approver is never honoured here.
- **SPEC-7.523**: 404s ("Ticket") when the ticket is absent from the caller's tenant, then delegates with the same fixed admin default.
- **SPEC-7.524**: The app layer requires exactly one of the three approver kinds set, before any DB write.
- **SPEC-7.525**: A non-null approver_contact_id must name a portal contact of this tenant; checked here (not left to the FK) because the FK bypasses RLS.
- **SPEC-7.526**: Only "approve"/"reject" are accepted; anything else is a 400, otherwise approved/rejected status.
- **SPEC-7.527**: Lock the row before authorization so two concurrent decisions cannot both read pending and both pass.
- **SPEC-7.528**: 404 ("Approval") when no row matches.
- **SPEC-7.529**: 400 "Approval is already {status}" when the locked row is not pending.
- **SPEC-7.530**: Authorization checks only approver_user_id and approver_role, never approver_contact_id, so a contact-only row always yields 403 here regardless of staff role.
- **SPEC-7.531**: UPDATE is reconditioned on status='pending'; zero rows affected means 400 "Approval is already decided".
- **SPEC-7.532**: Writes status, decision_notes, decided_by_id and decided_at, and never decided_by_contact_id.
- **SPEC-7.533**: Commits, then re-fetches via get() to build the response rather than constructing it from the UPDATE's data.
- **SPEC-7.534**: Requires approvals:decide, loaded from the database per request, before decide_as_contact runs.
- **SPEC-7.535**: Scoped by (tenant_id, id, approver_contact_id = contact_id); a row not addressed to this contact is indistinguishable from a nonexistent id, so it is 404, never 403.
- **SPEC-7.536**: Locks the row with FOR UPDATE before checking status, the same concurrency reason as the staff path.
- **SPEC-7.537**: 400 "Approval is already {status}" when not pending, and "Approval is already decided" if the UPDATE below affects zero rows.
- **SPEC-7.538**: Decision-value validation identical to the staff path: only "approve"/"reject", same error text.
- **SPEC-7.539**: Writes status, decision_notes, decided_by_contact_id and decided_at; never decided_by_id.
- **SPEC-7.540**: Writes a best-effort portal audit row; a failure to write it does not fail the decision, only logs a warn.
- **SPEC-7.541**: The contact id comes only from the authenticated session, never from the request body.
- **SPEC-7.542**: 404 ("Approval") when no row matches.
- **SPEC-7.543**: 400 "Approval is already {status}" when the row's status is not pending.
- **SPEC-7.544**: 403 unless requested_by_id == caller_id, so a contact-filed row (requested_by_id NULL) is never cancellable by any staff caller through this route.
- **SPEC-7.545**: Requested_by_id must decode as Option<Uuid>, not a bare Uuid, since it is NULL on a contact-filed row (PMS-1236: decoding it non-optional made such a cancel 500 instead of the intended 403).
- **SPEC-7.546**: Sets status='cancelled' and decided_at=NOW() without touching any decided_by column; the row is retained, not deleted; also, the row is retained with status 'cancelled', not deleted, so this returns a bare {"cancelled": true} rather than the updated ApprovalResponse.
- **SPEC-7.547**: Unlike decide/decide_as_contact, this UPDATE takes no row lock and is not reconditioned on status='pending', so a concurrent decide/cancel racing between the read above and this UPDATE can overwrite an already-decided row's status.
- **SPEC-7.548**: Returns every approval for (tenant, target, entity_id) ordered requested_at DESC, no status filter, no pagination.
- **SPEC-7.549**: Status pending and (approver_user_id = caller OR approver_role = ANY(roles_held)), ordered requested_at ASC.
- **SPEC-7.550**: Deliberately a one-element array holding only this role; a future multi-role identity is not currently supported by this call site.
- **SPEC-7.551**: Identical WHERE predicate to pending_for_user, so the count and the list can never disagree for the same inputs.
- **SPEC-7.552**: Filters strictly on status pending and approver_contact_id = contact_id, the id taken only from the session; also, the contact plane's pending list and count both require approvals:decide before reading.
- **SPEC-7.553**: Begin_with_tenant sets the app.current_tenant GUC transaction-locally so reads respect the fail-closed RLS policy.
- **SPEC-7.554**: 404 ("Approval") when no row matches (tenant_id, id); every mutating call re-fetches through this to build its response.
- **SPEC-7.555**: Each *_name column is NULLIF(TRIM(CONCAT(...))) so a blank or deleted name resolves to NULL, never an empty string.
- **SPEC-7.556**: An id set on a row whose resolved name column came back NULL is collected here and logged, tagged per call site; this never changes the HTTP response.
- **SPEC-7.557**: Every method also takes tenant_id explicitly and filters on it in SQL, so no query here relies solely on RLS.
- **SPEC-7.558**: Opens its own tenant-scoped transaction for the parent lookup rather than reusing a pool-level connection, so the check stays correct now that these tables are under fail-closed RLS.

### 7.10 Notifications

- **SPEC-7.559**: Dispatch opens exactly one begin_with_tenant transaction per call, covering rule lookup, template load, preference reads and every insert, and commits it before returning.
- **SPEC-7.560**: Render_event (and enrich_with_branding it calls) never opens a second transaction; both run their reads on the connection the caller's transaction already set the tenant GUC on.
- **SPEC-7.561**: Returns the total notifications rows actually inserted and propagates any database error to the caller rather than swallowing it.
- **SPEC-7.562**: Every caller awaits dispatch inline for the row write only; the queued rows are delivered asynchronously later by DispatcherWorker.
- **SPEC-7.563**: Only active rules for this tenant and event_type are considered; inactive or other-tenant rules are never looked up.
- **SPEC-7.564**: A missing context key never matches, an array expected value matches by containment ("in"), a scalar expected value requires exact equality; absent conditions or {} match unconditionally; also, a rule whose conditions do not match the dispatch context is skipped entirely (see rule_conditions_match for the match semantics).
- **SPEC-7.565**: A rule with no template_id, a missing template, or an inactive template is skipped, logged via warn!, and contributes zero to the fanout count; dispatch never falls back to a synthetic subject/body.
- **SPEC-7.566**: Template_id is required at both the HTTP validation layer and independently here, so non-HTTP callers of create_rule/update_rule are also gated.
- **SPEC-7.567**: Recipients are the union of rule.recipients.user_ids with an optional context.recipient_user_id, of rule.recipients.emails with an optional context.recipient_email, and of rule.recipients.contacts with an optional context.recipient_contact_id, each deduplicated.
- **SPEC-7.568**: An email address that case-insensitively matches one of this rule's user_ids' own email is dropped from the emails list before fan-out, so the same person is never queued twice.
- **SPEC-7.569**: For in_app, contact_ids are the only recipients filtered by contact preferences and emails is forced empty; every other channel forces contact_ids empty.
- **SPEC-7.570**: Entity_type/entity_id are taken from context; entity_type must be non-empty and at most 50 chars, entity_id must parse as a UUID, otherwise the column stays NULL with no rejection error.
- **SPEC-7.571**: The template is rendered exactly once per rule, reused unchanged across every channel that rule fans out on.
- **SPEC-7.572**: A template with no subject leaves notifications.subject NULL rather than synthesizing one.
- **SPEC-7.573**: Body_html is rendered with Escape::Html while subject/body_text use Escape::Text; the rendered body_html is persisted on the row at dispatch time and never re-rendered by the worker.
- **SPEC-7.574**: Dispatch (unlike preview) logs one warn per message with a non-empty unresolved list; the placeholders still ship as literal {{key}} text.
- **SPEC-7.575**: One row per user_id via a single INSERT ... SELECT ... FROM UNNEST, status = 'pending', contact_id/recipient left NULL.
- **SPEC-7.576**: One row per address via a single UNNEST statement, status = 'pending', user_id/contact_id left NULL.
- **SPEC-7.577**: One row per contact_id via a single UNNEST statement, status = 'pending'; this branch only fires for in-app rows since contact_ids is empty for any other channel.
- **SPEC-7.578**: The JSON body is exactly {"fanout": <u64>} where the value is the count dispatch returned.
- **SPEC-7.579**: Preview renders through the identical render_event function dispatch uses, issues only read-only SELECTs, and commits its own begin_with_tenant transaction despite writing nothing.
- **SPEC-7.580**: One NotificationPreviewResponse per (rule, channel) pair in the same order dispatch iterates them.
- **SPEC-7.581**: User_id recipients render as their resolved email with a fallback to the bare UUID; contact_ids are left out of the response entirely.
- **SPEC-7.582**: Unresolved names the exact {{key}} placeholders that did not resolve; those keys stay literal in subject/body_text/body_html rather than being fabricated as a sample send-time value.
- **SPEC-7.583**: Preview requires only RequireAuth, not RequireAdmin, because it exposes only the caller's own tenant's templates/rule-recipients, already exposed by the list routes.
- **SPEC-7.584**: Opt-out by default: no row accepts every channel; is_enabled = false rejects every channel; is_enabled = true (or NULL) accepts only a channel in channel_types. The same function governs both user and contact (contact_notification_preferences) acceptance.
- **SPEC-7.585**: User and contact preference rows are each batch-loaded in exactly one query per dispatch call, never once per (recipient, channel) pair in a nested loop.
- **SPEC-7.586**: Upserts on the unique (user_id, event_type) constraint; the caller can only ever write their own preferences.
- **SPEC-7.587**: Is_enabled defaults to true when omitted from the request JSON.
- **SPEC-7.588**: Lists only the authenticated caller's own rows (tenant_id + user_id), ordered by event_type, paginated.
- **SPEC-7.589**: No zero-key constructor exists, so a caller cannot silently make config_encrypted a no-op.
- **SPEC-7.590**: A config that fails to parse as JSON becomes Null rather than failing the whole list call.
- **SPEC-7.591**: Channel_type is a free-form String here; nothing in create_channel/update_channel enforces the documented set.
- **SPEC-7.592**: Channel/template/rule update and delete are tenant-scoped (WHERE tenant_id = $1 AND id = $2); a missing or other-tenant row is AppError::NotFound (404), never 403.
- **SPEC-7.593**: Create_channel/update_channel/create_template/update_template/create_rule/update_rule each write exactly one audit_write row in the mutation's transaction; the matching delete_* methods write none.
- **SPEC-7.594**: The worker recognizes only "in_app" and "email"; any other channel_type is a permanent, non-retrying failure, even though UpsertNotificationChannelRequest's doc comment lists other names as configurable.
- **SPEC-7.595**: Every dispatch and preview call enriches context with msp_name, msp_logo_url, msp_primary_color, msp_support_email, msp_footer_line, msp_footer_line_html and app_name before rendering.
- **SPEC-7.596**: A caller-supplied msp_name/msp_logo_url/msp_primary_color/msp_support_email always wins over the tenant's stored branding, since ensure_key only inserts when the key is absent.
- **SPEC-7.597**: With_app_name always overwrites any caller-supplied app_name with the deployment's configured product name, so context data can never rename the product in an outbound email.
- **SPEC-7.598**: A non-object context is replaced with {} before branding keys are attached, so those keys are never silently dropped.
- **SPEC-7.599**: Msp_name defaults to the literal "Mokosh Platform" when the tenant's name is empty or the tenant row is not found.
- **SPEC-7.600**: Msp_logo_url is always an absolute http(s) URL or the empty string, never a relative path.
- **SPEC-7.601**: Msp_primary_color is always a non-empty color value, defaulting to "#111827" (DEFAULT_PRIMARY_COLOR) when blank or absent.
- **SPEC-7.602**: Msp_footer_line composition rule (and its HTML twin below), including the escaping of both msp_name and the support email in the HTML variant.
- **SPEC-7.603**: Flat, non-recursive, non-conditional {{key}} substitution against the top-level fields of context only; no dotted-path or nested-object lookup.
- **SPEC-7.604**: A string value is emitted verbatim; any other JSON value type is emitted via its Display/to_string representation.
- **SPEC-7.605**: A {{key}} absent from context keeps its original internal whitespace in the output while the trimmed key is appended once (deduplicated) to the unresolved list.
- **SPEC-7.606**: An unterminated {{ with no matching }} emits the literal {{ plus the remaining input verbatim and returns immediately, adding nothing to unresolved.
- **SPEC-7.607**: Under Escape::Html every value is HTML-escaped unless its key is in MARKUP_KEYS (raw markup built in Rust); under Escape::Text nothing is ever escaped.
- **SPEC-7.608**: Exactly one tracing::trace! event at RENDER_TRACE_TARGET per render pass (subject/body_text/body_html are three separate passes, one per rule, not one per channel).
- **SPEC-7.609**: Only channel_type = 'in_app' rows, scoped to tenant_id plus either user_id or contact_id, never both in one query.
- **SPEC-7.610**: The staff arm requires CallerContext::Staff plus auth.user to be Some (staff_user), else AppError::Unauthorized.
- **SPEC-7.611**: The contact arm additionally requires a DB-loaded require_capability(caps::NOTIFICATIONS_READ) check, separate from session resolution.
- **SPEC-7.612**: Zero rows affected returns AppError::NotFound("Notification") (404); a row owned by a different user/contact/tenant is never a 403/401.
- **SPEC-7.613**: Ordered created_at DESC and paginated via the standard envelope; also, reject_unsupported_sort() runs at the route layer before the service query.
- **SPEC-7.614**: Status defaults to the literal "pending" if the DB column is unexpectedly NULL, rather than erroring.
- **SPEC-7.615**: 25 rows are drained per scheduled run() tick; the worker carries no per-tick parameter beyond this constant.
- **SPEC-7.616**: One SQL statement selects due rows (pending and ready, or sending whose 600s claim has expired), oldest first, FOR UPDATE SKIP LOCKED, and in the same statement sets status='sending', bumps attempt_count and stamps next_attempt_at = NOW() + CLAIM_TIMEOUT_SECS, recovering from a worker crash mid-tick with no extra schema.
- **SPEC-7.617**: BACKOFF_SECS = [60, 300, 1800, 7200, 21600] indexed by attempt_count - 1 (clamped to 0); once exhausted the row is marked failed with next_attempt_at = NULL.
- **SPEC-7.618**: A permanent delivery failure always sets status='failed'/next_attempt_at=NULL with no retry on first occurrence; this in_app case (no user_id and no contact_id) is one of several such cases (see also the email cases below and the unregistered-transport case); also, neither user_id nor recipient is a permanent failure; also, no resolvable address and no fallback recipient is a permanent failure; also, the worker recognizes only "in_app" and "email"; any other channel_type is a permanent, non-retrying failure, even though UpsertNotificationChannelRequest's doc comment lists other names as configurable.
- **SPEC-7.619**: A failed address lookup itself is a transient failure (the read broke, not that the notification is unsendable), so it backs off and retries rather than failing immediately.
- **SPEC-7.620**: An SMTP send failure via Mailer::send_multipart is always Transient ("smtp: {e}"), so it always gets the backoff ladder rather than an immediate permanent fail.
- **SPEC-7.621**: No database transaction is held open across any transport call; resolve_addresses resolves every address for the batch before any deliver call in the tick.
- **SPEC-7.622**: Only rows where channel == "email" and user_id is Some are looked up here; standalone-recipient rows and non-email channels are never included.
- **SPEC-7.623**: Filters to status = 'active', so an offboarded user's row is excluded and resolves to a permanent "user {uid} has no email" failure.
- **SPEC-7.624**: Committed rather than dropped, to avoid leaving the connection idle in transaction while the pool is needed for the sends this phase exists to free up.
- **SPEC-7.625**: Writes every tick's outcomes in one transaction using at most two statements regardless of batch size, each skipped entirely if its input list is empty.
- **SPEC-7.626**: Run_tick is public so the integration test suite can drive the worker deterministically; production scheduling goes through Job::run(), which calls run_tick(TICK_BATCH_SIZE) and only logs when stats.examined > 0.
- **SPEC-7.627**: On successful send, logs tracing::info! with id, channel and latency_ms (now minus created_at), making enqueue-to-sent latency observable.
- **SPEC-7.628**: Every channel/template/rule write route requires RequireAuth + RequireAdmin; every GET/list route needs only RequireAuth except list_channels, which also requires RequireAdmin.
- **SPEC-7.629**: DispatchNotificationRequest derives Validate but declares no field-level #[validate(...)] attributes, so req.validate()? at both the dispatch and preview routes is a structural no-op.
- **SPEC-7.630**: Documents that every route in this file is admin-surface API with no SPA caller as of the 2026-09-22 parity record, and lists the exempted paths below.


## 8. Integrations and dependencies

| Role | System | Direction and use |
|---|---|---|
| Database | PostgreSQL | Primary store (sections 5.1, 5.2). |
| Identity provider | OIDC provider (`bunyip` in the code) | Verifies `at+jwt` bearers via JWKS; sends account-deleted, grant-changed webhooks and back-channel logout; optional directory lookup, machine-credential status reads, host-secret and mail provider endpoints. |
| Payments | Stripe, PayPal | Per-tenant checkout, saved payment methods, refunds, webhook reconciliation. |
| Accounting | Xero, QuickBooks (Intuit) | OAuth connect, delegated invoice and bill issuing, mappings, signed webhooks. |
| RMM | Tactical RMM | Device and alert sync with an adapter. `mesh_central`, `datto`, `connectwise` and `ninja_rmm` are accepted as provider names but resolve to a stub that fails with "not implemented" and records it in `last_error`. Signed alert and status ingest endpoints. |
| Contact directories | Google People, Microsoft Graph, iCloud CardDAV, vCard files | One-way import. |
| Mail | SMTP relay, or the identity provider's mailer | Outbound mail; `log` provider writes to the log only. |
| Secrets | Infisical, the identity provider's host-secret route | Optional secret providers. |
| Object storage | Local filesystem, S3-compatible store | Attachments, logos, branding assets. |
| Geo and network data | IP2Location LITE, IP2Proxy | Optional local database files. |

Third-party systems are reached over HTTPS with `reqwest` (rustls); the SMTP transport uses the platform TLS library.

## 9. Data model and migrations

Every migration under `migrations/` is embedded at compile time via `sqlx::migrate!` and runs once, in filename order, against `mokosh_migrator`. Committed migrations are immutable (`common/scripts/check-migration-immutability.nu` fails CI on any modification, rename or deletion), so every `SPEC-9.<n>` requirement sourced from a migration is enforced solely by that migration having already run; none of the 291 migration files below carry an inline `// SPEC-9.<n>` comment, and this section is their only citation. `scripts/test-db-roles.sql` and `scripts/wipe_demo_seed.sql` are the only two files in this section's scope that are not migrations and that do carry inline `// SPEC-9.<n>` comments at their implementing statements.

### Tenancy

- **SPEC-9.1**: `tenants` is seeded at creation (migrations/002_tenants.sql) with a default row id `00000000-0000-0000-0000-000000000001`.
- **SPEC-9.2**: `tenants.kind` (migrations/019_tenant_kind.sql) distinguishes an organization tenant from a personal tenant; `tenants.personal_owner_id` (migrations/036_tenant_personal_owner.sql) replaces an earlier, fully reverted `bunyip_org_id` column (migrations/034, migrations/036).
- **SPEC-9.3**: Row-level security on every `tenant_id`-bearing table is first installed fail-open (migrations/024_triggers_and_rls.sql: a dynamic `information_schema` scan attaches a permissive policy and an `update_updated_at_column()` trigger to each matching table) and is then rewritten fail-closed (migrations/038_rls_fail_closed.sql: every such policy is replaced with one that adds `WITH CHECK` and the table is altered to `FORCE ROW LEVEL SECURITY`).
- **SPEC-9.4**: migrations/039_system_shared_class.sql establishes the "system-shared" row class: a row with `tenant_id IS NULL` is readable tenant-wide via an added `OR tenant_id IS NULL` read disjunct, and is only writable when the session GUC `app.allow_system_writes = 'on'` is set, enforced by trigger function `mokosh_guard_system_shared_row()`; helper `mokosh_enable_system_shared(target regclass)` opts a table into the class, but migration 039's own one-time loop attaches the disjunct only to tables that already existed that day.
- **SPEC-9.5**: migrations/130_system_shared_policy_on_optin.sql rewrites `mokosh_enable_system_shared()` to attach the `tenant_id IS NULL` read disjunct whenever a table opts in after migration 039, closing the gap left for tables created between 039 and 130.
- **SPEC-9.6**: migrations/040_backfill_comingled_default_tenant.sql is a read-only verification: it checks 32 named business tables for zero rows at the shared default tenant and raises if any are non-empty; it performs no write.
- **SPEC-9.7**: `tenants`, `tenant_membership_entitlements` (migrations/154), `platform_admins` (migrations/160), `mokosh_bunyip_grants` (migrations/225), `mokosh_grant_invitations` (migrations/267), `tenant_intake_tokens` (migrations/095/067) and `identities` (migrations/157) are deliberately exempt from per-tenant RLS because each serves a cross-tenant or pre-authentication lookup; none of them is a defect.
- **SPEC-9.8**: migrations/153_tenants_unique_name.sql adds a case-insensitive unique index on `tenants.name` that excludes personal tenants, so two organization tenants cannot share a case-insensitive name while two personal tenants may.
- **SPEC-9.9**: migrations/166_system_attribution_user_per_tenant.sql backfills, for every tenant lacking an active `super_admin`/`admin`/`manager` user, one `users` row with email `system+<slug>@mokosh.local`, role `admin`, status `active`, and `password_hash` left NULL so the row can never authenticate, solely to give `tickets.created_by_id` (NOT NULL) a value for portal-originated and email-intake tickets.
- **SPEC-9.10**: migrations/211_tenant_invitations_team_id.sql adds nullable `tenant_invitations.team_id`; a NULL value means a tenant-wide invite with no team assignment, and deleting the referenced team (`ON DELETE SET NULL`) must not invalidate an in-flight invitation.
- **SPEC-9.11**: migrations/245_mokosh_bunyip_grants_revoked_by.sql adds nullable `mokosh_bunyip_grants.revoked_by` constrained to `NULL, 'owner', 'grantee', 'system'`, recording who initiated a grant revoke; historical rows and pre-receiver-update webhook rows are left NULL.

### Identity and authentication

- **SPEC-9.12**: `users`, `user_sessions`, `api_keys`, `password_reset_tokens`, `teams`, `team_members` are created by migrations/003_auth.sql as the platform identity plane.
- **SPEC-9.13**: `user_oauth_identities` (migrations/018) is denormalized rather than tenant-joined, so RLS (migrations/041) is attached directly to the table rather than via a parent-join policy.
- **SPEC-9.14**: MFA recovery codes are added by migrations/029_user_mfa_recovery_codes.sql (a renamed replacement of an earlier colliding migration 027).
- **SPEC-9.15**: `tenant_invitations` is created by migrations/035_tenant_invitations.sql; `users.date_format_string` is added by migrations/037.
- **SPEC-9.16**: `users.profile_completed_at` is added by migrations/046; theme preferences are added by migrations/054.
- **SPEC-9.17**: `users.mfa_last_used_step`, `mfa_failed_attempts`, `mfa_locked_until` are added by migrations/084_user_mfa_attempt_lockout.sql to provide TOTP anti-replay and lockout.
- **SPEC-9.18**: migrations/085_mapps_330_backfill_users_to_admin.sql guardedly backfills `role = 'admin'` for every non-`super_admin`/`admin` user matching its WHERE clause; the UPDATE is idempotent (a second run matches zero rows).
- **SPEC-9.19**: `users.deleted_at` (migrations/087) is a tombstone column, not a hard delete.
- **SPEC-9.20**: migrations/088_deferrable_fk_constraints.sql converts every then-existing non-deferrable FK to `DEFERRABLE INITIALLY IMMEDIATE`; a new FK added by a later migration is not automatically covered and must declare `DEFERRABLE INITIALLY IMMEDIATE` itself if it needs that posture (see migrations/271 for a case that does).
- **SPEC-9.21**: `users.last_login_country` and `login_location_alerts` are added by migrations/089; `login_approvals` (migrations/090) and `user_login_devices` (migrations/091) are created with RLS attached inline at creation.
- **SPEC-9.22**: `users.password_changed_at` (migrations/093) and `contacts.portal_tokens_valid_from` (migrations/112) each define a cutoff before which an issued token/session is no longer honored.
- **SPEC-9.23**: `users.mfa_secret` is widened from a fixed-length type to `TEXT` by migrations/129_encrypt_user_mfa_secret.sql to hold AES-256-GCM ciphertext; no existing plaintext row is rewritten, and reclassification happens opportunistically on the next successful verify.
- **SPEC-9.24**: migrations/157_identities_and_memberships.sql creates `identities` (no `tenant_id`, no RLS, unique on `lower(email)`) and `tenant_memberships` (unique on `(identity_id, tenant_id)`), backfills both from `users`, and installs trigger `users_sync_to_identity` (function `sync_user_to_identity_and_membership`) that mirrors every INSERT/UPDATE on `users` into `identities` and `tenant_memberships` by `lower(email)` match.
- **SPEC-9.25**: migrations/158_identities_mfa_watermark.sql adds `identities.mfa_last_totp_step` (default 0) as a TOTP anti-replay watermark updated only when the new step is strictly greater than the stored one; a zero-row update means replay.
- **SPEC-9.26**: migrations/159_identities_sync_back_to_users.sql installs the reverse mirror trigger `identities_sync_to_users` (function `sync_identity_to_users`), which early-returns when `pg_trigger_depth() > 1` so a users-to-identities propagated write never re-propagates back to users.
- **SPEC-9.27**: migrations/160_platform_admins.sql creates `platform_admins` with no `tenant_id` and no RLS, unique on `lower(email)`, independent of any `users.role = 'super_admin'` row; migrations/161_platform_admins_backfill.sql backfills it from `users WHERE role = 'super_admin'` with `ON CONFLICT DO NOTHING` to tolerate cross-tenant email collisions.
- **SPEC-9.28**: migrations/162_retire_super_admin_users.sql guardedly neuters (sets `status = 'inactive'`, clears `password_hash`/`mfa_secret`/`mfa_enabled`) every `role = 'super_admin'` `users` row rather than deleting it, preserving FK-referenced attribution.
- **SPEC-9.29**: migrations/163_client_setup_password_isolation.sql adds a transaction-scoped opt-out: setting `app.skip_users_identity_mirror = 'on'` suppresses the users-to-identities mirror for that transaction, and the mirror functions only propagate `password_hash` `WHEN NEW.password_hash IS DISTINCT FROM OLD.password_hash`.
- **SPEC-9.30**: migrations/164_password_per_tenant_only.sql removes `password_hash` entirely from both mirror directions' UPDATE branches (the INSERT branch still seeds it once); `identities.password_hash` can never be overwritten by a `users` row after creation, and a `users` row can never be overwritten by an `identities` row.
- **SPEC-9.31**: migrations/165_contacts_portal_role.sql adds nullable `contacts.portal_role` constrained to NULL, `'admin'`, or `'user'`, with no backfill, distinguishing a tenant's portal owner from an invited sub-user.
- **SPEC-9.32**: migrations/195_rls_contact_prefs_and_memberships.sql replaces migration 149's RLS policy on `contact_notification_preferences` (which raised `invalid input syntax for type uuid: ""` on a pooled connection with no tenant GUC set) with the fail-closed `NULLIF(...)::uuid` form, and enables and forces RLS on `tenant_memberships` for the first time, superseding migration 157's claim that it was unRLS'd.
- **SPEC-9.33**: migrations/196_mfa_secret_leaves_the_mirror.sql widens `identities.mfa_secret` to `TEXT` and removes `mfa_secret` from both mirror functions' UPDATE branches, closing the defect where any TOTP verify would fan a stale or plaintext identity-plane secret back onto the sealed `users`-plane secret.
- **SPEC-9.34**: migrations/225_mokosh_bunyip_grants.sql creates `mokosh_bunyip_grants` with no `tenant_id` and no RLS (an intentionally cross-tenant table), unique on `(grantee_bunyip_user_id, mokosh_account_id)`, with a CHECK coupling `role IS NOT NULL` to `revoked_at IS NULL` and a CHECK restricting `role` to `admin|manager|technician|finance|read_only`.
- **SPEC-9.35**: migrations/226_users_bunyip_user_id.sql adds nullable `users.bunyip_user_id`, backfilled to each row's own `id`; a unique partial index enforces at most one `users` row per `(bunyip_user_id, tenant_id)` pair, and `users.id` itself is left as the sole primary key to avoid rewriting every FK referencing it.
- **SPEC-9.36**: migrations/234_token_lookup_hash.sql adds a nullable, equality-matchable `lookup_hash` (SHA-256 hex digest) to `password_reset_tokens` and `portal_setup_tokens` alongside the existing non-equality-matchable Argon2 `token_hash`; existing rows are not backfilled since the plaintext secret no longer exists to derive it from.
- **SPEC-9.37**: migrations/236_mokosh_bunyip_grants_event_at.sql adds `mokosh_bunyip_grants.event_at` (NOT NULL, default NOW, backfilled from `COALESCE(revoked_at, granted_at)`); the webhook upsert must accept an incoming event only when it is strictly newer than the stored `event_at`, so a late or replayed webhook event can never overwrite newer grant state.
- **SPEC-9.38**: migrations/241_platform_admin_recovery_codes.sql adds `platform_admins.mfa_recovery_codes_hashes` (`TEXT[] NOT NULL DEFAULT '{}'`), left empty on every existing row since no code was minted before this migration.
- **SPEC-9.39**: migrations/246_identities_mirror_is_one_way.sql drops the `identities_sync_to_users` trigger and its function entirely, making the mirror one-way (`users` to `identities` only), eliminating a deadlock between the two mirror functions' opposite lock-acquisition orders.
- **SPEC-9.40**: migrations/260_restore_retired_super_admin_seats.sql guardedly restores every `users` row that migration 162 retired (role `super_admin`, status `inactive`, `password_hash IS NULL`, `mfa_secret IS NULL`) to `status = 'active', role = 'admin'`, because that retirement had also disabled the person's only bunyip sign-in seat; the UPDATE is idempotent.
- **SPEC-9.41**: migrations/269_mokosh_bunyip_grants_grantee_email.sql adds nullable `mokosh_bunyip_grants.grantee_email`, used by `MembershipRepo::list_views_for_identity` in standalone mode when no `bunyip_user_id` is set.
- **SPEC-9.42**: migrations/274_mokosh_bunyip_grants_account_id_idx.sql adds a partial index on `mokosh_account_id WHERE revoked_at IS NULL`, since the prior sole index (leading on `grantee_bunyip_user_id`) could not serve a lookup filtered only by `mokosh_account_id`.

### Contacts and the portal plane

- **SPEC-9.43**: `companies`, `contacts`, `sites` are created by migrations/004_contacts.sql.
- **SPEC-9.44**: migrations/043_pms196_fks_and_triggers.sql repairs forward-referenced FKs on `companies`'s columns; migrations/057_companies_tenant_name_unique.sql adds a company-name uniqueness constraint later narrowed by migrations/062 to exclude `internal`-type companies.
- **SPEC-9.45**: migrations/060_contacts_freeform_company.sql makes `contacts.company_id` nullable and adds freeform `company_name`; mutual exclusivity between the two is enforced only at the application layer, not by a DB constraint.
- **SPEC-9.46**: migrations/082_portal_login_lockout.sql adds `contacts.portal_failed_login_count` and `portal_locked_until` implementing portal account lockout, mirroring the `users` MFA lockout shape.
- **SPEC-9.47**: migrations/108_contact_phones_and_companies.sql creates `contact_phones` and `contact_companies` with RLS attached inline, primary-flag partial unique indexes, and backfill from the legacy `phone`/`mobile`/`fax`/`company_id` columns via the `recompute_contact_mirrors` pattern.
- **SPEC-9.48**: migrations/110_contacts_company_id_set_null.sql changes `contacts.company_id`'s FK to `ON DELETE SET NULL DEFERRABLE INITIALLY IMMEDIATE` by dynamically resolving the real constraint name and raising if not found; migrations/113 applies the same change to five more FKs to `companies`, deliberately leaving `credential_vault.company_id` and `tenants.own_company_id` as blocking (non-SET-NULL) references.
- **SPEC-9.49**: migrations/112_portal_token_cutoff.sql adds `contacts.portal_tokens_valid_from`, mirroring `users.password_changed_at`'s cutoff semantics for the contact plane.
- **SPEC-9.50**: migrations/135_portal_refresh_tokens.sql and migrations/136_portal_password_reset_tokens.sql create `portal_refresh_tokens` and `portal_password_reset_tokens` with RLS enabled but not forced at creation; migrations/140_portal_tables_force_rls.sql adds the missing `FORCE ROW LEVEL SECURITY` to both.
- **SPEC-9.51**: migrations/137_portal_mfa.sql mirrors the `users` MFA column shape onto `contacts` as `portal_mfa_*` columns; migrations/138_portal_login_location.sql mirrors `users.last_login_country`/`login_location_alerts` as `portal_last_login_country`/`portal_login_location_alerts`.
- **SPEC-9.52**: migrations/141_form_definitions_portal_visible.sql adds `form_definitions.portal_visible`.
- **SPEC-9.53**: migrations/142_notifications_portal_recipients.sql adds `notifications.contact_id` for portal recipients; it is not mutually exclusive with `user_id` at the DB level, by design.
- **SPEC-9.54**: migrations/143_ticket_approvals_contact.sql adds `ticket_approvals.approver_contact_id` as a third XOR branch alongside `approver_user_id`/`approver_role`; its original `= 1`-count XOR CHECK and its unconstrained FK made deleting a sole approver contact fail, a defect not fixed until migrations/232 (see Defects found).
- **SPEC-9.55**: migrations/144_portal_exports_and_delegations.sql and migrations/145/147 implement `portal_exports`/`portal_delegations` with a 7-day worker-managed TTL expiry, a JSON bundle, a truncation marker, and per-section caps.
- **SPEC-9.56**: migrations/149_contact_notification_preferences.sql creates `contact_notification_preferences` with RLS enabled but not forced at creation (fixed by migrations/195).
- **SPEC-9.57**: migrations/150_notifications_entity_ref.sql adds `notifications.entity_type`/`entity_id`.
- **SPEC-9.58**: migrations/165_contacts_portal_role.sql adds `contacts.portal_role` (nullable, CHECK restricted to `'admin'` or `'user'`, left NULL on pre-existing rows) and a partial index `idx_contacts_portal_role_active` on `(tenant_id, portal_role) WHERE is_portal_user = true`, matching the `WHERE tenant_id = $1 AND portal_role = 'admin' AND is_portal_user = true` query that finds a tenant's portal owner; migrations/167_companies_portal_slug.sql adds `companies.portal_slug` (a 16-char Crockford base32 identifier distinct from `tenants.slug`), lazily populated on first grant and reused per Company.
- **SPEC-9.59**: migrations/168_portal_roles.sql creates `portal_roles` (RLS enabled and forced); migrations/169_contact_role_assignments.sql creates the `contact_role_assignments` many-to-many join (RLS enabled and forced); a contact's effective capabilities are the union of every assigned role's capability array, and a grant REPLACES a contact's full role set rather than merging.
- **SPEC-9.60**: migrations/170_contact_sessions.sql creates `contact_sessions`; the refresh token is minted as `{session_id}.{secret}` and only the Argon2 hash of the secret half is stored, so rotation that sets `revoked_at` on the old row and issues a fresh row makes replay of a rotated token fail.
- **SPEC-9.61**: migrations/171_seed_builtin_portal_roles.sql seeds three built-in `portal_roles` rows per tenant ("Billing Contact", "Support Contact", "Read-Only") each with `is_builtin = TRUE` and its own capability array, via `ON CONFLICT (tenant_id, name) DO NOTHING`.
- **SPEC-9.62**: migrations/172_portal_login_intents.sql creates `portal_login_intents` keyed by `email` rather than `contact_id`, so a mid-flight revoke of role or portal access is re-evaluated at redeem time by re-matching contacts; RLS enabled and forced, with genuinely cross-tenant pre-auth writes going through the BYPASSRLS migrator pool instead.
- **SPEC-9.63**: migrations/174_companies_portal_id.sql adds `companies.portal_id` (a random opaque 9-digit numeric id, range-checked `100000000..999999999`), assigned lazily on first grant and kept alongside `portal_slug` for a transition period.
- **SPEC-9.64**: migrations/176_portal_login_intents_company_scope.sql adds nullable `portal_login_intents.company_id`: NULL matches any Company under the tenant, non-NULL restricts the magic-link redeem to that specific Company's contacts.
- **SPEC-9.65**: migrations/177_portal_roles_company_scope.sql adds `portal_roles.company_id` (NULL = tenant-wide, non-NULL = Company-scoped), drops the plain `UNIQUE(tenant_id, name)` and replaces it with two case-insensitive partial unique indexes that deliberately let the same role name exist at different scopes.
- **SPEC-9.66**: migrations/179_builtin_roles_expanded_caps.sql and migrations/180_builtin_support_gains_edit_request_approval.sql each append new capability strings to exactly one named built-in role (`is_builtin = TRUE` only) using `ARRAY(SELECT DISTINCT unnest(...))` so a re-run is idempotent and a tenant-custom role of the same name is untouched.
- **SPEC-9.67**: migrations/182_companies_branding.sql adds `companies.branding` (JSONB, default `{}`); effective branding is the tenant's branding merged with the Company's branding, every non-null Company key overriding the tenant key, falling back to a hardcoded SPA default when both are missing; the legacy `companies.logo_url` column is kept, not dropped.
- **SPEC-9.68**: migrations/183_contacts_email_unique_per_company.sql adds a unique partial index on `(tenant_id, company_id, LOWER(email)) WHERE email IS NOT NULL AND company_id IS NOT NULL AND is_portal_user = TRUE`, refusing two portal-enabled contacts at the same Company sharing a case-insensitive email while permitting the same email across different Companies or tenants.
- **SPEC-9.69**: migrations/181_ticket_approvals_requested_by_contact.sql adds `ticket_approvals.requested_by_contact_id`, relaxes `requested_by_id` to nullable, and adds a `requester_xor` CHECK requiring exactly one of the two to be set (later widened by migrations/232).
- **SPEC-9.70**: migrations/194_contact_session_families.sql adds `contact_sessions.family_id` (backfilled to each existing row's own `id`, then NOT NULL); every refresh-token rotation must copy the originating family's `family_id` forward so a stolen-token replay can be revoked by one UPDATE keyed on `family_id`.
- **SPEC-9.71**: migrations/197_contact_approvals_decide.sql adds `ticket_approvals.decided_by_contact_id`; there is no XOR constraint between it and `decided_by_id`, and the service is relied on to write exactly one of the two.
- **SPEC-9.72**: migrations/198_contact_company_link_repair.sql guardedly backfills a `contact_companies` row (marked primary) for every contact whose `company_id` has no corresponding link row, leaving any contact with an existing link row (primary or not) untouched.
- **SPEC-9.73**: migrations/214_portal_access_requests.sql creates `portal_access_requests` with a unique partial index enforcing at most one open request per `(tenant_id, contact_id, area)`.
- **SPEC-9.74**: migrations/218_contact_payment_methods.sql creates `contact_payment_methods` storing only `provider`, `provider_pm_id`, `brand`, `last4`, `exp_month`/`exp_year` and no PAN, CVV, full expiry string, or billing address; a unique partial index enforces at most one default card per contact.
- **SPEC-9.75**: migrations/239_portal_roles_builtin_key.sql adds `portal_roles.builtin_key`, guardedly backfilled per named built-in role, with a unique partial index on `(tenant_id, COALESCE(company_id, '0'::uuid), builtin_key) WHERE builtin_key IS NOT NULL` so a duplicate built-in-role seeding fails loudly.

### Contact sync

- **SPEC-9.76**: migrations/220_contact_sync.sql creates `contact_sync_connections` (unique live connection per `(tenant_id, provider)`), `contact_sync_links`, `contact_field_locks` (a locked field is never overwritten by a sync write), and `contact_sync_candidates` (narrowed at creation to `match_reason IN ('phone','name_company')`, later widened by migrations/227); all four tables have RLS enabled and forced.
- **SPEC-9.77**: migrations/221_contact_sync_oauth_states.sql creates `contact_sync_oauth_states` storing an Argon2 `state_hash`, a PKCE `code_verifier`, and a `redirect_uri` that must match byte-for-byte at token exchange; `consumed_at` enforces single use.
- **SPEC-9.78**: migrations/227_contact_sync_matching.sql widens `match_reason` to add `'email_ambiguous'` for an exact-but-ambiguous email match that must queue for human review rather than auto-link; it also adds `contact_sync_links.suggested_company_id`, set only when exactly one existing company name matches, and never auto-links.
- **SPEC-9.79**: migrations/228_contact_sync_lifecycle.sql adds `contact_sync_links.origin` (nullable; unknown origin is treated as `'linked'`, i.e. never auto-deleted) and `unlink_reason`, and creates `contact_sync_suppressions` keyed by a SHA-256 digest of the external id (not the id itself) so a removal record does not retain the removed person's identifier, keyed on `(tenant_id, provider)` so a disconnect/reconnect does not undo a suppression.
- **SPEC-9.80**: migrations/229_contact_sync_runs.sql creates `contact_sync_runs` with a unique partial index enforcing one active run per connection (`status IN ('queued','running')`), and adds `contact_sync_connections.consecutive_failures`/`failure_notified_at` so a failure-streak notification fires once per streak, not once per sync interval.
- **SPEC-9.81**: migrations/238_contact_import_files.sql widens the provider CHECK to add `'vcard'` and creates `contact_import_files`, whose uploaded bytes are discarded when the import run ends and in all cases by `expires_at`.
- **SPEC-9.82**: migrations/254_icloud_contact_sync.sql widens the provider CHECK to add `'icloud'`; the credential itself is not stored on `contact_sync_connections`, but through the secret provider.
- **SPEC-9.83**: migrations/258_google_client_is_the_hosts.sql deletes every per-tenant stored Google OAuth client id row from `tenant_settings`, moving the Google OAuth client identity to a deployment-level application secret; existing `contact_sync_connections` rows and tenant refresh tokens are left untouched and will subsequently fail with `invalid_grant` and be marked `reconnect_required`.
- **SPEC-9.84**: migrations/276_microsoft_contact_sync.sql widens the provider CHECK to add `'microsoft'`; migrations/294_contact_sync_oauth_states_microsoft.sql widens `contact_sync_oauth_states`'s separate provider CHECK to add `'microsoft'`, a gap left by 276 because the in-flight OAuth state row needed the same widening independently of the finished connection.

### Service desk

- **SPEC-9.85**: `tickets` and its lookup tables are created by migrations/005_tickets.sql; migrations/023 seeds ticket lookup data.
- **SPEC-9.86**: migrations/047_ticket_category_parent_same_tenant.sql adds a composite tenant-matching FK for the category hierarchy so a ticket category can only reference a category belonging to the same tenant.
- **SPEC-9.87**: migrations/066_ticket_approvals.sql creates `ticket_approvals` without RLS attached at creation (a confirmed gap, closed by migrations/095).
- **SPEC-9.88**: migrations/068_tickets_kb_article_source.sql adds `tickets.source_kb_article_id`; migrations/099_tickets_procedure_kb_article.sql separately adds `tickets.procedure_kb_article_id`; the two columns are deliberately distinct.
- **SPEC-9.89**: migrations/069_portal_ticket_notes.sql adds `ticket_notes.created_by_contact_id`.
- **SPEC-9.90**: migrations/071_workflow_rules.sql creates `workflow_rules`/`workflow_rule_runs`; migrations/072 seeds a workflow max-depth setting.
- **SPEC-9.91**: migrations/077_approvals_polymorphic.sql widens `ticket_approvals` to a polymorphic `target`/`entity_id` pair, replacing the earlier single `ticket_id` FK.
- **SPEC-9.92**: migrations/078_change_requests_and_quotes.sql creates stub `change_requests` and `quotes` tables; `quotes` is later promoted to a full entity by migrations/092, while `change_requests` is never given an equivalent promotion in the reviewed range.
- **SPEC-9.93**: migrations/079_ticket_note_attachments.sql makes `ticket_attachments.created_by_contact_id` and `uploaded_by_id` both nullable; mutual exclusivity between them is enforced only at the application layer.
- **SPEC-9.94**: migrations/083_ticket_templates.sql creates `ticket_templates` without RLS attached at creation (closed by migrations/095).
- **SPEC-9.95**: migrations/086_company_industries.sql creates `company_industries` with RLS attached inline at creation, in contrast to 064/066/067/083/092's omissions.
- **SPEC-9.96**: migrations/094_rls_quotes_backstop.sql and migrations/095_rls_deferred_tables.sql retroactively attach RLS to 13 tables created without it: `quotes`/`quote_sequences` (094) and `saved_dashboards`, `scheduled_dashboards`, `ticket_approvals`, `change_requests`, `tenant_intake_tokens`, `email_intake_log`, `saved_reports`, `scheduled_reports`, `workflow_rules`, `workflow_rule_runs`, `ticket_templates` (095).
- **SPEC-9.97**: migrations/098_payment_provider_integration.sql creates `payment_refunds` with RLS attached inline at creation.
- **SPEC-9.98**: migrations/100_form_definitions.sql attaches RLS to `form_definitions`/`form_fields`/`form_submissions`.
- **SPEC-9.99**: migrations/118_ticket_attachment_inline_images.sql adds `ticket_attachments.is_inline` for an unauthenticated inline-image route.
- **SPEC-9.100**: migrations/119_time_entry_kind.sql adds two enforcing CHECK constraints on `time_entries.entry_kind` to split client work from employee work.
- **SPEC-9.101**: migrations/128_rls_tenantless_child_tables.sql closes the RLS gap for `quote_lines`/`credit_note_lines` via parent-join `EXISTS` policies, mirroring the mechanism migrations/041 established for other tenantless child tables.
- **SPEC-9.102**: migrations/143_ticket_approvals_contact.sql (see Identity above) and migrations/181_ticket_approvals_requested_by_contact.sql together establish the three-way approver/requester XOR shape on `ticket_approvals` that migrations/197 and migrations/232 later extend and repair.
- **SPEC-9.103**: migrations/232_ticket_approvals_unknown_approver.sql widens both the `ticket_approvals_approver_xor` and `ticket_approvals_requester_xor` CHECKs from `= 1` to `<= 1`, and adds `ON DELETE SET NULL` to `ticket_approvals_requested_by_contact_id_fkey`, so deleting the sole approver or requester contact leaves the row as "unknown approver"/"unknown requester" instead of failing.
- **SPEC-9.104**: migrations/237_users_full_name_trigram.sql adds a GIN trigram index on `(first_name || ' ' || last_name)` on `users`, matching the ticket-list search's `text_match` expression exactly.
- **SPEC-9.105**: migrations/262_ticket_saved_views.sql creates `ticket_saved_views`, per-user (unique on `(tenant_id, user_id, name)`), with `filter`/`sort` stored as JSONB so new list-filter axes do not require a schema migration; unknown JSON keys are rejected at the application-validator layer, not by the schema.
- **SPEC-9.106**: migrations/264_note_structured_fields.sql adds four nullable structured columns to `ticket_notes` (`time_minutes`, `work_summary`, `parts_used`, `follow_up`), none backfilled.

### SLA

- **SPEC-9.107**: `business_hours`, `sla_policies`, `sla_targets` are created by migrations/005_tickets.sql; migrations/023 seeds SLA data; migrations/027 adds `sla_notifications`.

### Time, projects and calendar

- **SPEC-9.108**: `time_entries`, `work_types`, `active_timers` are created by migrations/006; `projects`/`tasks` by migrations/007; `appointments`/`time_off` by migrations/008.
- **SPEC-9.109**: migrations/028_appointment_reminders.sql creates `appointment_reminders` with no FK/cascade to its parent, unlike sibling tables.
- **SPEC-9.110**: migrations/033_timesheet_draft_state.sql widens the timesheet draft state.
- **SPEC-9.111**: migrations/048_project_types_lookup.sql replaces a CHECK-based project-type enum with a lookup table; migrations/049 adds single-default partial unique indexes for it and two other lookup tables.
- **SPEC-9.112**: migrations/055_time_entry_general_category.sql adds `time_entries.work_category`; migrations/056 adds `scheduling_templates`; migrations/059 adds `default_due_business_days`.
- **SPEC-9.113**: migrations/081_time_entry_billable_minutes.sql adds `time_entries.worked_minutes`/`billable_minutes`.
- **SPEC-9.114**: migrations/119_time_entry_kind.sql (see Service desk above) also governs `time_entries`.
- **SPEC-9.115**: migrations/120_timesheets_module_flag.sql seeds the `module_config` timesheets flag per tenant, conditional on `tenants.kind = 'org'`.
- **SPEC-9.116**: migrations/125_time_entry_hours_consumed.sql adds `hours_consumed`/`hours_balance_id` for block-hour draw tracking.
- **SPEC-9.117**: migrations/187_appointments_team_id.sql backfills `appointments.team_id`, a column a prior commit assumed existed since migration 008 but never actually added, which had caused every create/list appointment call to 500; its FK shape mirrors `on_call_schedules.team_id` (`ON DELETE SET NULL`).
- **SPEC-9.118**: migrations/188_work_day_segments.sql creates `work_day_segments` (`kind IN ('work','break')`), with a unique partial index enforcing one open segment per person regardless of kind or date; a work day is explicitly derived from its segments, never stored as its own row.

### Billing

- **SPEC-9.119**: `contracts`, `invoices`, `payments`, `tax_rates` are created by migrations/009/010; migrations/023 seeds billing lookup data; migrations/025 adds a unique constraint on `contract_hour_balances`; migrations/031 adds the `contract_invoice_runs` idempotency ledger.
- **SPEC-9.120**: migrations/050_payment_terms_lookup.sql adds a `payment_terms` lookup table with backfill; migrations/052_payments_amount_positive.sql adds a `payments.amount > 0` CHECK as `NOT VALID`, never subsequently validated against existing rows.
- **SPEC-9.121**: migrations/051_mileage_entries.sql creates `mileage_entries` with `project_id`/`task_id`/`contract_id`/`invoice_id` as unconstrained bare UUID columns (no FK), unlike the rest of the same CREATE TABLE.
- **SPEC-9.122**: migrations/053_tax_rate_widen_column.sql widens `tax_rates`; migrations/061_billing_cycle_weekly_biweekly.sql widens `billing_cycle` to add weekly/bi-weekly.
- **SPEC-9.123**: migrations/092_quotes_entity.sql builds out `quotes` as a full entity (sequences, money columns, status widening, unique constraints) with `quote_lines`; migrations/094 (see Service desk) retroactively attaches RLS to `quotes`/`quote_sequences`.
- **SPEC-9.124**: migrations/117_readable_payment_terms.sql guardedly renames the human-readable payment-terms label; migrations/121_release_time_held_by_approval.sql backfills released stranded time without touching `approval_status`.
- **SPEC-9.125**: migrations/122_credit_notes.sql creates `credit_notes`/`credit_note_sequences` with RLS attached inline; `credit_note_lines` deliberately has no `tenant_id` column, mirroring `invoice_lines`.
- **SPEC-9.126**: migrations/123_product_catalog.sql creates `products` with RLS attached inline, and links `invoice_lines`/`contract_items` to it by FK.
- **SPEC-9.127**: migrations/124_contract_item_billing_rule.sql adds `contract_items.billing_rule`/`billed_at`, replacing implicit item-type inference.
- **SPEC-9.128**: migrations/127_invoice_issuer_snapshot.sql adds `invoices.issuer_snapshot` (JSONB), frozen at first send and deliberately never backfilled onto pre-existing invoices.
- **SPEC-9.129**: migrations/133_payment_term_net_days.sql adds `payment_terms.net_days`, backfilled by regex against the existing label text.
- **SPEC-9.130**: migrations/134_invoice_emailed.sql adds `invoices.emailed_at`/`emailed_to`.
- **SPEC-9.131**: migrations/132_gateway_credentials_to_store.sql makes `payment_gateway_configs.config_encrypted` nullable for the secret-store migration; the column is deliberately never dropped, left as a permanent fallback.
- **SPEC-9.132**: migrations/185_payment_gateway_configs_client_display_name.sql adds nullable `client_display_name`; NULL preserves the provider-default Pay Now label.
- **SPEC-9.133**: migrations/189_invoice_tax_from_rate.sql adds `invoice_lines.is_taxable` (copied from `products.is_taxable` at write time, never re-derived later) and `invoices.tax_rate_id`/`tax_rate`, both NULL on any row whose `tax_amount` was supplied directly; migrations/190_quote_tax_from_rate.sql applies the identical shape to `quotes`/`quote_lines`.
- **SPEC-9.134**: migrations/191_time_entry_prepaid_and_overage.sql widens `time_entries.billing_status` to add `'prepaid'` (never selected by the invoice-from-time-entries builder) and adds `overage_hours`/`overage_rate`.
- **SPEC-9.135**: migrations/192_invoice_write_off.sql adds `invoices.written_off_at`/`written_off_by_id`/`write_off_reason`/`write_off_amount`; `write_off_amount` is frozen at decision time and is distinct from `balance_due`, which keeps moving if a late payment lands afterward.
- **SPEC-9.136**: migrations/193_invoice_reminders.sql creates `invoice_reminders` with `UNIQUE (tenant_id, invoice_id, offset_days)` as the idempotency guard against the reminder worker firing twice for the same step; "overdue" itself stays derived, never stored.
- **SPEC-9.137**: migrations/216_payment_gateway_configs_min_partial_amount.sql adds nullable `min_partial_amount`; NULL means "use the code default" ($1.00).
- **SPEC-9.138**: migrations/218_contact_payment_methods.sql (see Contacts-portal above) also governs billing.
- **SPEC-9.139**: migrations/242_invoice_void.sql adds `invoices.voided_at`/`voided_by_id`/`void_reason`, giving void its own writer rather than reaching it as a side effect of a full credit, and guardedly reclassifies every pre-existing `void` invoice that could previously only be reached via a full credit to `paid` (with `paid_at` left NULL).
- **SPEC-9.140**: migrations/243_invoice_numbering_per_company.sql adds `companies.invoice_prefix` (CHECKed against a 31-character alphabet excluding ambiguous characters, unique per tenant) and a table-row counter `invoice_company_sequences` (not a Postgres SEQUENCE, so a rolled-back transaction leaves no gap); `invoices.number_scheme` is NULL for any invoice issued before the column existed.
- **SPEC-9.141**: migrations/244_invoice_company_sequences_rls.sql attaches the tenant-isolation RLS policy that migrations/243 omitted from `invoice_company_sequences`.
- **SPEC-9.142**: migrations/249_opportunities.sql creates `opportunities` with a CHECK requiring `outcome` to be set exactly when `stage` is `won`/`lost`.
- **SPEC-9.143**: migrations/253_invoice_amendments.sql adds `invoices.amends_invoice_id`, naming the sent invoice this one replaces; the reverse "latest revision" pointer is deliberately not stored.
- **SPEC-9.144**: migrations/256_payment_gateway_connection_home.sql backfills `integrations` rows from `payment_gateway_configs` for `stripe`/`paypal` only (not `authorize_net`) and marks `payment_gateway_configs.is_active` retired, kept for one release as a write-only rollback mirror.
- **SPEC-9.145**: migrations/257_payment_webhook_deliveries_unreconciled.sql widens `payment_webhook_deliveries.outcome` to add `'unreconciled'` for a delivery that verified/dispatched but whose reconciliation was refused.
- **SPEC-9.146**: migrations/263_delivery_method.sql adds `delivery_method`/`delivery_note`/`delivered_by_id` to both `invoices` and `quotes`, each with a CHECK requiring a non-empty note when the method is `'other'`, and backfills `invoices`' values from `audit_log` rows with no row-count assertion (volume depends on audit history).
- **SPEC-9.147**: migrations/278_invoices_external_issuer.sql adds nullable `external_provider`/`external_invoice_id`/`external_number` to `invoices` with no index; migrations/291_credit_notes_external_issuer.sql adds the identical triple to `credit_notes`, and adds `credit_note_lines.product_id`.
- **SPEC-9.148**: migrations/279_expenses_subsystem.sql creates the Phase 0 expenses schema (`vendors`, `expense_categories`, `bills`, `bill_lines`, `expenses`, `expense_lines`), each with RLS enabled and forced and no serving code yet.
- **SPEC-9.149**: migrations/287_bill_payments.sql creates `bill_payments` with `CHECK (amount_minor > 0)`; the running total on `bills.paid_minor` is written only by `recompute_bill_payment_state`, for which this table is the sole input.
- **SPEC-9.150**: migrations/293_bills_expenses_search_trigram.sql adds four trigram GIN indexes serving the expenses module's ILIKE filters.
- **SPEC-9.151**: migrations/233_widen_payment_method_paypal.sql widens `payments.payment_method` to add `'paypal'`, since `record_gateway_payment` previously hardcoded `'credit_card'` for every gateway-confirmed payment because the CHECK allowed nothing else.
- **SPEC-9.152**: migrations/217_billing_contact_gains_pay_partial.sql and migrations/219_billing_contact_gains_payment_methods_manage_own.sql each append one capability (`invoices:pay_partial`, `payment_methods:manage_own`) to the built-in Billing Contact role only.
- **SPEC-9.153**: migrations/199_builtin_roles_backfill_appended_caps.sql re-appends, for every built-in role, the full capability set accumulated by migrations/179/180/171 so a tenant whose role predates those migrations is brought current; non-builtin roles of the same name are never touched.

### Assets

- **SPEC-9.154**: `assets`/`credential_vault` are created by migrations/011; migrations/023 seeds asset data.
- **SPEC-9.155**: migrations/044_asset_audit_log_survive_delete.sql makes `asset_audit_log`'s FK non-cascading and adds a `'deleted'` action; migrations/045_assets_zero_key_reencrypt_guard.sql is verification-only.
- **SPEC-9.156**: migrations/063_assets_cmdb_expand.sql expands CMDB fields; migrations/065_itil_ci_classification.sql adds ITIL classification.
- **SPEC-9.157**: migrations/080_assets_license_section.sql adds the license section to `assets`.
- **SPEC-9.158**: migrations/247_monitored_systems_and_status_observations.sql creates `monitored_systems` and `status_observations`, the latter with a `UNIQUE (monitored_system_id, check_kind, observed_at)` idempotency triple for replayed monitoring deliveries consumed via `ON CONFLICT DO NOTHING`.
- **SPEC-9.159**: migrations/248_websites_as_assets.sql seeds a per-tenant "Website" `asset_types` row and backfills one `assets` row per company with a non-blank `companies.website`; the legacy `companies.website` column is left in place, marked deprecated via `COMMENT ON COLUMN`.
- **SPEC-9.160**: migrations/250_credential_vault_stance.sql is comment-only: it records that credentials are stored locally (encrypted under `ENCRYPTION_KEY`) rather than in an external vault, and every plaintext read goes through an audited reveal endpoint that writes an `asset_audit_log` row.
- **SPEC-9.161**: migrations/251_kb_article_parent_and_company_index.sql (see Knowledge base) also touches assets-adjacent search; migrations/270_assets_search_haystack.sql adds a generated, stored `search_haystack` column using `host(ip_address)` specifically to avoid a `/32` CIDR suffix in the search text, plus a trigram GIN index on it.
- **SPEC-9.162**: migrations/271_asset_catalog.sql creates `asset_models` and `asset_templates`, both with every FK `DEFERRABLE INITIALLY IMMEDIATE`; the `asset_type_id` FK on `asset_models` uses `ON DELETE NO ACTION` rather than `RESTRICT` because only `NO ACTION` respects the deferrable clause under the tenant-import's `SET CONSTRAINTS ALL DEFERRED` posture.
- **SPEC-9.163**: migrations/272_asset_signature_candidates_mv.sql creates a materialized view grouping recent assets by manufacturer/model/type with `HAVING COUNT(*) >= 5`, refreshed every 60 seconds by a scheduler job; Postgres materialized views carry no RLS, so the reading handler must filter by `tenant_id` itself.
- **SPEC-9.164**: migrations/273_asset_catalog_seed.sql seeds ~39 manufacturer/model/type combinations into `asset_models` for the default tenant only, with `source = 'seeded'`, via `ON CONFLICT (tenant_id, lower(manufacturer), lower(model), asset_type_id) DO NOTHING`.
- **SPEC-9.165**: migrations/275_asset_tag_counters.sql creates `asset_tag_counters` (one row per tenant, `tenant_id` as primary key), lazily seeded by the first `create_asset` call from the highest existing `AST-<n>` tag, and adds a case-insensitive unique index on `assets.asset_tag` that tolerates NULL.

### Knowledge base

- **SPEC-9.166**: `kb_categories`/`kb_articles`/`kb_article_versions` are created by migrations/012; migrations/023 seeds KB data; migrations/026_kb_slug_unique.sql fixes a real slug-uniqueness gap left by migrations/012.
- **SPEC-9.167**: migrations/032_kb_article_votes.sql creates `kb_article_votes`; its own comment incorrectly claims "No RLS", contradicted by migrations/038 which does cover it (see Defects found).
- **SPEC-9.168**: migrations/041_rls_cover_tenantless_tables.sql attaches RLS to `kb_article_versions`/`invoice_lines`/`rate_card_items`/`sla_targets` via parent-join `EXISTS` policies.
- **SPEC-9.169**: migrations/114_kb_article_drafts.sql creates `kb_article_drafts` deliberately carrying its own `tenant_id` column rather than joining through `kb_articles` (which has none), to match the plain shape `tests/rls_coverage.rs` expects.
- **SPEC-9.170**: migrations/115_kb_article_attachments.sql documents the public image-read path as bypassing RLS entirely on the migrator pool, an accepted cost, not a defect.
- **SPEC-9.171**: migrations/200_kb_version_provenance.sql adds `kb_article_versions.change_kind` (`'create'|'edit'|'restore'`, backfilled `'create'` only for `version_number = 1`) and `kb_articles.updated_by_id` (not backfilled; readers fall back to the latest version's editor when NULL).
- **SPEC-9.172**: migrations/201_kb_article_comments.sql creates `kb_article_comments` with threading one level deep (enforced in the service, not by a DB constraint), a soft-delete `deleted_at` so a reply is never orphaned, and deliberately no visibility/customer-facing column so a portal contact never sees staff-only discussion.
- **SPEC-9.173**: migrations/202_kb_comment_mentions.sql creates `kb_comment_mentions` as a once-only notify guard, one row per `(comment, user)`.
- **SPEC-9.174**: migrations/251_kb_article_parent_and_company_index.sql adds `kb_articles.parent_article_id` with `ON DELETE SET NULL` (not CASCADE) so a client-specific article survives deletion of its generic parent, and a GIN index on `company_ids`.
- **SPEC-9.175**: migrations/292_kb_article_template_variables.sql adds `kb_articles.template_variables` (JSONB, default `[]`), stored on the article row so it rides along through version restore; minijinja renders with default `{{ }}`/`{% %}` delimiters, and the default empty array renders an article byte-identically to its stored content.

### Forms

- **SPEC-9.176**: migrations/070_saved_reports.sql (see Notifications-reporting) and migrations/101_form_request_tokens.sql create `form_request_tokens` for pre-auth resolution on the migrator pool.
- **SPEC-9.177**: migrations/105_form_definition_drafts.sql creates `form_definition_drafts`.
- **SPEC-9.178**: migrations/151_form_fields_file_type.sql widens `form_fields.field_type`'s CHECK to add `'file'`.
- **SPEC-9.179**: migrations/240_form_request_link_people.sql adds `form_request_tokens.uses_allowed`/`uses_remaining` and `parent_ticket_id`; a multi-person link files children under `parent_ticket_id`, with the parent carrying no SLA, assignee, or time of its own.

### Notifications and reporting

- **SPEC-9.180**: `notification_channels`/`notification_templates`/`notifications`/`notification_rules` are created by migrations/013; migrations/020 adds dispatcher backoff; migrations/021/027/028 seed templates; migrations/030 backfills non-default tenants.
- **SPEC-9.181**: migrations/022_rmm_mesh_central_provider.sql fixes the `mesh_central` provider; migrations/023 seeds 8 templates with no matching `notification_rules` rows, unlike every other template-seeding migration (see Defects found).
- **SPEC-9.182**: migrations/070_saved_reports.sql creates `saved_reports`; migrations/075/076 create `scheduled_reports`/`scheduled_dashboards`.
- **SPEC-9.183**: migrations/073_email_intake_log.sql documents a future `default_company_id` setting key that is never actually seeded in this migration; migrations/074 (a distinct setting) does seed its own key.
- **SPEC-9.184**: migrations/096_reseed_023_notification_templates.sql guardedly reseeds migrations/023's templates, using an `E'...'` literal for `\n` to fix a prior escaping issue.
- **SPEC-9.185**: migrations/097_notifications_body_html.sql adds `notifications.body_html` with a cross-tenant backfill.
- **SPEC-9.186**: migrations/104_ticket_note_org_identity.sql's backfill guard checks only `(event_type, template_id)`, not also `channel_type`/`name`, which risks a duplicate-rule insertion for a tenant that has customized the matching rule (see Defects found).
- **SPEC-9.187**: migrations/139_notification_templates_branding.sql guardedly rewrites `auth.password_reset`/`auth.welcome`/`ticket.note_added` to branded copy; this rewrite's WHERE clause unintentionally reverted migrations/104's earlier org-identity rewrite of `ticket.note_added` because it matched only on migrations/021's original subject text (see Defects found); migrations/148_restore_ticket_note_org_identity.sql guardedly repairs exactly that regression.
- **SPEC-9.188**: migrations/152_auth_welcome_portal_url.sql adds a portal-URL conditional block to `auth.welcome`.
- **SPEC-9.189**: migrations/173_auth_portal_grant_template.sql seeds the `auth.portal_grant` template/rule pair for the default tenant; migrations/175_auth_portal_grant_template_portal_id.sql guardedly rewrites it to surface a `{{portal_id}}` placeholder; migrations/184_auth_portal_grant_company_id_copy.sql guardedly renames the user-visible label to "Your Company ID:" while keeping the `{{portal_id}}` token unchanged.
- **SPEC-9.190**: migrations/178_auth_login_link_template.sql seeds the `auth.login_link` template/rule pair, fixing a previously silent no-op where `ContactAuthService::request_login_link` dispatched an event with no template/rule pair.
- **SPEC-9.191**: migrations/186_backfill_auth_portal_grant_template.sql backfills the `auth.portal_grant`/`auth.login_link` template and rule pairs (seeded only for the default tenant by migrations/173/178) into every other pre-existing tenant, guarded by a `NOT EXISTS` check that includes `template_id`.
- **SPEC-9.192**: migrations/203_rebrand_password_reset_and_welcome.sql guardedly rewrites `auth.password_reset`/`auth.welcome` to MSP-branded copy, gated on the exact text left by migrations/116; migrations/204_restore_app_name_transactional_copy.sql immediately reverts it, restoring migrations/116's `{{app_name}}`-based copy, on the premise that the branding intent was superseded and the product-vs-MSP-name decision is tracked elsewhere and deliberately not resolved by a migration.
- **SPEC-9.193**: migrations/205_audit_log_ticket_note_parent.sql adds a partial expression index on `audit_log ((new_values ->> 'ticket_id')) WHERE entity_type = 'ticket_notes'`, letting a per-ticket history read also pull in note-edit audit rows.
- **SPEC-9.194**: migrations/206_portal_transactional_mail.sql seeds `auth.portal_password_reset` and `auth.portal_welcome` template/rule pairs for the default tenant and fans them out to every pre-existing tenant; its backfill guard omits the `template_id` condition that migrations/186 and 202 both include (see Defects found).
- **SPEC-9.195**: migrations/202_kb_comment_mentions.sql's notification seed (see Knowledge base) uses the same fan-out shape as migrations/186.
- **SPEC-9.196**: migrations/207_app_secrets_table.sql through migrations/210_app_config_table.sql (see Security below) and migrations/208_guarded_content_update_assert_helper.sql's `mokosh_assert_content_rows_matched` function underpin every guarded content UPDATE from migration 208 onward; migrations/209_notification_template_content_guard.sql uses it to assert non-empty `subject`/`body_text` on `auth.password_reset` and `auth.welcome`.
- **SPEC-9.197**: migrations/212_compose_support_footer_line.sql replaces the literal support-footer sentence with `{{msp_footer_line}}`/`{{msp_footer_line_html}}` placeholders composed at render time, but its SET clause unconditionally rewrote `body_html` through `replace(COALESCE(body_html,''), ...)` even on rows matched only by `body_text`, blanking a legitimately-NULL `body_html` to `''` (see Defects found); migrations/231_repair_footer_line_blanked_html.sql repairs exactly that regression.
- **SPEC-9.198**: migrations/213_payment_webhook_deliveries.sql through migrations/215_portal_access_requested_notification.sql (see Billing/Integrations/Contacts-portal) also seed matching notification template/rule pairs following the migrations/206 fan-out shape.
- **SPEC-9.199**: migrations/224_portal_password_reset_greeting.sql guardedly prepends a `{{salutation}},` greeting to `auth.portal_password_reset`, requiring both the text and HTML fragments to match (unlike migrations/212's OR).
- **SPEC-9.200**: migrations/229_contact_sync_runs.sql (see Contact sync) also seeds a staff-facing `contact_sync.failing` template/rule pair, backfilled with the same `NOT EXISTS` guard shape as migrations/206/215.
- **SPEC-9.201**: migrations/230_request_link_greeting_repair.sql self-heals the `forms.request_link` greeting with no row-count assertion (zero matches is a legitimate outcome), operating on bare columns so a NULL `body_html` stays NULL.
- **SPEC-9.202**: migrations/255_portal_grant_greeting.sql guardedly replaces the `auth.portal_grant` greeting fragment with `{{salutation}},`, asserting via `mokosh_assert_content_rows_matched` and raising on zero matched rows.
- **SPEC-9.203**: migrations/265_notification_templates_invite_and_quote.sql seeds `invitations.created`/`quote.sent` template/rule pairs on the default tenant and fans them out; migrations/266_notification_templates_invite_and_quote_greeting.sql guardedly adds a `{{salutation}},` opening to both, identical guard shape to migrations/230/255.
- **SPEC-9.204**: migrations/267_mokosh_grant_invitations.sql creates `mokosh_grant_invitations` deliberately without RLS (three route handlers read it cross-tenant by invitee, by token), scope instead pinned per-query and documented by `// SAFETY (PMS-285)` comments; migrations/268_grant_invitation_template.sql seeds and fans out the matching `auth.mokosh_grant_invite` template/rule pair; migrations/281_grant_invitation_salutation.sql guardedly adds the `{{salutation}},` greeting to it, asserting matched rows and raising on zero expected matches.

### Integrations and operations

- **SPEC-9.205**: `rmm_connections`/`files`/`tenant_settings`/`module_config` are created by migrations/014/016/017; `audit_log` by migrations/015.
- **SPEC-9.206**: migrations/213_payment_webhook_deliveries.sql creates `payment_webhook_deliveries`, deliberately never storing the raw webhook body or headers.
- **SPEC-9.207**: migrations/252_integrations.sql creates `integrations` (unique on `(tenant_id, provider)`), with no credential column by design (credentials go through `SecretProvider`), and deliberately excludes `rmm_connections`'s provider from its own CHECK list since RMM is not one of this subsystem's arbitrated capabilities; migrations/256_payment_gateway_connection_home.sql (see Billing) performs the first backfill into it.
- **SPEC-9.208**: migrations/258_google_client_is_the_hosts.sql (see Contact sync) also governs integrations-ops.
- **SPEC-9.209**: migrations/259_contact_companies_contact_index.sql adds an index serving `contact_sync`'s per-contact company-name correlated subquery that neither prior index on `contact_companies` could serve.
- **SPEC-9.210**: migrations/261_feature_toggles.sql creates `feature_toggles`, deliberately not tenant-scoped (no `tenant_id`, no RLS); a missing row reads as "off", and an unknown key is logged and ignored rather than erroring.
- **SPEC-9.211**: migrations/277_drop_point_of_sale_capability.sql removes the retired `point_of_sale` capability string from every `integrations.enabled_capabilities` array with no rollback path provided.
- **SPEC-9.212**: migrations/280_integrations_icloud_provider.sql widens `integrations.provider`'s CHECK to add `'icloud'` even though no row can be written for it yet, so the enum and CHECK do not disagree while `IntegrationsService` refuses every actual write.
- **SPEC-9.213**: migrations/283_stripe_invoicing_capability_retired.sql strips the `'invoicing'` capability from Stripe rows only, leaving `payments` alone, and only emits a NOTICE when at least one row was stripped (no assertion of a nonzero expected count).
- **SPEC-9.214**: migrations/282_invoice_issuer_mappings.sql adds `integrations.external_organisation_id` and creates `invoice_issuer_company_mappings`/`invoice_issuer_product_mappings`, each unique per `(tenant_id, provider, company_id|product_id)`.
- **SPEC-9.215**: migrations/284_invoice_issuer_oauth_states.sql creates `invoice_issuer_oauth_states`, setting `consumed_at` before the token exchange to block replay of a slow or failing exchange.
- **SPEC-9.216**: migrations/285_invoice_issuer_vendor_mappings.sql creates `invoice_issuer_vendor_mappings`; migrations/286_invoice_issuer_expense_account_mappings.sql creates `invoice_issuer_expense_account_mappings` at category granularity (not per-vendor), because the same vendor can supply costs belonging to different accounts.
- **SPEC-9.217**: migrations/288_invoice_issuer_payment_account.sql adds `integrations.external_payment_account_id`; NULL blocks the dispatcher from pushing a reimbursement until an admin sets it.
- **SPEC-9.218**: migrations/289_invoice_issuer_user_mappings.sql creates `invoice_issuer_user_mappings`, where `ON DELETE CASCADE` on `user_id` removes the mapping for a departed user while the claim's own `external_expense_id` persists independently.
- **SPEC-9.219**: migrations/290_integrations_external_org_unique.sql adds the only constraint on `integrations` not scoped to `tenant_id`: a cross-tenant partial unique index on `(provider, external_organisation_id) WHERE external_organisation_id IS NOT NULL`, fixing a gap where two tenants could hold the same external-organization pair.

### Security, grants and roles

- **SPEC-9.220**: migrations/168-172 and migrations/194-195 (see Contacts-portal/Identity) each enable and force RLS with the standard `tenant_isolation` policy on their new tables.
- **SPEC-9.221**: migrations/207_app_secrets_table.sql creates `app_secrets` with no `tenant_id` and no RLS (there is no tenant GUC to filter a process-wide secret on), storing AES-256-GCM ciphertext written and read exclusively by `crate::app_secrets::database`.
- **SPEC-9.222**: migrations/208_guarded_content_update_assert_helper.sql adds `mokosh_assert_content_rows_matched(matched, expected, context)`, raising `check_violation` when `matched <> expected`; `scripts/check-guarded-content-migrations.nu` enforces its use on any guarded content UPDATE added after this migration.
- **SPEC-9.223**: migrations/210_app_config_table.sql creates `app_config` for plaintext configuration (not secrets), also with no `tenant_id`/RLS; bootstrap-tier keys are refused at the provider layer, not by any schema constraint on this table.
- **SPEC-9.224**: migrations/199_builtin_roles_backfill_appended_caps.sql (see Billing) re-applies the accumulated built-in-role capability set.
- **SPEC-9.225**: migrations/235_app_role_grants_every_table.sql re-issues a blanket `GRANT ... ON ALL TABLES/SEQUENCES/FUNCTIONS IN SCHEMA public TO mokosh_app` to close a gap where tables created by migrations 201, 202, 213, 214, 220, 221, 225, 228, 229 had never been granted to the app pool role, causing permission-denied errors; from this migration forward, every migration creating a table must grant it to `mokosh_app` in the same file.

### Corrections and retention

- **SPEC-9.226**: `scripts/test-db-roles.sql` idempotently creates the bare role `mokosh_app` (name only, no LOGIN/password/privileges) so `#[mokosh_test]`'s bare-cluster migration run does not fail at migrations/207's `GRANT ... TO mokosh_app` (Postgres error 42704); it deliberately does not reproduce `provision_roles`'s LOGIN/password/privilege set, to avoid a second, silently-driftable definition of a role `src/db/provision.rs` owns.
- **SPEC-9.227**: `scripts/wipe_demo_seed.sql` identifies demo rows only when a `companies` row matches `tenant_id = :tenant_id AND name = 'Acme Corporation (Demo)' AND tags @> ARRAY['demo']::text[]`, captured into a temp table so the preview and the deletes target the identical row set.
- **SPEC-9.228**: `scripts/wipe_demo_seed.sql` deletes `tickets` referencing a captured demo company before deleting the `companies` row itself, because `tickets` has no `ON DELETE CASCADE` from `companies` (per migrations/005_tickets.sql), while `contacts` and `sites` do cascade and are left to cascade implicitly.
- **SPEC-9.229**: `scripts/wipe_demo_seed.sql` runs its preview SELECT and both DELETEs inside `BEGIN; ... ROLLBACK;`, so by default it only previews; the operator must manually change the final `ROLLBACK` to `COMMIT` and rerun to actually remove rows.
- **SPEC-9.230**: migrations/121_release_time_held_by_approval.sql (see Billing) and the other guarded content UPDATEs in migrations 096/104/106/116/117/139/148/152/230/231/283 are documented, case by case, as deliberately not asserting a matched-row count, each for a stated reason (e.g. zero matches is a legitimate outcome, or volume is not knowable in advance).

### Early schema split and incremental additions

- **SPEC-9.231**: migrations/010_billing.sql creates `invoices` (status CHECK IN draft/pending/sent/paid/partially_paid/void/written_off, unique on `(tenant_id, invoice_number)`), `invoice_sequences`, `invoice_lines`, `payments` (payment_method CHECK IN check/credit_card/ach/wire/cash/other), `payment_gateway_configs` (provider CHECK IN stripe/authorize_net/paypal, `config_encrypted` ciphertext) and `tax_rates`, as the PMS-128 split of the original monolithic billing schema.
- **SPEC-9.232**: migrations/016_files.sql creates `files` (tenant_id, original_name, storage_path, mime_type, file_size, checksum, uploaded_by_id NOT NULL at creation, polymorphic entity_type/entity_id), the PMS-128 split's file-storage ledger table (left unwritten-to until migration 126).
- **SPEC-9.233**: migrations/017_settings.sql creates `tenant_settings` (unique on `(tenant_id, category, key)`, JSONB `value`) and `module_config` (unique on `(tenant_id, module_name)`, `is_enabled` flag plus JSONB `config`), the PMS-128 split's generic per-tenant settings and optional-module-configuration tables.
- **SPEC-9.234**: migrations/042_portal_setup_tokens.sql creates `portal_setup_tokens`, mirroring `password_reset_tokens` but bound to a `contacts` row: the emailed token is `{contact_id}.{secret}`, only the Argon2 hash of the secret half is stored, the row expires after 72h, and the table gets the fail-closed FORCE'd `tenant_isolation` policy explicitly because the DO-block loops in 024/038 had already run and do not retroactively cover a table created later.
- **SPEC-9.235**: migrations/058_tickets_tenant_team_idx.sql adds a composite `(tenant_id, team_id)` index on `tickets` so the team-scoped ticket filter and the team-scoped dashboard aggregates do not fall back to a per-tenant index plus a heap filter on the nullable `team_id`.
- **SPEC-9.236**: migrations/064_saved_dashboards.sql creates `saved_dashboards` (owner `user_id`, SPA-opaque JSONB `layout`, `is_default` flag), with a partial unique index enforcing at most one `is_default = true` row per `(tenant_id, user_id)`; the application, not the database, is responsible for flipping a prior default's flag off in the same transaction as a new promotion.
- **SPEC-9.237**: migrations/067_email_intake.sql creates `tenant_intake_tokens` (SHA-256 `token_hash`, never the plaintext bearer, free-text `kind` discriminator) for the email-to-ticket intake gateway, and adds a partial unique index on `tickets(tenant_id, email_message_id) WHERE email_message_id IS NOT NULL` so a duplicate intake against the same tenant and Message-Id is rejected at the database layer even if the application-level dedup check is bypassed.
- **SPEC-9.238**: migrations/076_scheduled_dashboards.sql creates `scheduled_dashboards` (cron_expr validated at the API surface, `channel` CHECK restricted to `'email'` only, nullable `recipient_email` override, `last_error` text that does not block the worker from advancing `next_run_at` on failure), with `ON DELETE CASCADE` on both `dashboard_id` and `user_id` since a schedule has no existence independent of its owning dashboard and user.
- **SPEC-9.239**: migrations/102_form_contact_and_request_link_copy.sql adds a free-text `form_definitions.contact_info` column (rendered as a sentence, not parsed) and rewrites the seeded `forms.request_link` notification template (originally inserted by migration 101) to add the `sender_name`, `company_name`, `contact_line` and `abuse_notice`/`abuse_notice_html` placeholders, matching the UPDATE's WHERE clause against the exact prior seeded body so a tenant that has since customized its own copy through the notification CRUD API is left untouched.
- **SPEC-9.240**: migrations/103_request_link_logo.sql adds the `{{logo_html}}` placeholder to the `forms.request_link` HTML body (composed server-side into either a complete `<p><img></p>` or an empty string, never a conditional inside the template itself), again matching its UPDATE's WHERE clause against the exact migration-102 body so only tenants still holding that exact copy are rewritten.
- **SPEC-9.241**: migrations/106_salutation_copy.sql replaces the separately-worded greetings in `forms.request_link` and `auth.welcome` with one shared `{{salutation}}` placeholder (composed by `utils::email::salutation`, yielding "Hello David" or bare "Hello" with no trailing space before the template's own comma), fixing `auth.welcome` rendering "Hello ," for a user created with no name.
- **SPEC-9.242**: migrations/107_search_trigram_indexes.sql adds `gin_trgm_ops` indexes on `tickets.ticket_number`, `tickets.description`, `contacts.first_name`, `contacts.last_name`, `contacts.email`, `assets.serial_number`, `assets.asset_tag` and `projects.name`, because a leading-wildcard `ILIKE '%q%'` cannot use a plain B-tree and Postgres can only combine a multi-column OR into a `BitmapOr` scan when every branch already has its own index.
- **SPEC-9.243**: migrations/109_contact_company_link_order.sql adds `contact_companies.sort_order` (backfilled by `ROW_NUMBER() OVER (PARTITION BY contact_id ORDER BY created_at, id)`) because `created_at` alone was not a total order (every link written in one request shares the same transaction timestamp), making "removing the primary link promotes the oldest remaining link" a coin flip; the service sets `sort_order` on INSERT only, so a surviving link never loses its original position.
- **SPEC-9.244**: migrations/111_notifications_sending_status.sql adds `'sending'` to the `notifications.status` CHECK domain (claimed-but-undelivered, set when a dispatcher tick flips a batch before committing and sending outside any open transaction) and replaces the pending-only partial index with `idx_notifications_claimable` covering both `'pending'` and `'sending'`, so a row left `'sending'` past its `next_attempt_at` (a worker that died mid-tick) is picked up again on the same predicate as a fresh `'pending'` row.
- **SPEC-9.245**: migrations/126_file_ledger.sql drops `files.uploaded_by_id`'s NOT NULL (a portal or inbound-email upload has no `users` row behind it), documents `storage_path` as relative to the configurable storage root rather than absolute, adds `idx_files_tenant_size`, and backfills one row per existing `ticket_attachments` and `kb_article_attachments` row (matching `ObjectKey::relative_path` exactly) so `files`, previously never written to, stops reporting a constant zero for `TenantUsage.storage_bytes`; tenant logo files are deliberately not backfilled because nothing recorded their size.
- **SPEC-9.246**: migrations/131_secret_store.sql creates `secrets` (unique on `(tenant_id, name)`, NOT NULL `value_encrypted` so a row's mere existence means a secret is stored) with the same fail-closed FORCE'd `tenant_isolation` policy as every other tenant-scoped table, as the generic per-tenant secret store the DATABASE backend of `crate::secrets` writes to; nothing writes to it as of this migration.
- **SPEC-9.247**: migrations/146_portal_search_trigram.sql adds `gin_trgm_ops` indexes on `tickets.ticket_number`, `tickets.description`, `invoices.invoice_number`, `invoices.po_number`, `quotes.summary` and `kb_articles.content` so `portal_search`'s per-keystroke `ILIKE '%q%'` predicates on the customer portal do not force a sequential scan on a large tenant.
- **SPEC-9.248**: migrations/147_portal_exports_truncated_marker.sql adds `portal_exports.bundle_truncated` (NOT NULL, default FALSE) and `portal_exports.bundle_section_totals` (nullable JSONB), populated by the export worker when it caps a per-section fetch, so the portal export status endpoint can surface an incomplete bundle to the SPA instead of a truncated bundle looking identical to a complete one.
- **SPEC-9.249**: migrations/155_teams_name_uniqueness.sql adds a case-insensitive unique index on `teams(tenant_id, LOWER(name)) WHERE is_active`, so two active teams cannot share a name within a tenant while an archived team's name is free to be reused.
- **SPEC-9.250**: migrations/156_team_members_updated_at.sql adds `team_members.updated_at` with a `BEFORE UPDATE` trigger reusing the shared `update_updated_at_column()` function (migration 024), so a role change on a team membership is audit-trackable without a delete-and-reinsert.

## 10. Deployment and operations

- Build: `oci-build/Dockerfile` builds both binaries in a musl Rust builder image with dependencies cached in a separate
  layer, then copies `mokosh-server`, `mokosh-bootstrap`, `migrations/` and the font license into an Alpine runtime
  image. Build arguments `MOKOSH_GIT_HASH`, `MOKOSH_GIT_DESCRIBE`, `MOKOSH_BUILD_DATE` and `SOURCE_DATE_EPOCH` feed the
  version banner and image labels. The release profile uses LTO, one codegen unit, `panic = "abort"` and stripping.
- Process: the image starts as root through `gosu-entrypoint.sh`, which can remap the app user's uid and gid from `PUID`
  and `PGID`, runs root hooks in `/etc/entrypoint.d/`, changes ownership of `DATA_DIRS` (`/app/attachments`), and drops
  to `appuser` (default uid 1001) with `gosu` before running `/app/mokosh-server`. Started as a non-root user it only
  checks that `DATA_DIRS` is writable.
- Port: 8080 is exposed; the listen port is `PORT`.
- Volumes: local object storage writes under `STORAGE_ROOT` (the image prepares `/app/attachments`); persist it when the
  `local` provider is used.
- Health: `GET /api/v1/health` returns `OK` without touching dependencies and is the image `HEALTHCHECK`
  (30 s interval, 3 s timeout). `GET /api/v1/ready` pings the database (3 s bound) and, when `INFISICAL_ADDRESS` is set,
  the secret manager's `/api/status` (1 s timeout); it answers `200` with `status: ready` or `503` with `not_ready`, and
  per-check results (`ok`, `skipped` or `error: ...`). It is sent with `Cache-Control: no-store`.
- Version: `GET /api/v1/version` returns the build's version information; the startup log prints the banner.
- Development: `Dockerfile` runs `cargo run` against sources mounted by `compose.dev.yml`, which also defines
  PostgreSQL, a local mail catcher, and optional profiles for a secret manager and an S3-compatible store.
- Repository checks: the `justfile` `check` recipe runs compile, clippy, rustfmt, migration immutability, route-consumer,
  configuration and documentation guards implemented as Nushell scripts under `scripts/`; integration tests live in
  `tests/` and browser tests in `e2e/`.

## 11. Non-functional behavior

- Logging: `tracing` text output to stdout, filtered by `RUST_LOG`. Request tracing is applied to the whole router.
  Boot logs record the hosting profile, the provider selected per capability and whether each was chosen by profile or by
  explicit configuration, the classification of each governed secret (used, missing, shadowed, misplaced), and
  warnings for declared features whose keys no provider holds. Expected token rejections (junk, expired) log at `debug`;
  identity-provider outages and misconfiguration log at `warn`.
- Errors: all error responses share one JSON envelope; a failure is never reported with a success status
  (section 2.4). Database and internal errors are mapped to server-error statuses.
- Background work: tick failures are logged and retried at the next tick; notification delivery distinguishes transient
  from permanent failures and records the state on the row.
- Concurrency: several replicas can run the dispatcher safely (`SKIP LOCKED`); rate limiters and the revoked-session
  list are per process.
- Performance bounds: database pool of 20 connections per pool; responses are gzip or brotli compressed; attachment
  downloads stream from storage instead of buffering; recurring appointments are expanded per requested range.
- Observability endpoints: `/api/v1/health`, `/api/v1/ready`, `/api/v1/version`, `/api/v1/providers` (public
  provider summary), `/api/v1/admin/providers/status` (full report, JSON or HTML) and its refresh.
