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

- **SPEC-1 and 2.1**: the combined router's `.fallback(...)` must catch every request matching none of the six
  top-level nests, including a bare `GET /`, and must answer the `not_a_frontend` 404 HTML page rather than axum's
  default 404, which would otherwise leak internal route information, citing `src/api/router.rs:1400`.

### Non-goals

mokosh-server does not serve a user interface (see above). It does not implement its own OIDC identity provider;
`bunyip` is the one identity provider this document names, and provisioning a different one is out of scope. It
does not read application configuration from any source this module group's registry does not declare: a key not
in `src/config/variables.toml` has no reader, by construction of the registry described in section 2.7. It does
not run scheduled jobs across multiple processes: the scheduler in section 2.5 assumes exactly one running
instance, and offers no leader election or distributed locking.

### Process model

One long-running process per deployment, serving every tenant from the same `mokosh-server` binary; there is no
per-tenant process or thread. Section 2.3 states the boot sequence in full; section 2.5 states the interval and
one-shot background work that runs inside the same process once it is up.

### Retention and cleanup

This module group (sections 1-2) owns no application data, so it states no retention or cleanup rule of its own
for any domain area; those rules belong to the module group that owns the data and are specified where that group
lands:

- Billing, time, tickets, contacts, documents, and knowledge base: none in this section; see the module group that
  owns each (billing and time, service desk, remaining modules) once its specification section exists.
- Connection pool lifecycle (`src/db/pool.rs`) is a resource limit, not a data-retention rule: a connection is
  recycled on an idle timeout and a hard lifetime cap, covered in section 2.6, but no row is ever deleted by it.
- The one-shot correction tasks in `src/scheduler/one_shot.rs` run once per process start; they are idempotent
  corrections to existing rows, not a cleanup or expiry mechanism, covered in section 2.5.

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

`mokosh-server` is one long-running process. `src/main.rs` runs the following, in order. Each step either ends
startup (a hard failure) or logs and continues (a soft failure); which one applies is stated per step.

- **SPEC-1 and 2.2**: a secret resolved via `resolve_secret` (`JWT_SECRET`, `ENCRYPTION_KEY`,
  `BUNYIP_WEBHOOK_SECRET`) must fall back to its hardcoded development value when unset only in the
  development/dev/test environments; every other environment value, including the development value set
  explicitly, is a fatal boot error, citing `src/main.rs:128`.
- **SPEC-1 and 2.3**: outside development/dev/test, a `JWT_SECRET` shorter than 32 bytes is a fatal boot error;
  development/dev/test accept any length, citing `src/main.rs:145`.
- **SPEC-1 and 2.4**: outside development/dev/test, `ENCRYPTION_KEY` must be exactly 64 ASCII hex characters
  (32 bytes hex-encoded); development/dev/test also accept a raw 32-byte key, citing `src/main.rs:162`.
- **SPEC-1 and 2.5**: outside development/dev/test, `MOKOSH_DEPLOYMENT_MODE`, `MOKOSH_APP_DATABASE_URL`,
  `BASE_URL`, `CLIENT_ORIGIN` and `SPA_BASE_URL` form a closed, ordered list; `check_deployment_requirements`
  must collect every one left unset or blank and raise a single combined fatal error naming each one's purpose,
  legal options and an example, citing `src/main.rs:215`.
- **SPEC-1 and 2.6**: a recognized `argv[1]` subcommand must short-circuit to `run_cli` and return before
  tracing, dotenv, configuration or the database are touched, citing `src/main.rs:530`.
- **SPEC-1 and 2.7**: the server path's tracing subscriber must read `RUST_LOG`, defaulting to `"info"` when
  unset or unparsable; this init is skipped entirely on the CLI-dispatch path, which installs its own
  (SPEC-1 and 2.58), citing `src/main.rs:546`.
- **SPEC-1 and 2.8**: two unconditional info-level lines (the version banner, then a hardcoded "multi-tenant
  mode" line) must be logged before any configuration, env file or database is touched, citing `src/main.rs:556`.
- **SPEC-1 and 2.9**: `.env` is loaded via `dotenvy::dotenv().ok()`, so a missing file must be silently
  ignored rather than failing startup, citing `src/main.rs:566`.
- **SPEC-1 and 2.10**: an unrecognized `MOKOSH_DEPLOYMENT_MODE` value must end startup here, naming the legal
  values, before the database or any provider is touched, citing `src/main.rs:575`.
- **SPEC-1 and 2.11**: a retired storage env var name must end startup; the message is printed to stderr (not
  only the tracing log) and returned as the process's fatal error, citing `src/main.rs:586`.
- **SPEC-1 and 2.12**: an unrecognised `CONFIG_BACKEND`, or a failure resolving the first configuration
  generation, must end startup here, citing `src/main.rs:598`.
- **SPEC-1 and 2.13**: unlike every other fatal boot step in this function, an `AppConfig::from_env` failure
  must panic (`.expect`) rather than returning a typed error, citing `src/main.rs:603`.
- **SPEC-1 and 2.14**: DB role self-provisioning must run before either request pool is opened, and must be
  skipped entirely when `mokosh_migrator` can already log in; a failure must propagate as a fatal boot error,
  citing `src/main.rs:617`.
- **SPEC-1 and 2.15**: `Database::new` must open both the app and migrator pools in one call; a connection
  failure must propagate as a fatal boot error before migrations ever run, citing `src/main.rs:628`.
- **SPEC-1 and 2.16**: a migration failure must be fatal: logged at error level and returned, ending startup
  without serving on a half-migrated database, citing `src/main.rs:641`.
- **SPEC-1 and 2.17**: `RUN_MIGRATIONS=false` must skip the whole migration block silently; `main.rs` logs no
  explicit "migrations skipped" line in that case, citing `src/main.rs:643`.
- **SPEC-1 and 2.18**: "Database connected" must be logged unconditionally, whether or not migrations ran,
  citing `src/main.rs:653`.
- **SPEC-1 and 2.19**: a platform-admin bootstrap failure must be logged at warn level with boot continuing;
  it is never fatal, citing `src/main.rs:657`.
- **SPEC-1 and 2.20**: a single hardcoded info line names the two auth mechanisms (bunyip-as-OP Resource
  Server plus the legacy HS256 cookie); it is not derived from which providers actually resolved, citing
  `src/main.rs:668`.
- **SPEC-1 and 2.21**: a malformed `ENCRYPTION_KEY`, re-parsed into raw bytes here after its shape was already
  validated by `AppConfig::from_env`, must panic via `.expect` rather than returning a typed boot error, citing
  `src/main.rs:674`.
- **SPEC-1 and 2.22**: application-tier secret provider construction (the per-secret defaults and the
  process-wide installation) must be fatal; a failure here ends startup before any provider-backed secret can
  be read, citing `src/main.rs:699`.
- **SPEC-1 and 2.23**: a half-configured Google OAuth client pair (one of id/secret set, the other missing) is
  a fatal boot error; both unset resolves to `None` with no error, citing `src/main.rs:720`.
- **SPEC-1 and 2.24**: a half-configured Xero or Intuit application pair is a fatal boot error, the same
  posture as the Google client; unavailable `app_secrets` falls back to `IssuerApps::default()` with no error,
  citing `src/main.rs:733`.
- **SPEC-1 and 2.25**: `app_secrets::current()` returning `None` here, meaning the earlier `init_from_env` call
  silently failed to install, must be a fatal error, not a panic, citing `src/main.rs:778`.
- **SPEC-1 and 2.26**: a failure loading the product-name setting must be logged at warn level with boot
  continuing on the built-in default name, citing `src/main.rs:792`.
- **SPEC-1 and 2.27**: an unrecognised `MAIL_PROVIDER`, or `MAIL_PROVIDER=smtp` with no `SMTP_HOST`, must end
  startup; the resolved provider and its source (explicit vs. profile default) are logged at info level,
  citing `src/main.rs:812`.
- **SPEC-1 and 2.28**: a failure loading the mailer configuration (a DB setting or `SMTP_*` env) must panic via
  `.expect`, citing `src/main.rs:824`.
- **SPEC-1 and 2.29**: a failure constructing the `Mailer` for the selected provider must panic via `.expect`,
  citing `src/main.rs:832`.
- **SPEC-1 and 2.30**: the mailer transport must be verified at boot, not on first send; a verify failure is
  fatal (logged at error level, startup ends); `LogMailer`'s verify is a no-op `Ok(())`, citing
  `src/main.rs:844`.
- **SPEC-1 and 2.31**: the Bunyip RS verifier is optional; a missing or invalid `OIDC_ISSUER`/`OIDC_AUDIENCE`
  configuration must log an info-level reason and leave it `None` (the legacy HS256 path still serves); it is
  never fatal, citing `src/main.rs:860`.
- **SPEC-1 and 2.32**: an invalid `AUTH_PROVIDERS` selection must end startup; a valid one is logged via
  `record()` and installed process-wide before the router is built, so every later reader of the selection sees
  the same value, citing `src/main.rs:883`.
- **SPEC-1 and 2.33**: tenant-secret provider construction must panic via `.expect("secret provider
  configuration")` on misconfiguration rather than returning a typed boot error, citing `src/main.rs:971`.
- **SPEC-1 and 2.34**: object storage provider construction must panic via `.expect("storage provider
  configuration")` on misconfiguration, the same posture as the secret provider, citing `src/main.rs:993`.
- **SPEC-1 and 2.35**: `provider_selection.record()` must log, for all five capability kinds, whether the
  hosting profile's default stands or an operator's explicit override took effect; it performs no validation
  of its own, citing `src/main.rs:1034`.
- **SPEC-1 and 2.36**: the `FeatureSnapshot` must start with every toggle off; the scheduler's first
  (immediate) tick of `FeatureToggleRefresh` is what first populates it, so a request served before that tick
  sees every feature off regardless of the database's rows, citing `src/main.rs:1047`.
- **SPEC-1 and 2.37**: unlike every other job registered in `main.rs`, the feature-toggle refresh and (below)
  the asset-signature-detector refresh must be registered at their own job-module constant intervals, not a
  literal duration written in `main.rs`, citing `src/main.rs:1054`.
- **SPEC-1 and 2.38**: the notification dispatcher must be registered on a hardcoded 5-second interval, the
  only job in `main.rs` at that cadence, citing `src/main.rs:1077`.
- **SPEC-1 and 2.39**: RMM sync must be registered on a hardcoded 60-second interval, citing
  `src/main.rs:1080`.
- **SPEC-1 and 2.40**: the contact-sync runner must be registered as a wakeable job on a hardcoded 60-second
  interval AND woken on demand via `contact_sync_wake` (also handed to `create_api_router`), so a request that
  commits a sync run need not wait for the next tick, citing `src/main.rs:1115`.
- **SPEC-1 and 2.41**: contract lifecycle and recurring invoicing must each be registered on a hardcoded
  3600-second (1-hour) interval, citing `src/main.rs:1134`.
- **SPEC-1 and 2.42**: SLA sweep must be registered on a hardcoded 60-second interval, citing
  `src/main.rs:1141`.
- **SPEC-1 and 2.43**: calendar reminders must be registered on a hardcoded 60-second interval, citing
  `src/main.rs:1165`.
- **SPEC-1 and 2.44**: the grant-invitation expiry sweep must be registered using the module's own
  `GRANT_INVITATIONS_SWEEP_INTERVAL` constant rather than a literal duration written in `main.rs`, citing
  `src/main.rs:1181`.
- **SPEC-1 and 2.45**: scheduled reports must be registered on a hardcoded 60-second interval, citing
  `src/main.rs:1201`.
- **SPEC-1 and 2.47**: `main.rs` must spawn five one-shot movers via `spawn_once` (KB attachment, tenant logo,
  branding assets, gateway credential, Google client-secret cleanup) without awaiting any of them; a failure
  inside one is handled by `spawn_once` or the mover itself, not surfaced to `main`'s own control flow, citing
  `src/main.rs:1248`.
- **SPEC-1 and 2.46**: scheduled dashboards must be registered on a hardcoded 60-second interval, citing
  `src/main.rs:1215`.
- **SPEC-1 and 2.48**: invoice reminders must be registered on a hardcoded 3600-second (1-hour) interval,
  citing `src/main.rs:1319`.
- **SPEC-1 and 2.49**: status-observation retention must be registered on a hardcoded 21600-second (6-hour)
  interval, citing `src/main.rs:1334`.
- **SPEC-1 and 2.50**: `scheduler.start()` must be called exactly once, after every job above is registered;
  its returned handles must be held for the rest of `main` so the spawned tasks stay alive rather than being
  dropped before the server starts serving, citing `src/main.rs:1341`.
- **SPEC-1 and 2.51**: an unset `IP2LOCATION_DB_PATH`, or a failed `.BIN` load, must leave `geoip` as `None`
  and log info/warn respectively; never fatal, citing `src/main.rs:1351`.
- **SPEC-1 and 2.52**: an unset `IP2PROXY_DB_PATH`, or a failed `.BIN` load, must leave `ip_enrich` as `None`
  and log info/warn respectively; never fatal, independent of the geoip service, citing `src/main.rs:1374`.
- **SPEC-1 and 2.53**: the router must be built with one `create_api_router` call, after every provider,
  worker and secret above is ready; it is the last construction step before the listener binds, citing
  `src/main.rs:1397`.
- **SPEC-1 and 2.54**: the bind address must be `{HOST}:{PORT}` (defaulting to `0.0.0.0`/`8080` per
  `AppConfig::from_env`); a malformed combination fails the `SocketAddr` parse and is fatal, citing
  `src/main.rs:1427`.
- **SPEC-1 and 2.55**: a bind failure (for example the port already in use) must propagate as a fatal startup
  error, citing `src/main.rs:1431`.
- **SPEC-1 and 2.56**: `axum::serve` must run with no graceful-shutdown handler attached (no
  `.with_graceful_shutdown`, no SIGTERM/SIGINT handling in `main.rs`); the process relies entirely on the
  default OS signal behavior and drains no in-flight connection on exit, citing `src/main.rs:1456`.
- **SPEC-1 and 2.57**: `run_cli` must load `.env.infisical` then `.env`, each via `let _ =` so either file's
  absence is silently ignored; this is a different source order than the server path (SPEC-1 and 2.9), which
  loads only `.env`, citing `src/main.rs:1463`.
- **SPEC-1 and 2.58**: `run_cli` must install its own tracing subscriber (the same `RUST_LOG`-with-`"info"`-
  default rule as SPEC-1 and 2.7), because the CLI dispatch at the top of `main` returns before `main`'s own
  subscriber is installed, citing `src/main.rs:1463`.
- **SPEC-1 and 2.59**: a subcommand error must be printed to stderr and exit the process via
  `std::process::exit(1)`, not returned as this function's `Result`, so `main`'s own error formatting never
  sees it, citing `src/main.rs:1474`.

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
(section 9, "Tenancy").

Errors: every failure is an `AppError` rendered as a JSON envelope `{"error": {"code", "message", "errors"?}}`. The
`normalize_error_envelope` layer rewrites plain-text extractor rejections into the same envelope. Rate-limit
rejections answer `429` with `Retry-After`. A deleted account answers `410` with code `ACCOUNT_DELETED`. An expired
token answers `401` with a `WWW-Authenticate: Bearer` challenge that distinguishes expired, invalid and ended-session
credentials.

- **SPEC-1 and 2.60**: the seven top-level mounts and their auth models (session `/api/v1`, no-auth-by-design
  `/api/v1/public`, contact Bearer `/api/v1/contact`, and the four signed receivers) must match CLAUDE.md's
  "Routing model" claim; the invoice-issuer webhooks mount is a fifth signed receiver CLAUDE.md's prose does
  not name individually (a documentation-completeness gap; see Intent unclear), citing
  `src/api/router.rs:1373`.
- **SPEC-1 and 2.61**: `sanitize_json_body` must be layered once on the combined `Router`, outside every nest,
  so it runs on every path including the signed receivers; the `RAW_BODY_PATHS` exemption is a prefix check
  inside the function itself, not a difference in which nests this layer wraps, citing
  `src/api/router.rs:1414`.
- **SPEC-1 and 2.62**: seven independent `normalize_error_envelope` instances must each be layered separately:
  `api_v1`, `bunyip_nest`, `stripe_webhooks`, `paypal_webhooks`, `invoice_issuer_webhooks` (one per provider
  closure call), `public_api`, and `contact_api`, citing `src/api/router.rs:992` (and repeated at
  `src/api/router.rs:1118`, `:1166`, `:1190`, `:1240`, `:1334`, `:1367`).
- **SPEC-1 and 2.63**: the public API's per-IP rate limit must trigger on every request to that nest, keyed by
  the caller's extracted client IP (trusted-proxy-aware); the quota is `PUBLIC_API_PER_MIN` (60/minute), and a
  caller past quota gets a 429 with `Retry-After`, citing `src/api/router.rs:1321`.
- **SPEC-1 and 2.64 DEFECT**: the comment above `logout_verifier.map(...)` claims the back-channel logout
  receiver is "Mounted whether or not the verifier exists", but `logout_verifier.map(...)` only builds
  `Some(router)` when `bunyip_verifier` was `Some`, and the `match backchannel_logout { Some(logout) =>
  bunyip_nest.merge(logout), None => ... }` further down only merges the route in that case; with no verifier
  the route is NOT mounted and a request to it 404s, contradicting the comment's own claim. Not fixed here;
  see Defects found, citing `src/api/router.rs:1076` and `src/api/router.rs:1133`.
- **SPEC-1 and 2.65**: `api_v1`'s middleware stack, innermost to outermost, must be: `seed_middleware`, then
  `auth_middleware`, then the contact-plane middleware, then `Extension<Database>`,
  `Extension<SettingsService>`, `Extension<PlatformAdminService>`, and finally `normalize_error_envelope` as
  the outermost layer; each later `.layer()` call wraps the ones before it, citing `src/api/router.rs:924`.
- **SPEC-1 and 2.66**: `/platform`'s own `PlatformAdminService` instance (built at the nest) must be a
  distinct object from the one the outer `Extension` layer injects near the end of the chain; both target the
  same table but are separate instances serving separate call sites, citing `src/api/router.rs:624` (and
  `src/api/router.rs:979`).
- **SPEC-1 and 2.67**: `/tenants`, `/teams` and `/me` (teams) must only be mounted when the `multi-tenant`
  cargo feature is on; a build without it has no tenant CRUD and no teams surface at all, not merely a gated
  handler, citing `src/api/router.rs:638`.
- **SPEC-1 and 2.68**: `contact_api` must compose `contact_portal::contact_routes` with the branding module's
  contact-scoped routes, sharing one `ContactAuthService` instance between the two merged routers so a single
  `load_capabilities` implementation backs both, citing `src/api/router.rs:1354`.
- **SPEC-1 and 2.69**: both routes on the `bunyip_nest` must authenticate via an HMAC signature over the raw
  body rather than a session; `account_deleted` must run on the migrator/BYPASSRLS pool because it is pre-auth
  and resolves its own tenant from the `users` row it reads, citing `src/api/router.rs:1120`.
- **SPEC-1 and 2.70**: Stripe and PayPal must share `provider_webhook_handler` and the per-tenant
  `/webhooks/{tenant_id}` path shape; only `provider_id` and the state's `billing`/`payment_methods` differ
  between them, citing `src/api/router.rs:1160`.
- **SPEC-1 and 2.71**: the invoice-issuer webhooks must register one URL per provider (Xero, QuickBooks), not
  one per tenant, since there is one application per provider and so one webhook subscription for the host to
  configure, unlike the per-tenant Stripe/PayPal `{tenant_id}` path, citing `src/api/router.rs:1385`.
- **SPEC-1 and 2.72**: the global stack order on the combined `Router`, each `.layer()` wrapping the previous
  outward, must be: `sanitize_json_body`, then tracing, then compression, then CORS, then security headers
  (outermost), so every response from every nest passes through all five, citing `src/api/router.rs:1420`.
- **SPEC-1 and 2.73**: `GET /api/v1/health` must answer the static string `"OK"` with no downstream dependency
  check at all, in contrast to `/ready`, citing `src/api/router.rs:1487`.
- **SPEC-1 and 2.74**: `GET /api/v1/ready` must answer 200 with
  `{"status":"ready","checks":{"db":...,"infisical":...}}` when both checks pass, else 503 with
  `"status":"not_ready"` and the failing check's value replaced by an `"error: ..."` string; every response
  must carry `Cache-Control: no-store`, citing `src/api/router.rs:1523`.
- **SPEC-1 and 2.75**: the readiness DB ping must be bounded to 3 seconds; a ping that neither answers nor
  errors within that bound is treated as a failure ("db ping exceeded 3s") rather than hanging the `/ready`
  response open, citing `src/api/router.rs:1579`.
- **SPEC-1 and 2.76**: the Infisical probe must be built lazily in a `OnceLock` on the first `/ready` request,
  not at `create_api_router` time, caching the parsed URL, a credential-scrubbed display string, and a reused
  `reqwest::Client`; a blank or unset `INFISICAL_ADDRESS` at that first call means no probe runs for the
  lifetime of the process, citing `src/api/router.rs:1608`.
- **SPEC-1 and 2.77**: `probe_infisical` must return a three-way result read by `ready_check`: `Ok(true)`
  (probe ran, 2xx response) renders `"infisical":"ok"`; `Ok(false)` (unconfigured) renders `"skipped"` and
  never fails readiness; `Err(_)` (configured but DNS/TCP/non-2xx/timeout failure) renders `"error: ..."` and
  fails readiness with a 503, citing `src/api/router.rs:1688`.
- **SPEC-1 and 2.78**: a route-overlap test must textually scan `tickets/routes.rs` (mounted at `/tickets`)
  and `tickets/attachments.rs` (merged at the top level) for `.route(...)` calls, compute each one's effective
  `(method, prefix+path)`, and fail on any pair both sources register; it also fails if the scan finds 20 or
  fewer routes total, guarding against the parser silently matching nothing, citing `src/api/router.rs:1797`.
- **SPEC-1 and 2.79**: two tests (`brotli_is_negotiated_when_the_client_advertises_it`,
  `gzip_only_client_still_gets_gzip`) must confirm the global `CompressionLayer::new()` offers brotli when the
  client advertises it alongside gzip, and falls back to gzip for a gzip-only client, without the layer's
  offered algorithm set being visible from its construction call, citing `src/api/router.rs:1971`.
- **SPEC-1 and 2.80**: `CorsOriginMatcher::from_entries` must run exactly once, at router construction (boot),
  not per request; a parse failure must panic the boot rather than being deferred to request time, citing
  `src/api/cors_origin.rs:53` (and `src/api/cors_origin.rs:63` for the per-request `matches` call it feeds).
- **SPEC-1 and 2.81**: `CorsOriginMatcher::from_entries` is the one call site that parses `CORS_ORIGIN` entries;
  `matches` itself must do no parsing, only byte comparisons against rules parsed once at boot, citing
  `src/api/cors_origin.rs:53`.
- **SPEC-1 and 2.82**: an empty `CORS_ORIGIN` entry must panic at boot rather than being skipped or
  allow-listing nothing, citing `src/api/cors_origin.rs:105`.
- **SPEC-1 and 2.83**: a wildcard entry with no suffix after `<scheme>://*.` must panic at boot, citing
  `src/api/cors_origin.rs:113`.
- **SPEC-1 and 2.84**: a wildcard suffix containing another `*` must panic at boot; only the leftmost label
  may be a wildcard, citing `src/api/cors_origin.rs:119`.
- **SPEC-1 and 2.85**: a wildcard suffix with no dot must panic at boot; the suffix must include a TLD, citing
  `src/api/cors_origin.rs:125`.
- **SPEC-1 and 2.86**: an entry containing `*` outside the leading `<scheme>://*.` position must panic at
  boot, citing `src/api/cors_origin.rs:138`.
- **SPEC-1 and 2.87**: an exact entry that does not parse as a valid header value must panic at boot, citing
  `src/api/cors_origin.rs:144`.
- **SPEC-1 and 2.88**: an exact-origin rule must match byte-for-byte, case-sensitively, with no normalization
  of the incoming `Origin` header, citing `src/api/cors_origin.rs:67`.
- **SPEC-1 and 2.89**: a wildcard rule's scheme must be matched as a literal prefix, so a wildcard entry never
  matches the other scheme, citing `src/api/cors_origin.rs:71`.
- **SPEC-1 and 2.90**: a wildcard rule's suffix comparison must be a tail (suffix) comparison, not
  leftmost-label-only, so any number of leading host labels match, citing `src/api/cors_origin.rs:85`.
- **SPEC-1 and 2.91**: a wildcard rule must reject the bare apex and the empty-label host by requiring the
  matched host to be strictly longer than the stored suffix, citing `src/api/cors_origin.rs:81`.
- **SPEC-1 and 2.92**: a wildcard rule's suffix is the literal configuration text and must be compared
  byte-for-byte, case-sensitively, citing `src/api/cors_origin.rs:67`.
- **SPEC-1 and 2.93**: a wildcard rule's stored suffix must include a leading dot and must include a port if
  one was written into the configuration entry, citing `src/api/cors_origin.rs:85`.

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

- **SPEC-1 and 2.94**: one job runs per registration, ticked at a fixed interval on its own tokio task, citing
  `src/scheduler/mod.rs:68`.
- **SPEC-1 and 2.95**: a second job registered with the same name must panic at registration rather than
  silently shadowing the first, citing `src/scheduler/mod.rs:180`.
- **SPEC-1 and 2.96**: a wakeable job must keep its registered interval; `JobWake` only runs it sooner and
  never changes the cadence, citing `src/scheduler/mod.rs:173`.
- **SPEC-1 and 2.97**: `tokio::sync::Notify::notify_one` retains at most one permit, so any number of wakes
  before the next `notified()` must collapse into a single extra run rather than one run per wake, citing
  `src/scheduler/mod.rs:108`.
- **SPEC-1 and 2.98**: `tokio::time::interval` must fire its first tick immediately, then every `interval`,
  with missed ticks skipped rather than queued, citing `src/scheduler/mod.rs:240`.
- **SPEC-1 and 2.99**: a tick that returns `Err` must be logged at warn and discarded; the loop must never
  stop or retry early, citing `src/scheduler/mod.rs:273`.
- **SPEC-1 and 2.100**: a one-shot pass must run exactly once per process start, never on a recurring
  `Scheduler` interval, citing `src/scheduler/one_shot.rs:64`.
- **SPEC-1 and 2.101**: a `main.rs` local variable named with the `_mover` or `_cleanup` suffix must never be
  `scheduler.register()`'d, enforced by a test that scans `main.rs` for the convention, citing
  `src/scheduler/one_shot.rs:134`.

### 2.6 Database and tenancy

Two connection pools back every request: an unprivileged `mokosh_app` pool (`NOBYPASSRLS`) that serves requests
under row-level security, and a `mokosh_migrator` pool (`BYPASSRLS`) reserved for migrations and the handful of
tables row-level security does not cover.

- **SPEC-1 and 2.102**: each pool must be capped at 20 connections (minimum 2), with a 30-second acquire
  timeout, 600-second idle timeout and 1800-second maximum connection lifetime, citing `src/db/pool.rs:62`.
- **SPEC-1 and 2.103**: `Database::pool()` must return the unprivileged `app_pool`; a serving query that
  bypasses `begin_with_tenant` fail-closes to zero rows under row-level security, citing `src/db/pool.rs:110`.
- **SPEC-1 and 2.104**: `Database::migrator_pool()` is the BYPASSRLS accessor; `scripts/check-pool-safety.nu`
  must require every bare `.pool()` call site elsewhere to carry a `SAFETY (PMS-285)` note, citing
  `src/db/pool.rs:122`.
- **SPEC-1 and 2.105**: `set_config`'s `true` argument must make the setting transaction-local (`SET LOCAL`
  semantics), so the tenant GUC never leaks to the next request that reuses this pooled connection, citing
  `src/db/pool.rs:189`.
- **SPEC-1 and 2.106**: `health_check` must run against `app_pool`, never `migrator_pool`, so a readiness
  probe exercises the same connection serving requests, citing `src/db/pool.rs:150`.
- **SPEC-1 and 2.107**: `run_migrations` must run on `migrator_pool`; a migration failure must return
  `AppError::Database`, which ends startup, citing `src/db/pool.rs:136`.
- **SPEC-1 and 2.108**: `Database::from_pool` must wrap one pool as both `app_pool` and `migrator_pool`, so
  row-level security never bites (the single role used is whichever one connected it), citing
  `src/db/pool.rs:84`.
- **SPEC-1 and 2.109**: `Database::from_pools` must wrap two distinct pools, so a test can connect `app_pool`
  as the unprivileged `mokosh_app` role and exercise row-level security against it, citing
  `src/db/pool.rs:97`.
- **SPEC-1 and 2.110**: `provision_roles` must drive which provisioning statements run, if any, from four
  boot-time role-probe outcomes (`RolesProbe::BothExist`, `MigratorConnectsAppMissing`, `AppPasswordMismatch`,
  `MigratorCannotConnect`), citing `src/db/provision.rs:62`.
- **SPEC-1 and 2.111**: only `AppPasswordMismatch` must skip the migrator statements, so reconciling
  `mokosh_app`'s password never rewrites `mokosh_migrator`'s, citing `src/db/provision.rs:239`.
- **SPEC-1 and 2.112**: provisioning must create `mokosh_migrator` as `LOGIN BYPASSRLS` with `GRANT ALL ON
  SCHEMA public` and `GRANT CREATE ON DATABASE`, so migrations can self-install the trusted extensions
  (uuid-ossp/pg_trgm/citext/pgcrypto), citing `src/db/provision.rs:254`.
- **SPEC-1 and 2.113**: provisioning must create `mokosh_app` as `LOGIN NOSUPERUSER NOBYPASSRLS` with
  CONNECT/USAGE/DML grants on current objects; default-privilege grants for future migration-created objects
  are a separate statement group, citing `src/db/provision.rs:313`.
- **SPEC-1 and 2.114**: only Postgres SQLSTATE `28P01` must count as a password mismatch; every other failure
  reports `Ok` so a transient probe failure cannot force a full provision, citing `src/db/provision.rs:505`.
- **SPEC-1 and 2.115**: `rolcanlogin = TRUE` must be required for the probe to treat a hand-created
  `mokosh_app` as already provisioned; a NOLOGIN role routes to the full provision path instead of the fast
  path, citing `src/db/provision.rs:440`.
- **SPEC-1 and 2.116**: every read in `src/db/identity.rs` must run on the migrator (BYPASSRLS) pool;
  `identities` carries no `tenant_id` and no row-level security, and `tenant_memberships`' fail-closed
  `tenant_isolation` policy is the backstop if a caller passes the app pool instead, citing
  `src/db/identity.rs:21`.
- **SPEC-1 and 2.117**: `record_identity_mfa_success` must compare-and-set on `mfa_last_totp_step`; zero rows
  affected must be treated as a replay, citing `src/db/identity.rs:387`.
- **SPEC-1 and 2.118**: grant-arm rows must be collected before owner-arm rows, and an owner-arm row whose
  `tenant_id` already appeared from a grant must be skipped, so a grantee's seat keeps its grant designation,
  citing `src/db/identity.rs:273`.
- **SPEC-1 and 2.119**: `platform_admins` is row-level-security-exempt and every read/write in
  `src/db/platform_admin.rs` must run on the migrator pool; its credential lifecycle is independent of
  `users`/`identities`/`tenant_memberships`, citing `src/db/platform_admin.rs:10`.
- **SPEC-1 and 2.120**: `stage_mfa_secret` must stage the secret without flipping `mfa_enabled`, so a
  misconfigured authenticator cannot lock an operator out before `enable_mfa` confirms it with a live code,
  citing `src/db/platform_admin.rs:124`.
- **SPEC-1 and 2.121**: `spend_recovery_code` must use `rows_affected == 1` to distinguish a genuine spend from
  a replay or an unknown code, citing `src/db/platform_admin.rs:191`.

### 2.7 Configuration provider registry

Every configuration key is declared once in a registry (`src/config/registry.rs`), with a declared `Tier`
(Bootstrap or Application) determining whether it is resolved once per process or re-resolved on refresh.

- **SPEC-1 and 2.122**: `declare_keys!` is the one declaration site a `ConfigKey` and its Tier/since/required
  facts come from; a flag or a read naming a key it does not emit must fail to compile, citing
  `src/config/registry.rs:192`.
- **SPEC-1 and 2.123**: `Tier` is the two-tier split a provider read is built on (Bootstrap: resolved once per
  process, unchanged across a refresh; Application: re-resolved on refresh), citing
  `src/config/registry.rs:55`.
- **SPEC-1 and 2.124**: `config::get`/`has`/`served_by` are the one read path every caller outside the
  `ENTRY_POINTS` allowlist must use; `guard.rs`'s `every_env_read_goes_through_the_provider` test must enforce
  it, citing `src/config/mod.rs:722`.
- **SPEC-1 and 2.125**: `refresh` must re-resolve every application-tier key atomically and fall back to the
  previous generation on a rejected outcome, citing `src/config/mod.rs:754`.
- **SPEC-1 and 2.126**: a bootstrap-tier key must be refused before any I/O on both a full refresh and the
  per-key `refuse_refresh_of_bootstrap` form, and a rejected outcome must leave the live generation and its
  counter untouched, citing `src/config/mod.rs:785` (and `src/config/mod.rs:1130`).
- **SPEC-1 and 2.127**: `init_from_env` is the boot entry point that must install a provider from
  `CONFIG_BACKEND` (or the hosting profile's default) before any other read, citing `src/config/mod.rs:1152`.
- **SPEC-1 and 2.128**: `CONFIG_BACKEND` is a single-provider slot that can only resolve to `Environment`
  today; any other legal provider name must be treated as a wiring error directing the operator to
  `CONFIG_PROVIDERS`, citing `src/config/mod.rs:559`.
- **SPEC-1 and 2.129**: the staleness report must compare a recorded generation to a live provider probe
  without ever exposing a value, only key/provider identity, citing `src/config/mod.rs:900`.
- **SPEC-1 and 2.130**: the PMS-987 priority-list provider chain and its classification are wired but dormant;
  no boot path installs one, so `CONFIG_PROVIDERS` still only feeds the single-provider slot via
  `ConfigSelection` (see Intent unclear), citing `src/config/mod.rs:1286`.
- **SPEC-1 and 2.131**: the environment provider must treat a non-UTF8 env var as unset-with-error-log,
  distinct from genuinely absent, citing `src/config/env.rs:21`.
- **SPEC-1 and 2.132**: the environment provider's enumeration must list only declared registry keys, never
  the raw process environment, citing `src/config/env.rs:51`.
- **SPEC-1 and 2.133**: the file provider must read `CONFIG_FILE_DIR` directly as its own construction input,
  per the `guard.rs` provider-of-record exemption, citing `src/config/file.rs:67`.
- **SPEC-1 and 2.134**: a missing file-provider directory must resolve to silent-empty (enablement); an
  unreadable one must log an error; both collapse to an empty provider, citing `src/config/file.rs:85`.
- **SPEC-1 and 2.135**: the file provider must strip exactly one trailing newline per file; anything else in
  the value is preserved, citing `src/config/file.rs:267`.
- **SPEC-1 and 2.136**: the file provider's `set` and `delete` must both refuse a bootstrap-tier key before
  touching the filesystem, citing `src/config/file.rs:196`.
- **SPEC-1 and 2.137**: the database provider's `build` must refuse any bootstrap-tier key before any pool
  I/O, and its cache must only ever hold the application-tier keys it was given, citing
  `src/config/database.rs:69`.
- **SPEC-1 and 2.138**: the database provider's `set` must write `app_config` through the migrator pool (not
  the request-serving pool) and sync the cache so a read-after-write sees it, citing
  `src/config/database.rs:174`.
- **SPEC-1 and 2.139**: the Bunyip provider must serve only its declared `SERVED_KEYS` allowlist, to respect
  bunyip's per-app rate cap rather than the whole registry, citing `src/config/bunyip.rs:64`.
- **SPEC-1 and 2.140**: the Bunyip provider must read `BUNYIP_CONFIG_URL`/`_CLIENT_ID`/`_CLIENT_SECRET`
  directly as its own construction input, per the `guard.rs` exemption, citing `src/config/bunyip.rs:90`.
- **SPEC-1 and 2.141**: fetching a Bunyip-served key must treat a 404 as an unheld key (`Ok(None)`); a 401 or
  403 must be a hard provider error naming its own remedy, since each is fixed in a different place, citing
  `src/config/bunyip.rs:248`.
- **SPEC-1 and 2.142**: the Bunyip provider's `set` must be a stub that always refuses; the provider stays
  read-only until bunyip's write endpoint exists, citing `src/config/bunyip.rs:233`.
- **SPEC-1 and 2.143**: a `Flag<T>` must pair a declared application-tier key with a typed default, distinct
  from a `ConfigKey`'s own Tier (a flag always stays on Application so it is refresh-visible), citing
  `src/config/flags.rs:119`.
- **SPEC-1 and 2.144**: `Flag::read` is the one read path for a flag; a blank or unparsable raw value must
  fall back to the flag's default rather than failing the read, citing `src/config/flags.rs:151`.
- **SPEC-1 and 2.145**: `FlagDefault::PerProfile` must resolve against the current `DeploymentMode` on every
  read rather than freezing a mode at construction, citing `src/config/flags.rs:173`.
- **SPEC-1 and 2.146**: `ENTRY_POINTS` is the complete, named allowlist of files permitted to read the
  environment directly instead of through `crate::config::get`, citing `src/config/guard.rs:33`.
- **SPEC-1 and 2.147**: `every_env_read_goes_through_the_provider` is the acceptance criterion in executable
  form; a new direct environment read outside the seam and `ENTRY_POINTS` must fail the build, citing
  `src/config/guard.rs:204`.
- **SPEC-1 and 2.148**: `src/config/variables.toml` carries since/required/changelog facts for a variable read
  outside the registry (an `ENTRY_POINTS` file), where a `ConfigKey`'s own since/required fields do not apply;
  it is documentation data for `scripts/config-docs.nu`, not read by `declare_keys!` or any Rust code, citing
  `src/config/variables.toml:1`.

### 2.8 Provider seams

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

### 2.9 Version and build metadata

- **SPEC-1 and 2.149**: every `VersionInfo` field must be a compile-time `env!()` constant; there is no
  runtime git invocation in the server binary, citing `src/version.rs:11`.
- **SPEC-1 and 2.150**: `GET /api/v1/version` must serve `VersionInfo::current()` with no auth extractor on
  the handler, confirming `version.rs`'s doc-comment claim of endpoint consumption, citing
  `src/api/router.rs:547`.
- **SPEC-1 and 2.151**: the root `build.rs` must delegate `MOKOSH_GIT_HASH`/`MOKOSH_GIT_DESCRIBE`/
  `MOKOSH_BUILD_DATE` emission to `build-metadata::emit`, citing `build.rs:9`.
- **SPEC-1 and 2.152**: the resolution order for each build-metadata value must be the pre-set env var first,
  a `git` shell-out second, a hardcoded fallback last, citing `crates/build-metadata/src/lib.rs:44`.
- **SPEC-1 and 2.153**: the self-hosted update check must make no outbound request, and the probe must never
  be built, when `MOKOSH_UPDATE_CHECK_URL` is unset or blank, citing `src/version_check.rs:80`.
- **SPEC-1 and 2.154**: the update check's display URL must strip userinfo, query and fragment so a
  credential embedded in the configured URL never reaches an error message, citing `src/version_check.rs:89`.
- **SPEC-1 and 2.155**: a successful update-check result must be cached and reused for 15 minutes; a failed
  one for 60 seconds, citing `src/version_check.rs:131`.

### 2.10 Test infrastructure

The `#[mokosh_test]` attribute (`crates/mokosh-test-macros`, `crates/mokosh-test`) replaces `#[sqlx::test]`: every
test's database is cloned from one migrated template database rather than migrated from scratch.

- **SPEC-1 and 2.156**: the generated test body must run on a current-thread Tokio runtime with every driver
  enabled, matching what `#[sqlx::test]` built, citing `crates/mokosh-test-macros/src/lib.rs:90`.
- **SPEC-1 and 2.157**: the annotated fn must be async and take exactly one argument (the pool); any other
  shape must be a compile error, not a runtime one, citing `crates/mokosh-test-macros/src/lib.rs:60`.
- **SPEC-1 and 2.158**: the `#[mokosh_test]` attribute must take no arguments; the template is always built
  from `./migrations`, so a caller cannot ask for a different set, citing
  `crates/mokosh-test-macros/src/lib.rs:41`.
- **SPEC-1 and 2.159**: a per-test database must be a `CREATE DATABASE ... TEMPLATE` clone of the migrated
  template rather than migrated from scratch, unique per test and per run so it collides with nothing, citing
  `crates/mokosh-test/src/lib.rs:228`.
- **SPEC-1 and 2.160**: the template name must be `"mokosh_tpl_"` followed by the first 8 bytes (16 hex
  characters) of a SHA-256 digest over each migration's length-prefixed version/description/checksum, in
  order, citing `crates/mokosh-test/src/lib.rs:404`.
- **SPEC-1 and 2.161**: the template digest must run over `sqlx::migrate!`'s compile-time-embedded migration
  set, not a runtime directory walk, so the name and the schema that fills it always come from the same
  source, citing `crates/mokosh-test/src/lib.rs:407`.
- **SPEC-1 and 2.162**: `crates/mokosh-test/build.rs` must declare `migrations/` a build dependency so the
  crate recompiles whenever a migration is added or changed, citing `crates/mokosh-test/build.rs:14`.
- **SPEC-1 and 2.163**: the template build must be serialized across processes by a Postgres session-level
  advisory lock on a fixed key; the first process to arrive takes the lock and builds, every other process
  blocks until it is released, citing `crates/mokosh-test/src/lib.rs:99` (and
  `crates/mokosh-test/src/lib.rs:266`).
- **SPEC-1 and 2.164**: the template must be built under a `"_building"` name and only renamed to its real
  name once every migration has applied, so a process killed mid-build leaves a carcass rather than a
  template that looks done, citing `crates/mokosh-test/src/lib.rs:290`.
- **SPEC-1 and 2.165**: `ensure_template_built` must be idempotent with the build-if-absent logic `acquire`
  runs, so calling it ahead of the suite is optional, not required, citing `crates/mokosh-test/src/lib.rs:210`.
- **SPEC-1 and 2.166**: a per-test database name must be a v4 UUID prefix (so truncation at Postgres's 63-byte
  identifier limit never collides two test names) followed by as much of the test path's tail as fits, citing
  `crates/mokosh-test/src/lib.rs:432`.
- **SPEC-1 and 2.167**: cleanup must run in this exact order: close the pool, drop the pool, drop the runtime,
  then finish/drop the database; dropping the database before the runtime leaves a connected backend and
  Postgres refuses the `DROP DATABASE`, citing `crates/mokosh-test-macros/src/lib.rs:108`.
- **SPEC-1 and 2.168**: a failing (panicked) test's database must be kept, not dropped; a passing test's
  database must always be dropped, citing `crates/mokosh-test/src/lib.rs:84`.
- **SPEC-1 and 2.169**: dropping a test database must wait for `pg_stat_activity` to show zero sessions (up to
  60 polls at 50ms) before a non-`FORCE` `DROP DATABASE`; a database still occupied after the wait must be left
  in place with its sessions logged, citing `crates/mokosh-test/src/lib.rs:144`.
- **SPEC-1 and 2.170**: `close_pool` must bound `pool.close()` to 10 seconds; a timeout must log the test path
  rather than blocking the process indefinitely on a leaked pool, citing `crates/mokosh-test/src/lib.rs:64`.
- **SPEC-1 and 2.171**: after a template build, every other `"mokosh_tpl_%"` database with no active session
  must be dropped, so only the current and any still-in-use stale template persist, citing
  `crates/mokosh-test/src/lib.rs:335`.

### 2.11 Crate wiring and repo hygiene

- **SPEC-1 and 2.172**: `src/lib.rs` is the crate root and must wire every top-level module and re-export
  `Database`, `AuthState`, `CurrentUser`, `AppError`, `AppResult` and `VersionInfo` at the crate root, so
  downstream code reaches them as `mokosh_server::X` rather than through the full module path, citing
  `src/lib.rs:5`.
- **SPEC-1 and 2.173**: a repo-hygiene test must walk every tracked file under `CARGO_MANIFEST_DIR` (skipping
  build output and non-source directories, and any `.env*` file except `.env.example`) and fail if the former
  client repository's name (`mokosh-` followed by the plural of the thing a client is, assembled at runtime so
  this check is not itself a hit) appears as a byte substring anywhere, citing `src/lib.rs:70`.
- **SPEC-1 and 2.174**: a repo-hygiene test must scan every `.rs` file under `tests/` line by line for
  `#[sqlx::test` and fail if any line contains it, since a database-backed test must instead carry
  `#[mokosh_test]`, citing `src/lib.rs:129`.
- **SPEC-1 and 2.175**: a repo-hygiene test must read `.config/nextest.toml`, extract each of
  `[profile.ci]`'s and `[profile.unsupported]`'s `default-filter` string, and fail unless the unsupported
  filter equals `"not "` prepended to the ci filter (a literal text comparison, not an expression-equivalence
  check), citing `src/lib.rs:185`.
- **SPEC-1 and 2.176**: a repo-hygiene test must walk every `.rs` file under `src/secrets/` and `src/storage/`,
  and for every non-comment line containing a declaration keyword (`mod`/`struct`/`enum`/`trait`/`type`/`fn`/
  `union`/`const`/`static`) extract the identifier that follows and fail if it contains the substring `store`
  or `backend`; it does not scan prose or the `SECRET_BACKEND`/`STORAGE_BACKEND` env var names, citing
  `src/lib.rs:253`.

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

## 4. Utilities, PDF and wire types

Normative requirements for `src/utils/`, `src/pdf/` and `crates/mokosh-types/`. Each requirement below is cited at its
implementing or enforcing site with a `// SPEC-4.<n>` comment. Requirement numbers are assigned in file-reading order
and are not reused.

### 4.1 Money and date formatting

- **SPEC-4.1**: `utils::money::money` must format a decimal amount as `"{amount:.2} {currency_code}"` (exactly two
  decimal places, a literal space, then the code); when no currency is given it must default to `"USD"`, and it must
  never special-case any single currency with a bare symbol (for example `$`).
- **SPEC-4.2**: `utils::datetime::add_business_days` must add `n` business days (Monday-Friday) to `start`, skipping
  Saturday and Sunday, and return a date that is always a weekday; `n == 0` must return `start` unchanged. Holidays are
  not considered.

### 4.2 Unresolved-person logging

- **SPEC-4.3**: `utils::unresolved_person::log_unresolved_person_names` must be a no-op when `ids` is empty, so every
  call site can call it unconditionally after filtering to unresolved rows.
- **SPEC-4.4**: When `ids` is non-empty it must log exactly one `INFO`-level line per call, naming the caller-supplied
  `surface`, the total `ids.len()`, and at most the first 10 ids (`MAX_IDS_LOGGED`); it must never log a resolved name
  or email address, because an id alone identifies nothing but a name or email does.

### 4.3 Login-location geolocation and decision

- **SPEC-4.5**: `utils::geoip::GeoIpService::new` must return an error (not silently disable the feature) when the
  configured IP2Location database path is set but the file cannot be opened as an IP2Location database.
- **SPEC-4.6**: `GeoIpService::country_code` must return `None` for an address with no location record, and must treat
  the IP2Location placeholder value `"-"` and a blank string as "no country", never as a real ISO 3166-1 alpha-2 code.
- **SPEC-4.7**: `utils::login_location::login_location_decision` must return `Record` when there is no previous
  country (`None`), `Unchanged` when the previous country string equals the current one exactly, and `Alert` for any
  other previous value; it performs no lookup of its own, only a comparison of two already-resolved country codes.

### 4.4 Outbound URL SSRF guard and client IP

- **SPEC-4.8**: `utils::net::is_non_public_ip` must classify as non-public: IPv4 loopback, RFC1918 private, link-local,
  unspecified and broadcast addresses, the ranges `100.64.0.0/10`, `192.0.0.0/24` and `198.18.0.0/15`, IPv6 loopback,
  unspecified, unique-local (`fc00::/7`) and link-local addresses, and any `::ffff:a.b.c.d` IPv4-mapped address whose
  embedded IPv4 address is itself non-public. It must be the crate's only definition of this predicate.
- **SPEC-4.9**: `utils::net::guard_outbound_url` must refuse a URL whose scheme is not `http` or `https`
  (`UrlGuardError::Scheme`), a URL with no host (`UrlGuardError::NoHost`), and, when the caller passes
  `allowed_ports`, a URL whose port is outside that set (`UrlGuardError::Port`), before performing any DNS resolution.
- **SPEC-4.10**: Unless the host is named in the `PrivateTargetAllowlist`, `guard_outbound_url` must resolve the host
  and refuse the URL with `UrlGuardError::Blocked` if any resolved address is non-public per SPEC-4.8 and not covered
  by an allowlisted network; a resolution failure or a resolution to zero addresses must be reported as
  `UrlGuardError::Dns`, and a resolved address found non-public on a later redirect hop must be screened the same way.
- **SPEC-4.11**: `PrivateTargetAllowlist::parse` must treat an entry that parses as an IP address or CIDR as a network
  exemption and any other non-blank entry as an exact (case-insensitive) hostname exemption; an empty or all-blank
  input must produce an allowlist that exempts nothing (fail closed). A host named by `allows_host` must be exempted
  from resolution and screening entirely.
- **SPEC-4.12**: `utils::net::loggable_url_authority` must reduce a URL-shaped string to its authority (`host[:port]`),
  stripping any scheme, userinfo, path, query and fragment, even when the input does not parse as a URL at all, so the
  result is always safe to write to a log line.
- **SPEC-4.13**: `utils::client_ip::trusted_proxies` must parse `TRUSTED_PROXY_CIDR` as a comma-separated CIDR list,
  skipping (with a warning, not a boot failure) any entry that fails to parse, and must fall back to the built-in
  default list (`127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `::1/128`, `fc00::/7`, `fe80::/10`)
  when the variable is unset or blank.
- **SPEC-4.14**: `utils::client_ip::extract_client_ip` must return the socket peer address unchanged, ignoring
  `X-Forwarded-For` entirely, when the peer is not inside a trusted-proxy network.
- **SPEC-4.15**: When the peer is a trusted proxy, `extract_client_ip` must read every `X-Forwarded-For` header
  instance and element from right to left (treating repeated headers as one concatenated list) and return the first
  address that is not itself inside a trusted-proxy network; when every address in the chain is trusted, or the header
  is absent or unparseable, it must return the peer address, and it must never panic on malformed input.
- **SPEC-4.16**: `utils::client_ip::parse_forwarded_ip` must accept a bare IPv4 or IPv6 address, a bracketed IPv6
  literal with an optional `:port` suffix, and an IPv4 `host:port` form, and must return `None` for anything else.

### 4.5 Download headers, HTML escaping, inline images

- **SPEC-4.17**: `utils::content_disposition::content_disposition` must strip `"`, `/`, `\`, NUL and any other control
  character from the given filename, keep at most the first 255 remaining characters, trim surrounding whitespace, and
  fall back to the literal name `file` when nothing is left; a non-ASCII character must pass through unchanged. The
  result must always be returned as `attachment; filename="<name>"`.
- **SPEC-4.18**: `utils::html::html_escape` must replace `&` with `&amp;` before replacing `<`, `>` and `"`, so an
  already-escaped entity is never escaped a second time.
- **SPEC-4.19**: `utils::html::urlencoded` must percent-encode every byte outside `A-Z`, `a-z`, `0-9`, `-`, `_`, `.`
  and `~`.
- **SPEC-4.20**: `utils::inline_image::check_inline_image_mime` must accept only `image/png`, `image/jpeg`,
  `image/webp` and `image/gif` (matched case-insensitively and after cutting the value at the first `;`), returning
  the canonical lowercase MIME string on success; it must reject every other type, including `image/svg+xml`, because
  SVG is script-capable and the three public, unauthenticated image surfaces (tenant logo, KB article image, ticket
  inline image) must never serve one.

### 4.6 Recovery codes, app name, upload limits

- **SPEC-4.21**: `utils::recovery::generate_code` must produce 10 random bytes, base32-encode all 16 resulting
  characters (no truncation, preserving the full 80 bits of entropy) and format them as `XXXXXXXX-XXXXXXXX`.
  `canonicalize` must strip whitespace and hyphens and uppercase the remainder, so any of the hyphenated, unhyphenated,
  lower-case or spaced forms of a code canonicalize identically; `hash_code` and `hash_code_hex` must hash the
  canonical form with SHA-256.
- **SPEC-4.22**: `utils::app_name::app_name` must return `DEFAULT_APP_NAME` ("Mokosh") when no name has been set, and
  must otherwise return the cached name set by the most recent `set_app_name` call; `sanitize` must reject a blank (or
  whitespace-only) name, a name longer than `MAX_APP_NAME_LEN` (64) characters (counted as Unicode characters, not
  bytes), and a name containing any control character, since the value is later written into an email `Subject`
  header.
- **SPEC-4.23**: `utils::upload_limits::oversized_upload_error` must return an `AppError` that renders as HTTP 413
  (Payload Too Large) with the message `"{what} exceeds the {cap_bytes} byte cap."`. Every route that accepts an
  upload against its own size cap must build this refusal through this function rather than a hand-built error.
- **SPEC-4.24**: `utils::upload_limits::body_limit_bytes` must return the route's logical byte cap plus a fixed 64
  KiB margin (`MULTIPART_OVERHEAD_BYTES`), and every route with an upload cap must pass that value to
  `axum::extract::DefaultBodyLimit::max`, because axum's own un-raised multipart body limit is 2 MiB and would refuse
  an at-cap upload before `oversized_upload_error` ever runs.

### 4.7 Password policy, security response headers, sanitized JSON extraction

- **SPEC-4.25**: `utils::password_policy::validate` must reject a password shorter than `policy.min_length`
  (default 12) or longer than `policy.max_length` (default 128) characters, counted as Unicode characters, before
  running any other check.
- **SPEC-4.26**: `validate` must reject a password whose lowercased form, or whose lowercased form with `@` mapped to
  `a` and `$` mapped to `s`, exactly matches an entry in the embedded common-password list, independent of the length
  and score checks.
- **SPEC-4.27**: `validate` must reject a password whose `zxcvbn` score is below `policy.min_zxcvbn_score` (default
  3), scored with the caller-supplied `context_hints` so a password built from the user's own identifying strings
  scores lower.
- **SPEC-4.28**: The `security_headers` middleware must add `strict-transport-security`, `x-content-type-options`,
  `x-frame-options`, `referrer-policy`, `permissions-policy` and `content-security-policy` to every response, filling
  in only the headers the handler left unset, so a value the handler set for itself is never overwritten.
- **SPEC-4.29**: `utils::json::Json` as an extractor must deserialize from the `ParsedJsonBody` request extension
  when `sanitize_json_body` already parsed the body, and must fall back to `axum::Json`'s own parse only when that
  extension is absent, so a well-formed JSON request body is parsed by `serde_json` exactly once.

### 4.8 TOTP and recovery/portal cryptography

- **SPEC-4.30**: `utils::totp::base32_encode` must produce RFC 4648 base32 (uppercase alphabet) with no padding;
  `base32_decode` must ignore whitespace and `=` padding and accept either case.
- **SPEC-4.31**: `utils::totp::step` must compute the RFC 4226/6238 HMAC-SHA1 dynamic-truncation value for step
  number `t`, and `verify` must accept `code` only when it is exactly `TOTP_DIGITS` ASCII digits, trying every step
  from `t - window` to `t + window` inclusive with a constant-time comparison, returning the first matched step.
- **SPEC-4.32**: `utils::crypto::encrypt` must AES-256-GCM-encrypt with a random 12-byte nonce, store
  `nonce || ciphertext` and base64-encode the result; `decrypt` must reverse that exactly, rejecting an input shorter
  than the 12-byte nonce.
- **SPEC-4.33**: `utils::crypto::parse_encryption_key` must hex-decode a 64-character input to 32 bytes, must treat
  a 32-character input as raw bytes only when it is not entirely hex digits (rejecting an all-hex 32-character input
  as ambiguous), and must reject any other length.
- **SPEC-4.34**: `utils::crypto::generate_portal_slug` must produce a 16-character string drawn only from Crockford
  base32 characters with `I`, `L`, `O` and `U` excluded; `generate_portal_id` must return an integer in
  `[100_000_000, 1_000_000_000)` so it always renders as exactly 9 digits.
- **SPEC-4.35**: `utils::crypto::sha256_hex` must return the lowercase hex SHA-256 digest of its input.
  `verify_password_or_dummy` must run exactly one Argon2 verification whether `row_hash` is `Some` or `None`
  (verifying against a fixed dummy hash in the `None` case) and must return `Ok(false)` whenever `row_hash` is
  `None`, so a lookup that matched no row costs the same time as one that did.

### 4.9 Request-body text sanitization

- **SPEC-4.36**: `utils::text::is_secret_field` must match a key against `SECRET_FIELD_NAMES` case-insensitively and
  exactly (no substring match); `sanitize_json_tree` must skip sanitizing the entire subtree under a key that
  matches, while still sanitizing the key string itself.
- **SPEC-4.37**: `sanitize_json_tree` must apply `sanitize_invisible` to every string value and every object key at
  any depth (except a skipped secret subtree's values), recursing into arrays and objects, and must return `true` if
  and only if at least one byte changed.
- **SPEC-4.38**: `utils::text::sanitize_json_body` must forward the request body untouched when the path matches a
  `RAW_BODY_PATHS` prefix, when the `Content-Type` is not JSON, or when a declared `Content-Length` exceeds
  `MAX_SANITIZED_JSON_BYTES` (25 MB); on a body that parses as JSON it must store the parsed (and possibly
  sanitized) tree as a `ParsedJsonBody` request extension, replace the body with an empty one and remove
  `Content-Length`; on an empty or unparseable body it must forward the original bytes untouched.

### 4.10 Field-level validators

- **SPEC-4.39**: `utils::validation::validate_email` must accept only a string matching
  `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`.
- **SPEC-4.40**: `validate_phone` must first strip invisible characters via `sanitize_invisible`, then accept an
  empty result or one matching the E.164 pattern `^\+?[1-9]\d{1,14}$`.
- **SPEC-4.41**: `validate_slug` must delegate to `mokosh_types::validation::validate_slug` rather than defining its
  own grammar, so the server and the wire-type crate cannot diverge on what a slug is.
- **SPEC-4.42**: `validate_password_strength` must require between 8 and 128 characters and at least one lowercase
  letter, one uppercase letter, one ASCII digit and one non-alphanumeric character, listing every missing category
  in the error message.
- **SPEC-4.43**: `validate_cron` must accept only an expression `cron::Schedule::try_from` parses successfully.
- **SPEC-4.44**: `validate_scheduling_template_kind`, `validate_contract_type`, `validate_contract_status` and
  `validate_billing_cycle` must each accept only a value present in its fixed set (`SCHEDULING_TEMPLATE_KINDS`,
  `CONTRACT_TYPES`, `CONTRACT_STATUSES`, `BILLING_CYCLES` respectively), matching the corresponding database CHECK
  constraint exactly, so an out-of-set value is rejected with a 422 rather than a database error.
- **SPEC-4.45**: `validate_money_amount` must reject a magnitude of 10,000,000,000 or more; `validate_payment_amount`
  must additionally reject a value that is not strictly positive or has more than 2 decimal places;
  `validate_budget_amount` and `validate_budget_hours` must reject a negative value, more than 2 decimal places, or
  a magnitude at or above their respective `DECIMAL` column limits; `validate_sla_target_hours` must reject a value
  that is not strictly positive, has more than 2 decimal places, or reaches 100,000,000; `validate_tax_rate` must
  reject a negative value, a value over 100, or more than 4 decimal places.
- **SPEC-4.46**: `validate_ip_address` must accept an empty string or one `std::net::IpAddr` parses; validate a MAC
  address must accept an empty string or one matching a colon- or hyphen-separated six-octet hex pattern.
- **SPEC-4.47**: `slugify` must lowercase the input, replace every non-alphanumeric character with `-`, and collapse
  consecutive separators; `truncate` must cut at a UTF-8 character boundary at or before `max_len - 3` bytes and
  append `"..."` rather than panicking on a byte offset inside a multi-byte character.
- **SPEC-4.48**: `cross_field_error` must build a `ValidationError` carrying a `field` param equal to its `field`
  argument, so a schema-level validation error can be re-keyed onto a named form field instead of a generic bucket.

### 4.11 Pagination parameters and response metadata

- **SPEC-4.49**: `utils::pagination::PaginationParams` must reject a deserialized `per_page` greater than
  `MAX_PER_PAGE` (100) at parse time with a deserialization error; `PaginationParams::per_page` must clamp the
  stored value to the inclusive range `[1, MAX_PER_PAGE]`.
- **SPEC-4.50**: `PaginationParams::direction` (used by `order_by`, `order_by_mapped` and
  `reject_unsupported_sort`) must map `"asc"` (case-insensitive) to `"ASC"`, an empty string or `"desc"` to
  `"DESC"`, and reject any other value with a 422 naming the `sort_dir` field.
- **SPEC-4.51**: `order_by` and `order_by_mapped` must reject a `sort` value absent from their allow-list with a
  422 naming the `sort` field, the requested value and the accepted values, and must leave a `None` sort unchanged
  by substituting the default field or SQL expression; `order_by_mapped` must resolve an allow-listed public key to
  its mapped SQL expression rather than ever splicing the client-supplied string into the generated SQL;
  `reject_unsupported_sort` must reject any non-`None` `sort` with a 422 stating the endpoint does not support
  sorting.
- **SPEC-4.52**: `PaginatedResponse::new` must compute `total_pages` as `ceil(total / per_page)` with `per_page`
  floored to 1 to avoid division by zero, and must set `has_next` to `page < total_pages` and `has_prev` to
  `page > 1`.

### 4.12 The AppError envelope

- **SPEC-4.53**: `utils::error::AppError::status_code` and `error_code` must each return one fixed value per
  variant, including `AccountDeleted` as 410 `ACCOUNT_DELETED`, `TokenExpired` as 401 `TOKEN_EXPIRED`, and
  `RateLimited` as 429 `RATE_LIMITED`, so a client can switch on `code` without string-matching `message`.
- **SPEC-4.54**: `ErrorResponse::from(AppError)` must render the `Database` variant's wire message as the fixed
  string `"Database operation failed"` regardless of the wrapped cause, must render every other variant's wire
  message as its `Display` string, and must populate `errors` only for the `Validation` and `QueryError` variants.
- **SPEC-4.55**: `AppError`'s `IntoResponse` must render every `RateLimited` value, however constructed, through
  `rate_limited_response` (a `Retry-After` header and `Cache-Control: no-store`), defaulting the wait to
  `DEFAULT_RATE_LIMIT_RETRY_AFTER_SECONDS` (60) when `retry_after_seconds` is `None`.
- **SPEC-4.56**: `normalize_error_envelope` must leave a response unchanged unless its status is a client error
  (4xx) and its `Content-Type` is not `application/json`; such a response must be replaced with
  `envelope_for_rejection`'s canonical `{error:{code,message}}` body, discarding the original.
- **SPEC-4.57**: `From<sqlx::Error> for AppError` must map `RowNotFound` to `NotFound`, a Postgres `23505` unique
  violation to `Conflict`, and any other database error to `Database` with the raw cause logged at `error` level
  (a `23505` logs at `debug`).
- **SPEC-4.58**: `From<validator::ValidationErrors> for AppError` must flatten nested `Struct` and `List` errors
  into dotted (and `[index]`-suffixed) field paths, must re-key a schema-level error onto the field
  `validation::cross_field_error` recorded via `cross_field_target`, and must build each message from the field
  error's explicit `message` when present or otherwise synthesize one from its constraint code and bound
  parameters (`humanize_field_error`).

### 4.13 Deployment mode and provider selection

- **SPEC-4.59**: the deployment-mode reader used for mail dispatch must fall back to self-hosted and log a warning
  on an unrecognized `MOKOSH_DEPLOYMENT_MODE` value, never fail the read.
- **SPEC-4.60**: the deployment-mode reader used for provider selection must instead return an error naming the
  accepted values on an unrecognized `MOKOSH_DEPLOYMENT_MODE` value.
- **SPEC-4.61**: both readers must recognize the mode value case-insensitively and with surrounding whitespace
  trimmed, and must treat an empty value the same as an absent one (self-hosted).
- **SPEC-4.62**: resolving a deployment's provider table must select an operator's explicit per-capability choice
  over the hosting profile's default for that capability only, and must record for each capability whether its
  choice came from the profile or from an explicit override.
- **SPEC-4.63**: the self-hosted hosting profile's default provider table must name no provider that requires
  reaching an external service.

### 4.14 Outbound mail

- **SPEC-4.64**: a `Mailer` implementation that does not override `send_with_attachments` must send the text alone
  and log a warning when given one or more attachments, never silently drop them without logging.
- **SPEC-4.65**: sending to a recipient address in the reserved `.invalid` top-level domain must fail locally with
  a client error rather than being handed to a transport.
- **SPEC-4.66**: `SmtpTls::parse` must map `implicit`/`tls`/`smtps` to implicit TLS, `starttls` or an empty value to
  STARTTLS, and `none`/`plain`/`off` to no TLS, rejecting any other value; `SmtpMailer::verify` must report success
  only when the relay's `NOOP` returns true, and must report a distinct error for an unreachable host versus a
  reachable host that refuses the `NOOP`.
- **SPEC-4.67**: `MailerConfig::build` must select `LogMailer` when `SMTP_HOST` is unset or empty and `SmtpMailer`
  otherwise, and `MailerConfig::from_env` must reject a configuration that sets `SMTP_USERNAME` without a
  non-empty `SMTP_PASSWORD`.
- **SPEC-4.68**: resolving the mail provider must honor an explicit `MAIL_PROVIDER` value over everything else,
  must infer `smtp` as an explicit choice when `MAIL_PROVIDER` is unset but `SMTP_HOST` is set, and must otherwise
  fall back to the hosting profile's default provider.
- **SPEC-4.69**: building the `smtp` provider with no `SMTP_HOST` configured must fail with a named configuration
  error rather than falling back to another provider, and building the `log` provider while `SMTP_HOST` is set
  must still succeed but log a warning that the relay configuration is ignored.
- **SPEC-4.70**: `SharedMailer::swap` must replace the active mailer such that every subsequent send through the
  shared handle uses the new mailer, without any consumer needing to re-fetch a reference.

### 4.15 PDF document rendering

- **SPEC-4.71**: resolving a template's theme must fall back to the module's default accent color when the
  tenant's accent is absent or does not parse as `#rrggbb`, logging a warning only in the unparseable case; the
  band's text color must be chosen between a near-black and white ink by the accent's WCAG relative luminance so
  the band's own title stays legible against it.
- **SPEC-4.72**: parsing an accent color must accept only a leading `#` followed by exactly six ASCII hex digits,
  rejecting every other string.
- **SPEC-4.73**: rendering a document must embed, per font weight, only the glyphs that document's text actually
  draws, selected by a deterministic (sorted) glyph id list, falling back to embedding the whole face without
  failing the render when subsetting itself fails.
- **SPEC-4.74**: folding text into the embedded face's character set must replace a C0/C1 control character and
  any character the face has no glyph for with a single placeholder character, and must collect the distinct
  missing characters so the caller can report them once per document rather than once per occurrence.
- **SPEC-4.75**: rendering the same `Document` and the same `generated_on` date must produce byte-identical PDF
  output on every call, with no part of the output read from the system clock.
- **SPEC-4.76**: the saved PDF's trailer file identifier must be rewritten from a digest of the file with the
  original identifier bytes blanked first, replacing both identifier slots with the same value of the same byte
  length as what it replaces, and must leave the file untouched if the expected identifier markers are not found.
- **SPEC-4.77**: placing a logo must scale it to fit inside its configured box while preserving its aspect ratio,
  and a logo image that fails to decode must not fail the render, instead being omitted with a logged warning.
- **SPEC-4.78**: distributing a table's column widths must never narrow a column below the configured minimum,
  and a column whose content already fits within the narrow-column threshold must keep its full width before any
  wider column gives up space; a cell that still does not fit its column must be truncated with a trailing
  ellipsis rather than overflowing.

### 4.16 Shared wire-type validators and helpers

- **SPEC-4.79**: a slug must match `^[a-z0-9]+(-[a-z0-9]+)*$`: lowercase letters and digits only, with a single
  hyphen between groups and no leading, trailing or doubled hyphen.
- **SPEC-4.80**: a stored rate or hours value must fit `NUMERIC(10,2)` and may be zero; a per-mile rate must fit
  `NUMERIC(8,4)`; a mileage distance must fit `NUMERIC(8,2)` and must be strictly positive, rejecting zero where
  the other three accept it.
- **SPEC-4.81**: sanitizing a string must remove every Unicode format character and U+00AD, fold any non-ASCII
  whitespace character to a plain space, and trim the result, while a zero-width joiner or non-joiner in the
  interior of the string must be preserved and only removed when it is leading or trailing.
- **SPEC-4.82**: resolving a person's local date or "today" must bucket the instant by their configured IANA time
  zone, falling back to UTC when the zone string is empty or does not parse.
- **SPEC-4.83**: a PATCH field deserialized through the double-option convention must read an absent key as
  "leave alone", an explicit JSON `null` as "clear the field", and a present value as "set the field", regardless
  of which module's copy of the deserializer is applied to that field.
- **SPEC-4.84**: a form field name must match the same grouping grammar as a slug but with underscores in place of
  hyphens: lowercase letters and digits only, starting with a letter, with no trailing or doubled underscore.
- **SPEC-4.85**: a submitted TOTP code must contain only ASCII digits and must not be empty, independently of the
  6-8 character length check applied to it.
- **SPEC-4.86**: a user's theme base mode must be one of `light`, `dark` or `system`, rejecting every other value
  before it can reach the database CHECK constraint on that column.

### 4.17 Ticket notes and SLA status

- **SPEC-4.87**: a ticket note is editable only when the caller's role permits it, the note was not created by a
  contact, and, for a `Public` note, the note has not already been emailed; an `Internal` or `Resolution` note
  stays editable regardless of send state, and a `TimeEntry` note is never editable through this path.
- **SPEC-4.88**: the SLA at-risk lead is 20 percent of the window between a ticket's creation and its due date,
  clamped between a 5-minute floor and a 24-hour ceiling, with a non-positive window falling back to the floor;
  a ticket's SLA status must read `NotApplicable` once it is closed, resolved, or its status is flagged closed,
  `Breached` once `now` passes the due date, `Warning` once `now` enters the at-risk lead before the due date, and
  `OnTrack` otherwise.
- **SPEC-4.89**: a saved ticket view name must fail validation when it is empty or contains only whitespace, not
  merely when its untrimmed length is zero.

### 4.18 Contact and company request validation

- **SPEC-4.90**: a request field holding a NUL byte, singly or in any element of a string list, must be rejected
  before it reaches the database.
- **SPEC-4.91**: a required company name must fail validation when it is whitespace-only or contains a control
  character; the same rule applies to an optional company name field except that an empty string there is
  accepted and means "clear the stored name".
- **SPEC-4.92**: a contact request must reject supplying both a `company_id` and a non-empty freeform
  `company_name` at once, and the same exclusion applies between a non-empty `companies` list and a non-empty
  freeform `company_name`.
- **SPEC-4.93**: a child list of phones, or of company links, must reject more than one entry flagged primary; a
  list with none flagged primary is accepted.
- **SPEC-4.94**: a `companies` list must reject an entry that names the same `company_id` as another entry in
  the same list.
- **SPEC-4.95**: creating a contact must fail when its email is absent or blank; updating a contact must not
  apply that requirement, since an absent email there means leave the existing value alone.
- **SPEC-4.96**: a website value must be empty or use an `http`/`https` scheme with a non-empty host, rejecting
  every other scheme; normalizing a website for storage must add an `https://` prefix and lowercase only the
  authority when the input has no scheme and is shaped like a bare host, and must otherwise pass the input
  through unchanged so a value already carrying a scheme still reaches validation as typed.
- **SPEC-4.97**: normalizing a phone number for storage must first remove invisible characters, then strip only
  common formatting characters (spaces, tabs, a no-break space, hyphens, parentheses, dots) and nothing else;
  validating the normalized result against E.164 must accept an empty value, otherwise require an optional
  leading `+` followed by 2 to 15 digits whose first digit is 1-9.
- **SPEC-4.98**: a time zone field must be empty or parse as a valid IANA time zone name.
- **SPEC-4.99**: a country field must be empty or be one of the 249 ISO 3166-1 alpha-2 codes, case-insensitively.
- **SPEC-4.100**: a postal code field must be empty or be 2 to 12 characters of ASCII letters, digits, spaces or
  hyphens.
- **SPEC-4.101**: the free-text contact field named in a field-values suggestion query must map only to one of a
  fixed, closed set of column names, so that name is safe to interpolate into the query rather than being bound.

### 4.19 Invoice status edit-freeze rule

- **SPEC-4.102**: an invoice whose status is `sent`, `paid`, `partially_paid`, `void` or `written_off` must be
  treated as frozen, disallowing header or line edits; only `draft` and `pending` remain editable, and correcting
  a frozen invoice's totals must go through a credit note rather than an in-place edit.

## 5. Identity and tenancy

Normative requirements for `src/modules/auth/`, `src/modules/members/`, `src/modules/invitations/`,
`src/modules/contact_portal/`, `src/modules/portal_roles/`, `src/modules/tenants/`, `src/modules/platform/`,
`src/modules/teams/`, `src/modules/audit/`, `src/modules/credential_move.rs` and `src/modules/ip_enrich/`. Each
requirement below is cited at its implementing or enforcing site with a `// SPEC-5.<n>` comment. Requirement numbers are
assigned in file-reading order within each sub-section and are not reused. This section is split across sibling slices
of PMS-1596: SPEC-5.1 to SPEC-5.99 cover auth session core (service.rs, routes.rs, mod.rs, models.rs, tenant.rs,
caller_context.rs, bootstrap.rs); later slices add contiguous ranges for auth security controls, identity-provider
integration and grants, tenants and platform, the contact portal plane, and members/invitations/teams/audit/ip_enrich.

Legacy pre-split content: the database-wide table inventory that used to live here was superseded by section 9 "Data
model and migrations", which carries the authoritative SPEC-9.n requirements for every migration and schema shape.

### 5.1 Module wiring and typed tenant scope

- **SPEC-5.1**: `src/modules/auth/mod.rs` must not mount `/google` or `/google/callback` routes under `/api/v1/auth` and
  must not re-export a `login_with_google` or any `google_oauth_flow` helper; the retirement is deliberate and the
  `user_oauth_identities` table is retained for historical rows only.
- **SPEC-5.2**: `src/modules/auth/models.rs` must be a re-export shim for `mokosh_types::auth::*`; it must introduce no
  behavior or type of its own, so `super::models::*` paths in the module keep resolving.
- **SPEC-5.3**: `TenantId` (in `src/modules/auth/tenant.rs`) must be constructible inside the crate only through
  `TenantId::new`, and `TenantId::new` must have exactly one in-crate caller: `TenantScoped::tenant` on
  `CurrentUser`; a bare `Uuid` passed where a `TenantId` is expected must fail to compile.
- **SPEC-5.4**: `TenantId::from_trusted(uuid)` must be the sole public escape hatch, named verbosely so it is greppable
  at review, and must not be called with unvalidated request input; its legitimate uses are validated super-admin
  cross-tenant parameters, tests and bootstrap paths with no request context.
- **SPEC-5.5**: `TenantId` must bind to SQL identically to `Uuid` (via `#[sqlx(transparent)]`) and must implement
  `Display`, `Deref<Target=Uuid>` and `From<TenantId> for Uuid` so helpers such as `Database::begin_with_tenant` accept
  either shape.

### 5.2 First-run platform-admin bootstrap

- **SPEC-5.6**: `maybe_bootstrap_admin` (in `src/modules/auth/bootstrap.rs`) must run only when both `ADMIN_EMAIL` and
  `ADMIN_PASSWORD` environment variables are set AND non-empty after trim; any absence or blank must return `Ok(())`
  without writing to the database.
- **SPEC-5.7**: The bootstrap must write a `platform_admins` row, not a `users` row, on the migrator pool, with
  `status='active'`, `email_verified_at=NOW()`, derived first and last name from `derive_name(email)`, and an
  Argon2-hashed password; it must run `INSERT ... ON CONFLICT (id) DO NOTHING`.
- **SPEC-5.8**: The bootstrap must short-circuit idempotently when `SELECT COUNT(*) FROM platform_admins > 0`,
  logging at `info` with the message "ADMIN_EMAIL/ADMIN_PASSWORD set but a platform admin already exists" and
  returning without any write.
- **SPEC-5.9**: On a successful insert the bootstrap must log at `warn` level with the explicit text "DEV ONLY; do not
  use in production" and the sign-in location `/platform/login`, including the `admin_id` and `email` tracing fields.
- **SPEC-5.10**: `derive_name(email)` must extract the local-part, split on `.`, `_`, `-` or `+`, drop empties and
  title-case each piece, returning `("Admin", "User")` for an empty local-part, `(segment, "Admin")` for a single
  segment, and `(first, rest.join(" "))` for a multi-segment local-part.

### 5.3 Dual-plane caller context

- **SPEC-5.11**: `CallerContext` (in `src/modules/auth/caller_context.rs`) must carry exactly two variants, `Staff(AuthState)`
  and `Contact(ContactSession)`; the extractor `RequireCallerContext` must resolve the staff plane first and only fall
  back to the contact plane when no authenticated staff state is on the request.
- **SPEC-5.12**: When an `AuthState` is present with `deleted == true` (MAPPS-348 tombstone-after-verify),
  `RequireCallerContext` must return `AppError::AccountDeleted` (410 Gone) without touching the contact plane.
- **SPEC-5.13**: When neither plane is authenticated, `RequireCallerContext` must return `AppError::Unauthorized` (401).
- **SPEC-5.14**: `CallerContext::tenant()` must return the caller's `TenantId`; for a staff caller whose `AuthState`
  has no `tenant_id` the fallback must be `Uuid::nil` wrapped via `TenantId::from_trusted` so downstream queries fail
  closed (a nil tenant matches no real row), not fail open.
- **SPEC-5.15**: `CallerContext::today(db)` must compute the caller's "today" in their timezone, using
  `AuthState.user.timezone` (falling back to `"UTC"` when `user` is `None`) for a staff caller, or a cached
  `ContactSession` timezone populated from a tenant-scoped SELECT on `contacts.timezone` for a contact caller; the
  contact-side timezone lookup must run on an RLS-aware transaction opened with `begin_with_tenant` and must collapse
  a NULL or missing row to `"UTC"`.
- **SPEC-5.16**: `CallerContext::require_staff()` must return `Err(AppError::Forbidden("This endpoint is restricted
  to staff users."))` for a contact caller and `Ok(())` for a staff caller; the error text is observable and must not
  change.
- **SPEC-5.17**: `CallerContext::require_capability(cap, db)` must be an unconditional `Ok(())` for a staff caller
  (the staff plane does not consult `portal_roles`) and for a contact caller must load the DISTINCT union of
  `portal_roles.capabilities` across every active `contact_role_assignments` row for
  `(contact_id, tenant_id)`, cache the result via `ContactSession.role_cache: OnceCell` for the request's lifetime,
  and return `Err(AppError::Forbidden(capability_refusal_message(cap)))` when the capability is not present.
- **SPEC-5.18**: The capability loader `load_contact_capabilities` must run on the migrator pool (RLS-exempt) and
  carry a belt-and-braces `WHERE tenant_id = $1` on the join of `contact_role_assignments` to `portal_roles`.
- **SPEC-5.19**: `CallerContext::require_capability` must NOT consult the JWT `caps` claim; role revokes through
  `PUT /api/v1/contacts/{id}/portal-roles` must take effect on the next request, not after the 15-minute access-token
  TTL.
- **SPEC-5.20**: `capability_refusal_message(cap)` must look `cap` up in `capability_labels::descriptors()`,
  lowercase the first character of the label and format the string `"Missing required capability. You don't have
  permission to {phrase}."`; the message must not include a `:` separator or the raw capability key, so error
  strings do not enumerate capabilities.
- **SPEC-5.21**: `has_capability(cap, db)` must mirror `require_capability` but return a `bool`, returning `true` for
  every staff caller.
- **SPEC-5.22**: The module must publish process-global `AtomicUsize` counters `CAPABILITY_LOADS` and
  `TIMEZONE_LOADS`; each counter must increment once per actual database load (not once per `require_capability` or
  `today` call), so a test can assert that the per-request cache held.

### 5.4 Router construction and rate limiter wiring

- **SPEC-5.23**: `AuthRouterState` (in `src/modules/auth/routes.rs`) must carry three rate limiters:
  `login_limiter` (20/min per IP and 5/min per email), `forgot_password_limiter` (10/min per IP and 3/min per email),
  and `reauth_limiter` (10/min per IP and 5/min per user, failures only); all three limiters must live for the
  router's lifetime so quotas survive individual requests.
- **SPEC-5.24**: `POST /api/v1/auth/me/password` (`change_password`) and `POST /api/v1/auth/me/mfa/disable`
  (`disable_mfa`) must share one `reauth_limiter` instance; a failed current-password check on either endpoint must
  count against the other's budget so credential grinding by alternation is blocked.
- **SPEC-5.25**: The complete authenticated route set mounted on `/api/v1/auth` must be: `GET /me`, `PUT /me`,
  `GET /memberships`, `POST /me/complete-onboarding`, `PUT /me/password`, `GET /me/sessions`,
  `DELETE /me/sessions/{session_id}`, `POST /me/mfa/setup`, `POST /me/mfa/enable`, `POST /me/mfa/disable`,
  `GET /me/api-keys`, `POST /me/api-keys`, `DELETE /me/api-keys/{key_id}`, `GET /directory`, `GET /users`,
  `POST /users`, `GET /users/{user_id}`, `PUT /users/{user_id}`.
- **SPEC-5.26**: The complete public route set mounted on `/api/v1/auth` must be: `POST /login`,
  `POST /select-tenant`, `POST /switch-tenant/{tenant_id}` (the handler uses `RequireAuthState` internally),
  `POST /logout`, `POST /logout-all`, `POST /refresh`, `POST /forgot-password`, `POST /reset-password`,
  `GET /set-password/context/{token}`.

### 5.5 Rate-limited login paths and anti-enumeration

- **SPEC-5.27**: `POST /login` must call `request.validate()` before consulting the login limiter; an invalid body
  must return 400 without spending limiter budget.
- **SPEC-5.28**: The login limiter must be keyed `(client_ip, request.email)`; over quota must return a
  `rate_limited_response` with 429 status, the reset's `Retry-After` and the literal body
  `"Too many login attempts, please try again later"`.
- **SPEC-5.29**: Client IP for `POST /login` must be extracted via `extract_client_ip(peer, headers,
  trusted_proxies())`, falling back to the peer address for a direct client and walking `X-Forwarded-For` right to
  left only when the peer is itself a trusted proxy.
- **SPEC-5.30**: `POST /login` must select between two authentication paths by whether the request carries a tenant
  hint: a non-empty `tenant_id` or a trimmed non-empty `tenant_slug` dispatches to `AuthService::login` (tenant-hint
  path), and absence of both dispatches to `AuthService::authenticate_identity_first` (identity-first path).
- **SPEC-5.31**: When `AuthService::login` returns an `AppError` whose `known_retry_after()` is `Some`, the handler
  must map it to `rate_limited_response(retry_after, "Too many failed verification codes, please try again later")`,
  so the persistent MFA lockout is surfaced as 429 + `Retry-After` on the same contract as the per-request limiter.
- **SPEC-5.32**: `AuthService::login` must refuse before any credential check with the same `Unauthorized` shape when
  the local provider is disabled (`providers::is_enabled(AuthProviderKind::Local)` returns false), so provider
  enumeration from error shapes is not possible.
- **SPEC-5.33**: `AuthService::login` must resolve the caller's tenant in this order: a non-nil `request.tenant_id`
  wins; otherwise a non-blank `tenant_slug` must be resolved via `resolve_tenant_slug` (which 401s on unknown);
  neither provided must return `Unauthorized` (PMS-728 AC1 removed the old default-tenant fallback at this call
  site).
- **SPEC-5.34**: After tenant resolution, `AuthService::login` must call `find_user_by_email_for_tenant`, return
  `Unauthorized` when no row matches, and return `Forbidden("Account is not active")` when the row's `status` is not
  `Active`.
- **SPEC-5.35**: When `local_password_auth_disabled()` returns `true` (`deployment_mode.is_saas() && sso_mounted`),
  the login handler must refuse with `sso_only_rejection()` carrying the exact text `"This deployment signs in with
  single sign-on. Use your organisation's sign-in page; a password set here would not sign you in."`; the check
  must run after user lookup and status check but before any password verify.
- **SPEC-5.36**: Before the password verify, `AuthService::login` must call `ensure_tenant_active(user.tenant_id)` so
  a suspended tenant 403s with `"This organization is not active"` and an inactive tenant entitlement fails the same
  way.
- **SPEC-5.37**: A failed password must emit a best-effort audit row via `audit_write` on a tenant-scoped
  transaction with `AuditAction::Login` and a JSON `after` snapshot of `{"outcome":"failed","reason":"bad_password"}`,
  then return `Unauthorized`; a lost audit commit must be logged at `error` level but must not change the response.
- **SPEC-5.38**: `AuthService::assess_login` must return `LoginAssessment { country, device_hash, suspicious }` where
  `suspicious = country_new OR device_new`; `device_new` must require a non-blank device hash, a prior device
  record for this user (`has_known_device == true`, so first devices never trigger the alert), AND
  `is_known_device == false`.

### 5.6 MFA enrollment, verification, and fan-out writes

- **SPEC-5.39**: `start_mfa_enrollment(tenant_id, user_id)` must refuse with `Conflict("MFA is already enabled")` when
  the user's row already has `mfa_enabled = true`; it must generate a fresh TOTP secret via `totp::generate_secret`,
  base32-encode it, seal via `mfa_secret::seal`, and fan the sealed value out via `write_mfa_secret(email,
  Some(sealed), None)` to both `users` and `identities`; it must NOT flip `mfa_enabled`.
- **SPEC-5.40**: The provisioning URI returned by `start_mfa_enrollment` must set its issuer to
  `app_name().replace(':', " ")` (otpauth labels break on literal colons) and its label to `"{app}:{email}"`.
- **SPEC-5.41**: `enable_mfa(tenant_id, user_id, code)` must refuse with `BadRequest("MFA enrollment has not been
  started")` when the stored `mfa_secret` is absent; it must open the sealed secret, base32-decode it (a corrupt
  decode must return `Internal`), verify the TOTP code with a +/-1 step window, and on verify must generate 10
  recovery codes, hash each with `recovery_code_hex_hash`, write `mfa_enabled = true` to both planes via
  `write_mfa_enabled`, and persist the hashes on the per-tenant `users.mfa_recovery_codes_hashes` column; it must
  return the 10 raw recovery codes exactly once.
- **SPEC-5.42**: `disable_mfa(tenant_id, user_id, password)` must refuse with `BadRequest("This account has no
  password")` when `password_hash` is absent and with `Unauthorized` when the password does not verify; the
  order of its three writes must be `write_mfa_enabled(email, false)` first, then clear
  `mfa_recovery_codes_hashes` for the per-tenant row, then `write_mfa_secret(email, None, None)` last. Any other
  order would leave the flag enabled with no secret on a partial failure, locking the user out with no re-enrol
  path.
- **SPEC-5.43**: `write_mfa_secret(email, value, previous)` must run on the migrator pool and must update both
  `users` and `identities` at `lower(email)` in one transaction, writing `mfa_secret` and `updated_at`; when
  `previous` is `Some`, the UPDATE must include `AND mfa_secret = $previous` so a concurrent write cannot be lost.
- **SPEC-5.44**: `write_mfa_enabled(email, enabled)` must update `users` first, then `identities`, in one
  transaction on the migrator pool; the `identities` UPDATE must also reset `mfa_last_totp_step = 0`.
- **SPEC-5.45**: `upgrade_legacy_mfa_secret(email, secret_b32)` must seal the plaintext via `mfa_secret::seal` and
  call `write_mfa_secret(email, Some(sealed), Some(secret_b32))`, and must run only after a verified TOTP code
  confirms the plaintext is the correct secret.
- **SPEC-5.46**: `mfa_locked_until(tenant_id, user_id)` must return the stored `mfa_locked_until` under
  `begin_with_tenant`; `register_failed_mfa(tenant_id, user_id)` must UPDATE `users` with
  `mfa_failed_attempts = mfa_failed_attempts + 1` and `mfa_locked_until = COALESCE(NOW() + make_interval(secs =>
  <mfa_lock_seconds_sql>), mfa_locked_until)`, so the new window is derived from the incremented value inside the
  same UPDATE (never from a stale read).
- **SPEC-5.47**: `record_mfa_success(tenant_id, user_id, used_step)` must run a CAS UPDATE
  `WHERE mfa_last_used_step IS NULL OR mfa_last_used_step < $used_step`, clearing `mfa_failed_attempts = 0` and
  `mfa_locked_until = NULL` on success; it must return `false` on 0 rows affected (a step replay) and the caller
  must treat that as an MFA failure.
- **SPEC-5.48**: `clear_mfa_lockout(tenant_id, user_id)` must zero `mfa_failed_attempts` and
  `mfa_locked_until` without advancing `mfa_last_used_step`, because a recovery code is not a TOTP step.
- **SPEC-5.49**: `mfa_lockout_until(failed_count, now)` must return `None` for `failed_count < 3`; for `failed_count
  >= 3` it must return `now + 30 * 2^(failed_count - 3)` seconds, capped at 3600 seconds (1 hour); the exponent
  must be clamped so an unbounded `failed_count` cannot overflow.
- **SPEC-5.50**: `mfa_lock_seconds_sql(count_expr)` must produce the SQL twin of SPEC-5.49: `CASE WHEN (<expr>) >= 3
  THEN LEAST(3600, 30 * 2^LEAST(20, (<expr>) - 3))::double precision END`; the `count_expr` argument must be a SQL
  fragment (column or bind), never user input. A parity test must pin the two schedules to agree.

### 5.7 Suspicious-login approval gate

- **SPEC-5.51**: `LOGIN_APPROVAL_MAX_ATTEMPTS` must be exactly `5`: the wrong-code budget before the challenge is
  destroyed and a fresh code must be requested.
- **SPEC-5.52**: `issue_login_approval` must generate a 6-digit numeric code, SHA-256 hash it, DELETE any prior
  unconsumed challenge for that user, INSERT a new `login_approvals` row with `expires_at = NOW() + 15 minutes`,
  and detached-spawn-send the challenge email; it must not be gated on `sends_local_account_email()`, because
  suppressing it would strand callers mid-login.
- **SPEC-5.53**: `verify_login_approval` must consume the freshest unconsumed, unexpired challenge: on a code match
  it must UPDATE `consumed_at = NOW()` and return `Ok`; on a code mismatch it must UPDATE `attempts = attempts + 1
  RETURNING attempts` (never a stale read), and when the returned `attempts >= 5` it must DELETE the row.
- **SPEC-5.54**: An absent, expired, or over-limit challenge in `verify_login_approval` must return
  `Unauthorized`.
- **SPEC-5.55**: The suspicious-login gate in `AuthService::login` must run AFTER password and MFA verification, so
  a flagged sign-in is first authenticated; when `login_approval_enabled` is true and the assessment is
  `suspicious`, a missing `approval_code` must cause `issue_login_approval` and return a `LoginResponse` with
  `approval_required: true` and empty tokens, while a present `approval_code` must be checked via
  `verify_login_approval`.

### 5.8 Login-location alerts

- **SPEC-5.56**: `check_login_location` must no-op when any of these holds: `geoip` is `None`, the IP is
  unparseable, the IP is non-public per `utils::net::is_non_public_ip`, or geoip resolution fails; none of these
  paths must raise a login-time error.
- **SPEC-5.57**: `login_location_decision(previous, current)` must return `Record` when there is no previous
  country, `Unchanged` when the previous and current strings are equal, and `Alert` for any other difference; the
  first geolocatable login must record silently (no email).
- **SPEC-5.58**: A `country_change` alert email must be sent on a detached `tokio::spawn`, via the direct
  `mailer` (not the notifications dispatcher, because no template is seeded for this event), with no retry; a
  slow or failing SMTP must never add latency to or fail the login.
- **SPEC-5.59**: The alert email must only be sent when both `user.login_location_alerts` is true AND
  `self.sends_local_account_email()` is true; the country must be persisted via `set_last_login_country` in the
  same code path whether or not the email is suppressed.

### 5.9 Per-request active principal gate and session lifecycle

- **SPEC-5.60**: `ensure_user_and_tenant_active(tenant_id, user_id, token_iat, session_id)` must load the user via
  `get_user_by_id` (missing or tombstoned returns `NotFound`), require `status == Active` (else
  `Forbidden("Account is not active")`), call `ensure_tenant_active(user.tenant_id)`, verify
  `session_is_live(tenant_id, session_id)` (else `Forbidden("Session has been signed out")`), and when
  `user.password_changed_at.is_some() && token_iat < that.timestamp()` return `Unauthorized` (401, not 403, so the
  SPA's refresh-and-retry kicks in on a post-password-change token).
- **SPEC-5.61**: `session_is_live(tenant_id, session_id)` must run under `begin_with_tenant` because `user_sessions`
  is RLS-covered and must return `EXISTS WHERE id=$1 AND tenant_id=$2 AND expires_at > NOW()`.
- **SPEC-5.62**: `ensure_tenant_active(tenant_id)` must LEFT JOIN `tenants` with `tenant_membership_entitlements`
  (both RLS-exempt) in a single statement on `.pool()`, and must return `Forbidden("This organization is not
  active")` for any of these three cases: `tenants` row absent, `tenants.status != 'active'`, or the entitlement
  row is `suspended` or has `expires_at < NOW()`; an `unknown` or NULL entitlement must pass. All three failure
  branches must return identical copy so billing vs operator lifecycle are not distinguishable to the caller.
- **SPEC-5.63**: `set_tenant_entitlement(tenant_id, status, expires_at, reason)` must UPSERT
  `tenant_membership_entitlements` on the migrator pool (RLS-exempt), rejecting any `status` not in
  `{"active","suspended","unknown"}`.
- **SPEC-5.64**: `create_session(tenant_id, user_id, ip, ua, remember_me)` must mint a new UUID, set
  `token_hash = sha256_hex(generate_token(32))` (defence in depth, not a credential), and set
  `expires_at = NOW() + 30 days` when `remember_me == true`, else `+7 days`.
- **SPEC-5.65**: `generate_tokens(user, session_id)` must set `iat = nbf = now`, access `exp = now + 1 hour`,
  refresh `exp = now + 7 days`, must stamp `iss = MOKOSH_JWT_ISSUER` and `aud = MOKOSH_JWT_AUDIENCE` on both
  tokens, must set `typ = "access"` and `typ = "refresh"` respectively, must thread `sid` from the session row,
  and must resolve `mid` via `MembershipRepo::find_id_by_email_and_tenant` on the migrator pool (a `None`
  resolution is tolerated so bootstrap paths keep working); encoding must be HS256.
- **SPEC-5.66**: `decode_token(token)` must set `Algorithm::HS256` explicitly (never any other algorithm), set
  `validate_exp = true`, set `validate_aud = false` (deferred strict validation per MAPPS-334), and allow a
  30-second leeway.
- **SPEC-5.67**: `refresh_token(refresh_token)` must require `claims.typ == "refresh"` (else `Unauthorized`), find a
  live session row via `get_session(claims.tid, claims.sid)` (else `Unauthorized`), load the user and reject a
  non-`Active` status with `Forbidden`, call `ensure_tenant_active`, and then mint new tokens with the SAME `sid`
  as the refresh token carried (refresh reuses, does not rotate); it must update `last_activity_at` on the
  session row.
- **SPEC-5.68**: `logout(session_id)` must DELETE a single row from `user_sessions` by primary key on the
  migrator pool (an unguessable session id makes the single-row blast radius acceptable);
  `logout_all(tenant_id, user_id)` must DELETE every `user_sessions` row for the user under
  `begin_with_tenant`.
- **SPEC-5.69**: `POST /logout` must call `AuthService::logout(claims.sid)` only when the bearer decodes; a
  missing or undecodable bearer must silently skip the DELETE but still run the audit row; both paths must
  return 200.
- **SPEC-5.70**: `POST /logout` and `POST /logout-all` must write their audit rows on their own tenant-scoped
  transactions (PMS-256), so RLS is satisfied; an audit commit failure must be logged (`error` on logout, `warn`
  on logout-all) but must not fail the response.
- **SPEC-5.71**: `POST /switch-tenant/{tenant_id}` must require `RequireAuthState` and must verify the target tenant
  is in the caller's `AuthState.memberships` (the enriched middleware pass populated it); a missing match must
  return `NotFound("No active membership in the requested tenant")`; a missing `auth_state.user` must return
  `Unauthorized`; a verified membership must mint a new scoped session via `mint_session_for_membership`.
- **SPEC-5.72**: `GET /me/sessions` must call `pagination.reject_unsupported_sort()` first, best-effort decode the
  bearer to obtain `current_session_id` (defaulting to `Uuid::nil()` when the bearer is absent or malformed), and
  return a paginated `PaginatedResponse<SessionInfo>` where `is_current = (row.id == current_session_id)`.
- **SPEC-5.73**: `DELETE /me/sessions/{session_id}` must delegate to `AuthService::delete_session(user.id,
  session_id)` on the migrator pool and must return 200 even when the row was absent (there is no 404 surface).

### 5.10 Password lifecycle

- **SPEC-5.74**: `request_password_reset(tenant_hint, email)` must refuse with `sso_only_rejection()` before any
  user lookup when the deployment is SSO-only, so a known and unknown address are not distinguishable in that
  mode; in other modes it must silently return `Ok(())` when the email is unknown (anti-enumeration).
- **SPEC-5.75**: `request_password_reset` must generate a 64-character secret, store both a dual hash set
  (`token_hash = argon2(secret)` and `lookup_hash = sha256_hex(secret)` per PMS-1244, so only one Argon2 verify
  runs per attempt), compose the token as `{user_id}.{secret}`, set `expires_at = NOW() + 24 hours`, INSERT into
  `password_reset_tokens` under `begin_with_tenant(user.tenant_id)`, and dispatch the `"auth.password_reset"`
  notification template via the notifications dispatcher; a missing dispatcher must log at `warn` without a
  direct-send fallback (body copy lives in the template, per PMS-700).
- **SPEC-5.76**: `GET /set-password/context/{token}` must return `{tenant_name, tenant_slug}` for a valid
  unredeemed unexpired token and must return `NotFound("token")` for every failure mode (invalid shape, unknown
  lookup, expired, redeemed, Argon2 mismatch) so token enumeration is not possible. The handler must not mark
  the token as used.
- **SPEC-5.77**: `reset_password(request)` must refuse with `sso_only_rejection()` first, reject a mismatch
  between `new_password` and `confirm_password` with a validation error on `confirm_password`, parse the
  user-bound token (bad shape returns `BadRequest("Invalid or expired reset token")`), SELECT
  `(tenant_id, token_hash)` on the migrator pool filtered by `(user_id, lookup_hash, used_at IS NULL, expires_at >
  NOW())`, verify via `verify_password_or_dummy` to preserve timing (the verification error must be logged at
  `warn` and treated as invalid per PMS-1577), and on success UPDATE `users` with the new hash,
  `status = 'active'`, `password_changed_at = NOW()`, mark every unused reset token for the user used, and
  DELETE every `user_sessions` row for the user, all in ONE transaction under `begin_with_tenant` (PMS-681
  fail-closed: a session-revoke failure must roll the password change back).
- **SPEC-5.78**: `reset_password` and `change_password` must both set the session-local GUC
  `app.skip_users_identity_mirror = on` inside their transaction, as a belt-and-braces guard against the
  users-to-identities mirror trigger firing on these specific writes (MAPPS-548).
- **SPEC-5.79**: `change_password(tenant_id, user_id, request, ctx)` must refuse with `Forbidden("This account
  has no local password set")` when the loaded `password_hash` is NULL (a bunyip-only user; PMS-1236), return a
  validation error on `current_password` ("current password is incorrect") when the current password does not
  verify, and otherwise UPDATE the password hash, stamp `password_changed_at = NOW()`, and DELETE every
  `user_sessions` row for the user in the same transaction.
- **SPEC-5.80**: `PUT /me/password` must run the reauth limiter check by `(client_ip, user.id)` before the
  service call, must return 429 + `"Too many failed password attempts, please try again later"` over quota, and
  on a service error must record the failure against the reauth limiter only when the error is a validation
  failure on field `current_password`; other error shapes (validation on the new password, DB failure) must not
  spend limiter budget.

### 5.11 User CRUD and directory

- **SPEC-5.81**: `GET /me` must call `AuthService::get_user_by_id(user.tenant_id, user.id)` and project the row to
  `UserResponse`. `PUT /me` must set both `request.role` and `request.status` to `None` before calling
  `AuthService::update_user` so a caller cannot change their own role or status through `/me`.
- **SPEC-5.82**: `GET /memberships` must be a pure projection over `AuthState.memberships` populated by the
  middleware's enrich pass (MAPPS-491 phase 2); the handler must not make a database query.
- **SPEC-5.83**: `POST /me/complete-onboarding` must accept an empty body (`Option<Json<_>>`) and delegate to
  `AuthService::mark_profile_completed(tenant_id, user_id, first_name, last_name)`; the service UPDATE must be
  gated on `profile_completed_at IS NULL` for the name writes (first completion wins the names, so a replay
  cannot overwrite an IdP-authoritative value) and must stamp `profile_completed_at = COALESCE(profile_completed_at,
  NOW())` so the timestamp is idempotent.
- **SPEC-5.84**: `POST /users` must require `user.role.is_admin()` (else `Forbidden("You do not have permission to
  do that")`) and `user.role.can_grant(request.role)` (else `Forbidden("Cannot create a user with a role above
  your own")`, PMS-503 ceiling); it must then validate the body and call `AuthService::create_user`.
- **SPEC-5.85**: `AuthService::create_user(tenant_id, request, ctx)` must run an EXISTS check on
  `(tenant_id, email)` before insert and return `conflict("A user with this email already exists")` on a hit; it
  must INSERT with `status = 'pending'`; it must capture the audit `after` snapshot with the password hash and
  MFA secret stripped (`to_jsonb(t) - 'password_hash' - 'mfa_secret'`) and write an `AuditAction::Create` row via
  `audit_write`; when `send_welcome_email && !sends_local_account_email()` it must suppress the welcome mail and
  log at `info` (PMS-904); when `send_welcome_email && sends_local_account_email()` it must mint a user-bound
  welcome token (7-day expiry), persist it in `password_reset_tokens`, and dispatch the `"auth.welcome"`
  notification template (no dispatcher must log at `warn` and persist the token without mailing).
- **SPEC-5.86**: `GET /users/{user_id}` must permit the request when the caller is admin OR
  `caller.id == user_id`, else return `Forbidden("You do not have permission to do that")`; the service must bind
  both `id` and `tenant_id` so a cross-tenant `user_id` returns `NotFound("User")`, not a leak.
- **SPEC-5.87**: `PUT /users/{user_id}` must require `caller.role.is_admin()` (else `Forbidden("You do not have
  permission to do that")`); when `request.role` is `Some`, `caller.role.can_grant(role)` must hold (else
  `Forbidden("Cannot create a user with a role above your own")`, PMS-625 mirror of the create-side ceiling); the
  role check must run before body validation.
- **SPEC-5.88**: `update_user(tenant_id, user_id, request, ctx)` must build the UPDATE dynamically from the
  Option fields; the settable set must be exactly `email`, `mobile`, `title`, `role`, `status`, `timezone`,
  `date_format_string`, `theme_base_mode`, `theme_accent_id`, `login_location_alerts`. `first_name`, `last_name`
  and `phone` must not be writable here (PMS-512: bunyip owns names, phone has no mokosh-side source yet). An
  empty update must no-op and return the current user; the service must capture before and after snapshots with
  secret columns stripped and write one `AuditAction::Update` audit row.
- **SPEC-5.89**: `GET /directory` must be gated on `RequireAuth` (not `RequireManager`); any authenticated user of
  the tenant may read it. `list_directory` must SELECT `id, COALESCE(NULLIF(TRIM(first_name||' '||last_name),''),
  'Unnamed User') AS name, LOWER(split_part(email,'@',1)) AS handle FROM users WHERE tenant_id = $1 AND
  status = 'active' ORDER BY name, id`; the email itself must never enter the response. The handler must call
  `log_unresolved_person_names("auth.directory", &unresolved_ids)` for any row whose name resolved to
  `"Unnamed User"`.
- **SPEC-5.90**: `GET /users` must be gated on `RequireManager` and must call `list_users(tenant_id, filter,
  pagination)`, which must exclude rows whose email matches `system+%@mokosh.local` (MAPPS-562 - hides the
  auto-provisioned system attribution user) and must support optional `q` (ILIKE across email, first_name,
  last_name), `role` and `status` filters; the response must be the broader `UserResponse` projection.

### 5.12 Personal API keys

- **SPEC-5.91**: `AuthService::create_api_key(tenant_id, user_id, request, ctx)` must mint a raw key of exactly 44
  characters (`psa_` prefix plus 40 alphanumeric), store `key_prefix` as the first 10 characters and
  `key_hash = argon2(raw)`, default `scopes` to `["*"]` when absent, INSERT into `api_keys` with
  `is_active = TRUE`, write an `AuditAction::Create` audit row with the `key_hash` column stripped from the
  snapshot, and return the raw key in the response exactly once.
- **SPEC-5.92**: `list_api_keys(tenant_id, user_id, pagination)` must run under tenant GUC and must exclude the
  `key_hash` column from its row type and response.
- **SPEC-5.93**: `revoke_api_key(tenant_id, user_id, key_id)` must DELETE the row matched by
  `(id = $key_id AND tenant_id = $tenant_id AND user_id = $user_id)` and must return `NotFound("API key")` when
  zero rows were affected.

### 5.13 Identity-first login path

- **SPEC-5.94**: `authenticate_identity_first(request, ip, ua)` must resolve the identity via
  `IdentityRepo::find_by_email` on the migrator pool, list every active membership for the identity via
  `MembershipRepo::list_views_for_identity`, and verify the password either against `identities.password_hash`
  (when the identity holds zero memberships, so no per-tenant users row exists yet) or against each matching
  `users.password_hash` under each membership's tenant; a verification error must be logged at `warn` and
  treated as a mismatch (PMS-1577), and an empty match set must return `Unauthorized`.
- **SPEC-5.95**: When `identity.mfa_enabled` is true, `authenticate_identity_first` must require an `mfa_code` or
  must return `LoginResponse { mfa_required: true, ... }` with empty tokens and no user; it must decrypt
  `identities.mfa_secret` via `mfa_secret::open` (PMS-1055 - same ciphertext as the users plane), verify the
  code with a +/-1 step window, and on verify call `IdentityRepo::record_identity_mfa_success(id, step)` whose
  CAS semantics must refuse a replay with `Unauthorized`.
- **SPEC-5.96**: `authenticate_identity_first` must branch on the resolved membership set: zero memberships must
  mint an identity token and return `needs_setup: true`; exactly one matched membership must call
  `ensure_principal_usable`, run `check_login_approval`, and delegate to `mint_session_for_user`; more than one
  matched membership must mint an identity token and return `needs_selection: true` with
  `memberships: Some(matched)` in the response.
- **SPEC-5.97**: `mint_identity_token(identity_id, email)` must produce a 5-minute token with `typ = "identity"`,
  `tid = Uuid::nil()`, `sid = Uuid::nil()`, `mid = None`, and a placeholder role; `decode_identity_token(token)`
  must return `Unauthorized` on any decode error or on a `typ` other than `"identity"`.
- **SPEC-5.98**: `select_tenant_for_identity(identity_token, tenant_id, ip, ua)` must decode the identity token,
  look up the membership via `MembershipRepo::find(identity_id, tenant_id)` (missing returns `NotFound("Membership
  in this tenant")`, not-active returns `NotFound("Membership is not active")`), and delegate to
  `mint_session_for_membership`.

### 5.14 Static-analysis guards in the test module

- **SPEC-5.99**: `service.rs`'s test module must carry a source-scan test
  (`local_password_auth_closes_only_when_a_working_alternative_exists`) pinning the four-cell truth table of
  `(deployment_mode, sso_mounted)`: only `(Saas, true)` may close local password auth. A second source-scan test
  (`attempt_counters_are_incremented_in_sql`) must fail if the pre-PMS-693 shapes `"SET mfa_failed_attempts = $"`,
  `"SET portal_failed_login_count = $"`, or `"SET attempts = $"` re-enter `service.rs`, and must fail if the
  historical `register_failed_mfa` / `register_failed_login` signatures reappear. A third test
  (`routes_do_not_reach_global_login_helpers`) must assert that `routes.rs` does not call the migrator-pool
  cross-tenant helpers `find_user_placement`, `find_bunyip_principal` or `find_bunyip_principal_in_tenant`; and a
  fourth (`mirror_direction::no_writer_takes_the_identity_row_before_the_users_row`, PMS-1120) must source-scan
  the whole `src/` tree for `UPDATE identities` statements that touch mirrored columns and either require them to
  be inside `write_mfa_enabled` or `write_mfa_secret`, or require a preceding `UPDATE users` in the same
  function.

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

## 10. Build, CI and deployment

This section covers `.forgejo/workflows/`, `oci-build/`, `Dockerfile`, `compose.dev.yml`, `justfile`, `.env.example`,
`Cargo.toml`, `rust-toolchain.toml`, `.cargo/`, `.config/`, `.devcontainer/`, `renovate.json`, `.gitignore`,
`.gitmodules`, `.noseyparker-ignore.txt`, `scripts/*.nu`, and the non-test configuration and helpers under `e2e/`.
Requirements are numbered `SPEC-10.<n>` and cited at their implementing or enforcing site with a 1-2 line comment.

### 10.1 Compile and lint gate (`.forgejo/workflows/check.yml`)

- **SPEC-10.1** On every `pull_request` targeting `main`, the `check` job must run on `${{ vars.RUNS_ON_OPENSUSE_BASE_HEAVY }}`; the workflow must fail if the job exceeds its 30-minute timeout.
- **SPEC-10.2** `check.yml` must not declare a `push` trigger for `main`: re-running compile and lint after a merge gates nothing, since the pull request already covered the merge commit.
- **SPEC-10.3** The checkout step must set `fetch-depth: 0` (so migration-immutability can diff against `origin/main`) and `submodules: true` (so `common/common.just` resolves and `just --list` parses).
- **SPEC-10.4** The job must also shallow-clone `psa-systems/mokosh-apps` to path `mokosh-apps` using `secrets.FORGEJO_PAT`, for the route-consumers check.
- **SPEC-10.5** `CARGO_BUILD_JOBS` must be set to `nproc/2`, capping build parallelism at half the host's cores.
- **SPEC-10.6** The Rust build cache (`Swatinem/rust-cache@v2`) must use `shared-key: check` with `cache-on-failure: true`, matching `cache-warm.yml`'s `warm-check` job's key exactly; a mismatch means a pull request restores nothing.
- **SPEC-10.7** The job must run, in order, and fail the workflow if any exits non-zero: `just check-migration-versions`, `just check-migration-immutability`, `just check-migration-versions-against-base`, then `nu scripts/check-guarded-content-migrations.nu`, `check-no-duplicate-mail-copy.nu`, `check-pool-safety.nu`, `check-create-update-validate-parity.nu`, `check-rate-limit-helper.nu`, `check-runner-labels.nu`, `check-oci-build-cache.nu`, `check-oci-publish-tags.nu`, `check-workspace-deps.nu`, `check-env-example.nu`, `check-build-target-storage.nu`, `check-doc-recipes.nu`, `check-config-doc-paths.nu`, `config-docs.nu self-test` then `config-docs.nu check`, `check-doc-links.nu`, `check-claude-md.nu --self-test` then `check-claude-md.nu`, `cargo machete` (after installing pinned cargo-machete 0.9.2), then `check-route-consumers.nu` with env `MOKOSH_APPS_DIR=mokosh-apps`.
- **SPEC-10.8** `cargo-machete` must be installed by downloading `cargo-machete-v0.9.2-x86_64-unknown-linux-musl.tar.gz` from its GitHub release, verifying it against SHA-256 `48200087f54c55aabcd4db4af1e25742b49846c02a1b1bfa134711945b35b2e9` with `sha256sum --check --strict`, and installing to `${CARGO_HOME:-$HOME/.cargo}/bin/cargo-machete`; a checksum mismatch must fail the step.
- **SPEC-10.9** The job must run, in order, and fail on non-zero exit: `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo check --workspace --all-targets`, `cargo test --workspace --lib`, `cargo test --workspace --doc`.
- **SPEC-10.10** The `secrets` job must run on `${{ vars.RUNS_ON_OPENSUSE_BASE_MEDIUM }}` with a 15-minute timeout, rename an existing `~/.gitconfig` to `~/.gitconfig-disabled` before checkout, check out with `fetch-depth: 0` and `persist-credentials: false`, then invoke the `check-secrets` composite action from `psa-systems/common` with a fixed `kingfisher_excludes` path list, a `kingfisher_skip_regex`, and `noseyparker_ignore_file: .noseyparker-ignore.txt`.

### 10.2 Migration guard on merge (`.forgejo/workflows/post-merge-guards.yml`)

- **SPEC-10.11** On every `push` to `main`, the `guards` job must run on `${{ vars.RUNS_ON_OPENSUSE_BASE_MEDIUM }}` with a 5-minute timeout, check out with `fetch-depth: 0` and `submodules: true`, then run `just check-migration-versions` and `just check-migration-immutability` against the merge result, failing the workflow if either exits non-zero.

### 10.3 Integration test gate (`.forgejo/workflows/integration.yml`)

- **SPEC-10.12** On every `pull_request` into `main` (never `push`), the workflow must run three jobs: `build` (compiles once), `test` (a matrix of 3 shards, `fail-fast: false`), and `summary` (`needs: test`, `if: always()`).
- **SPEC-10.13** The `build` job must run on `${{ vars.RUNS_ON_OPENSUSE_DEV_LATEST }}` with a 25-minute timeout and env `SQLX_OFFLINE=true`, `RUST_BACKTRACE=1`.
- **SPEC-10.14** Before building, the job must fail with exit 1 and an `::error::` annotation if free disk space on the workspace filesystem is under 25 GB.
- **SPEC-10.15** The Rust build cache must use `shared-key: integration`, matching `cache-warm.yml`'s `warm-integration` job.
- **SPEC-10.16** `cargo-nextest` must be installed by downloading `https://get.nexte.st/0.9.145/linux`, verifying SHA-256 `32aa82416099eb12fffae9cf1a279ad201fecbd3f74826c613e32e9006b29867` via `sha256sum --check --strict`, then extracting to `${CARGO_HOME:-$HOME/.cargo}/bin`.
- **SPEC-10.17** The build step must run `cargo nextest archive --archive-file nextest-archive.tar.zst`, sampling free disk space every 5 seconds to `/tmp/disk-samples-build.txt` for the duration, and must propagate the archive command's own exit status, never the sampler's.
- **SPEC-10.18** The archive must be uploaded as artifact `nextest-archive` with `retention-days: 1` and `if-no-files-found: error`.
- **SPEC-10.19** The `test` job must run a 3-way matrix (`shard: [1, 2, 3]`) on `${{ vars.RUNS_ON_OPENSUSE_DEV_LATEST }}` with `fail-fast: false` and a 20-minute per-shard timeout, each with its own `postgres:18.2-alpine3.23` service (`POSTGRES_PASSWORD=postgres`, `POSTGRES_USER=postgres`, `POSTGRES_DB=postgres`, health-checked every 5 seconds up to 20 retries).
- **SPEC-10.20** Each shard must download the `nextest-archive` artifact, install the same pinned nextest (0.9.145, SHA-256 `32aa...867`), disable Postgres durability (`fsync`, `synchronous_commit`, `full_page_writes` all off via `ALTER SYSTEM SET` plus `pg_reload_conf()`), create the DB roles the migrations grant to by running `scripts/test-db-roles.sql` with `ON_ERROR_STOP=1`, set `TMPDIR=$HOME/.nextest-tmp`, build the template database by running `cargo nextest run --archive-file nextest-archive.tar.zst --profile ci --no-capture -E 'test(/^suites::template_database::/)'`, then run `cargo nextest run --archive-file nextest-archive.tar.zst --profile ci --partition hash:${shard}/3`.
- **SPEC-10.21** The `summary` job must run on `${{ vars.RUNS_ON_OPENSUSE_DEV_LATEST }}` with a 5-minute timeout, and must fail (`exit 1` with an `::error::` annotation) unless `needs.test.result == 'success'`.

### 10.4 Unsupported/scheduled integration suite (`.forgejo/workflows/integration-unsupported.yml`)

- **SPEC-10.22** The workflow must trigger only on `schedule: "0 6 * * 1"` (Monday 06:00 UTC) and `workflow_dispatch`, never on `push` or `pull_request`.
- **SPEC-10.23** The job must run on `${{ vars.RUNS_ON_OPENSUSE_BASE_HEAVY }}` with a 30-minute timeout, with its own `postgres:18.2-alpine3.23` service identical to `integration.yml`'s.
- **SPEC-10.24** The job must install the same pinned nextest (0.9.145 / SHA-256 `32aa...867`), then start MinIO for the S3 suite by pulling image digest `docker.io/bitnamilegacy/minio@sha256:451fe6858cb770cc9d0e77ba811ce287420f781c7c1b806a386f6896471a349c`, extracting `/opt/bitnami/minio/bin/minio` via `docker create` plus `docker cp`, verifying it against SHA-256 `0586fed6e33767430230d2f5bafd0d2f4ea2b844ce17025593dd7ab07f5f33c2`, and running it with `MINIO_ROOT_USER=mokosh MINIO_ROOT_PASSWORD=mokosh-ci-password` bound to `127.0.0.1:9000`, polling `/minio/health/live` for up to 30 seconds before failing loud.
- **SPEC-10.25** The step must fail immediately with an `::error::` if `uname -m` is not `x86_64` (the MinIO pin is amd64-only).
- **SPEC-10.26** The job must export `STORAGE_S3_ENDPOINT=http://127.0.0.1:9000`, `STORAGE_S3_BUCKET=mokosh-ci`, `STORAGE_S3_REGION=us-east-1`, `STORAGE_S3_PATH_STYLE=true`, `STORAGE_S3_ACCESS_KEY_ID=mokosh`, `STORAGE_S3_SECRET_ACCESS_KEY=mokosh-ci-password` to `GITHUB_ENV`.
- **SPEC-10.27** The job must disable Postgres durability and create DB roles identically to `integration.yml`, then run `cargo nextest run --profile unsupported` with no archive step.

### 10.5 End-to-end gate (`.forgejo/workflows/e2e.yml`)

- **SPEC-10.28** The workflow must trigger on `push: main`, `pull_request: main`, and `workflow_dispatch` with a required `environment` choice input (`staging` default, or `production`).
- **SPEC-10.29** All triggers must serialize under `concurrency: group: e2e-staging, cancel-in-progress: false`, so no run is ever cancelled mid-flight.
- **SPEC-10.30** The job must run on `${{ vars.RUNS_ON_OPENSUSE_BASE_HEAVY }}` with a 20-minute timeout and `defaults.run.working-directory: e2e`.
- **SPEC-10.31** Every `E2E_*` secret-backed env var must resolve to its `_PRODUCTION` secret only when `inputs.environment == 'production'`, else its `_STAGING` secret (except `E2E_OIDC_CLIENT_ID`, shared across environments with no suffix); `E2E_ENVIRONMENT` must be `production` only on an explicit production dispatch, else `staging`.
- **SPEC-10.32** Checkout must use `fetch-depth: 0`, required by `wait-for-deploy.mjs`'s `git log` walk.
- **SPEC-10.33** The job must install dependencies with `bun install --frozen-lockfile` and browsers with `bun x playwright install chromium firefox webkit`, with no separate Node setup step (the runner image ships `nodejs24`/`bun` pre-baked).
- **SPEC-10.34** The job must report `/dev/shm` free space and `fc-list` font count as warnings only, never failing the job, because `E2E / *` is intended as a required status check on `main`.
- **SPEC-10.35** On `push` or a `workflow_dispatch` with `environment=staging`, the job must run `node24 scripts/wait-for-deploy.mjs` (SHA-polling deploy-sync gate); on `pull_request` or a production dispatch, it must instead run `node24 scripts/health-check.mjs` (reachability check only); the two conditions must be mutually exclusive by event/environment.
- **SPEC-10.36** On `push`, `pull_request`, or a staging dispatch, the job must run `node24 scripts/check-e2e-bootstrapped.mjs` to set a `skip` output; the suite step must be skipped, not failed, when `steps.seeded.outputs.skip == 'true'`.
- **SPEC-10.37** The suite must run as `bun x playwright test`, adding `--grep-invert @external` only for a production dispatch.
- **SPEC-10.38** On failure, the job must upload `e2e/playwright-report/` and `e2e/test-results/` as artifact `playwright-report` with `retention-days: 14` and `if-no-files-found: ignore`.

### 10.6 Release and image publishing (`.forgejo/workflows/build-oci-image.yml`, `create-release.yml`)

- **SPEC-10.39** `build-oci-image.yml` must trigger on `push` to `main` or tag `v*` with a path filter limited to `src/**`, `crates/**`, `migrations/**`, `.cargo/**`, `Cargo.toml`, `Cargo.lock`, `oci-build/**`, `.forgejo/workflows/build-oci-image.yml`, plus `workflow_dispatch` with `dry_run` (boolean, default `true`) and `simulate_tag` (string) inputs.
- **SPEC-10.40** The `build-and-push` job must run only `if: github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')`, on `${{ vars.RUNS_ON_OPENSUSE_BASE_MEDIUM }}`, with a 45-minute timeout and `permissions: contents: read, packages: write`.
- **SPEC-10.41** The publish mode must be derived from the trigger only, never `git describe`: `workflow_dispatch` resolves `dry-run`; a tag ref resolves `release`; `ref_name == main` resolves `latest`; any other ref resolves `branch` (rejected downstream unless allow-listed in `oci-build/get-tags.nu`). `dry_run` must be true unless the event is `workflow_dispatch` and `inputs.dry_run == "false"`; push events always publish for real.
- **SPEC-10.42** Resolved tags and mode must come from `nu oci-build/get-tags.nu --mode $mode --ref-name $ref_name --simulate-tag $simulate_tag --json`, writing `mode`, `train`, `tag`, `describe`, `dry_run` to `GITHUB_OUTPUT`.
- **SPEC-10.43** Build metadata env vars `MOKOSH_GIT_HASH` (`git rev-parse --short=12 HEAD`), `MOKOSH_GIT_DESCRIBE` (`git describe --tags --always --dirty`), `MOKOSH_BUILD_DATE` (ISO-8601 UTC), `SOURCE_DATE_EPOCH` (`git log -1 --pretty=%ct HEAD`) must be exported and passed as `--build-arg` to the Docker build.
- **SPEC-10.44** The buildx builder must use the `docker-container` driver, required for cache export.
- **SPEC-10.45** The image build must use `--cache-from type=gha` and, when not a dry run, `--cache-to type=gha,mode=max,ignore-error=true`; a dry run must use `--load` and skip `--push`/`--cache-to` entirely, so a simulated run never mutates the shared cache.
- **SPEC-10.46** `create-release.yml` must trigger on `pull_request_target: closed` into `main`, and its `create-release` job must run only `if: github.event.pull_request.merged == true && startsWith(github.event.pull_request.head.ref, 'release/v')`, calling the reusable workflow `https://dev.a8n.run/psa-systems/common/.forgejo/workflows/create-release.yml@main` with `runs-on: ${{ vars.RUNS_ON_OPENSUSE_BASE_MEDIUM }}` and `secrets: inherit`.

### 10.7 Cache warmup (`.forgejo/workflows/cache-warm.yml`)

- **SPEC-10.47** The workflow must trigger only on `push: main`, running `warm-check` (`shared-key: check`; `cargo clippy --all-targets -- -D warnings`, `cargo check --all-targets`, `cargo test --no-run --workspace --lib`, `cargo test --workspace --doc`) and `warm-integration` (`shared-key: integration`; `SQLX_OFFLINE=true`; archiving via `cargo nextest archive --archive-file /tmp/nextest-archive.tar.zst --workspace --tests`), so neither job runs any assertion-bearing test.
- **SPEC-10.48** `warm-check`'s `shared-key` must equal `check.yml`'s and `warm-integration`'s must equal `integration.yml`'s, or a pull-request run restores nothing from cache.

### 10.8 Dependency updates (`.forgejo/workflows/renovate.yml`, `renovate.json`)

- **SPEC-10.49** `renovate.yml` must trigger on `schedule: "0 2 * * 6"` (Saturday 02:00 UTC) and `workflow_dispatch`, calling the pinned reusable workflow at commit `f466fa87127d4c5d78e9b8d5a730bfc59ef45450` (aliased `main`) with `target_repository: ${{ github.repository }}` and secrets `RENOVATE_CI_TOKEN`, `PUBLIC_GITHUB_REPO_TOKEN`, `PSA_SYSTEMS_PRIVATE_PACKAGE_PAT`, `A8N_TOOLS_PRIVATE_PACKAGE_PAT`, `FORGEJO_PAT`.
- **SPEC-10.50** `renovate.json` must extend `local>psa-systems/common:renovate-default`, set `gitAuthor` to `renovate-bot <renovate-bot@users.noreply.dev.a8n.run>`, enable `osvVulnerabilityAlerts`, and restrict `enabledManagers` to exactly `cargo`, `docker-compose`, `dockerfile`, `github-actions`; Renovate must not open a PR for any other manager (for example npm in `e2e/`) from this config.
- **SPEC-10.51** The `packageRules` entry matching package names `rust`/`rustc` must group them under `groupName: "rust toolchain"`, separate from any other dependency grouping, so a toolchain bump never folds into a general dependency-update PR.

### 10.9 `justfile`: recipe wiring and precedence

- **SPEC-10.52** `justfile` must import `common/common.just` (a submodule vendored at `./common`) with `import 'common/common.just'` after `default` is defined, since `just` picks the default recipe by source order, never from an import; a clone that has not run `git submodule update --init` must fail to resolve the import before any recipe runs.
- **SPEC-10.53** `justfile` must set `allow-duplicate-recipes := true` so that the locally redefined recipes `default`, `dev-clean`, `ensure-env`, `check-docker`, `build-docker` and `test` (which also exist in `common/common.just`) are legal redefinitions, and the last definition in file order (this repo's own body, defined after the import) wins.
- **SPEC-10.54** `default` must run `just --list` and nothing else; invoking `just` with no recipe name must print the recipe list, never execute a recipe body.

### 10.10 `justfile`: check recipes

- **SPEC-10.55** `just check` must run exactly this recipe list, in order, as prerequisites: `check-compile check-clippy check-fmt check-migrations check-migration-immutability check-migration-versions-against-base check-guarded-content-migrations check-pool-safety check-validate-parity check-route-consumers check-mail-copy check-rate-limit-helper check-runner-labels check-oci-cache check-oci-publish-tags check-workspace-deps check-unused-deps check-env-example check-build-target-storage check-doc-recipes check-config-doc-paths check-config-docs check-doc-links check-claude-md`, and must not include `check-docker` or `test-integration`; any prerequisite's non-zero exit fails the whole recipe at that point.
- **SPEC-10.56** `check-compile` must run `cargo check --workspace --all-targets`.
- **SPEC-10.57** `check-clippy` must run `cargo clippy --workspace --all-targets -- -D warnings`, matching `check.yml` exactly so a lint failing CI also fails this local recipe.
- **SPEC-10.58** `check-fmt` must run `cargo fmt --all --check` and must not modify any file.
- **SPEC-10.59** `check-config-docs` must run `nu scripts/config-docs.nu self-test` then `nu scripts/config-docs.nu check`, in that order; either non-zero exit fails the recipe.
- **SPEC-10.60** `check-doc-links` must run `nu scripts/check-doc-links.nu`.
- **SPEC-10.61** `check-claude-md` must run `nu scripts/check-claude-md.nu --self-test` then `nu scripts/check-claude-md.nu`, in that order.
- **SPEC-10.62** `check-build-target-storage` must run `nu scripts/check-build-target-storage.nu`.
- **SPEC-10.63** `check-doc-recipes` must run `nu scripts/check-doc-recipes.nu`.
- **SPEC-10.64** `check-config-doc-paths` must run `nu scripts/check-config-doc-paths.nu`.
- **SPEC-10.65** `check-env-example` must run `nu scripts/check-env-example.nu`.
- **SPEC-10.66** `check-migrations` must run `check-migration-versions` and `check-migration-versions-against-base` as prerequisites (the former is `common/common.just`'s own recipe, invoking its own `scripts/check-migration-versions.nu` against `migrations_dir`).
- **SPEC-10.67** `check-migration-versions-against-base base_ref="origin/main"` must run `nu scripts/check-migration-versions-against-base.nu migrations {{base_ref}}`.
- **SPEC-10.68** `check-guarded-content-migrations` must run `nu scripts/check-guarded-content-migrations.nu`.
- **SPEC-10.69** `check-pool-safety` must run `nu scripts/check-pool-safety.nu`.
- **SPEC-10.70** `check-validate-parity` must run `nu scripts/check-create-update-validate-parity.nu`.
- **SPEC-10.71** `check-route-consumers` must run `nu scripts/check-route-consumers.nu`.
- **SPEC-10.72** `check-mail-copy` must run `nu scripts/check-no-duplicate-mail-copy.nu`.
- **SPEC-10.73** `check-rate-limit-helper` must run `nu scripts/check-rate-limit-helper.nu`.
- **SPEC-10.74** `check-runner-labels` must run `nu scripts/check-runner-labels.nu`.
- **SPEC-10.75** `check-oci-cache` must run `nu scripts/check-oci-build-cache.nu`.
- **SPEC-10.76** `check-oci-publish-tags` must run `nu scripts/check-oci-publish-tags.nu`.
- **SPEC-10.77** `check-workspace-deps` must run `nu scripts/check-workspace-deps.nu`.
- **SPEC-10.78** `check-unused-deps` must exit 1 with stderr `cargo-machete not installed: cargo install --locked cargo-machete` when `cargo-machete` is not on `PATH`, and otherwise run `cargo machete`.
- **SPEC-10.79** `check-docker` must build only the `builder` target stage (`--target builder`) of `oci-build/Dockerfile`, tagged `mokosh-server:check`, with build args `MOKOSH_GIT_HASH`, `MOKOSH_GIT_DESCRIBE`, `MOKOSH_BUILD_DATE` computed the same way as the CI build (10.43); `check-docker` must not be a prerequisite of `just check` because it needs a Docker builder and network access that no `check.yml` step requires either.

### 10.11 `justfile`: dev stack recipes

- **SPEC-10.80** `ensure-env` must be a no-op if `.env` already exists and must never overwrite it. On first run it must generate, via `openssl rand -hex 24` (pg/migrator/app passwords, Infisical Postgres password, MinIO root password), `openssl rand -hex 32` (`JWT_SECRET`, `ENCRYPTION_KEY`), `openssl rand -hex 16` (`INFISICAL_ENCRYPTION_KEY`) and `openssl rand -base64 32` (`INFISICAL_AUTH_SECRET`), substitute these into the named keys and the three rebuilt `postgres://` URL lines (`DATABASE_URL`, `MOKOSH_ADMIN_DATABASE_URL`, `MOKOSH_APP_DATABASE_URL`, `INFISICAL_DB_CONNECTION_URI`) while leaving `${MOKOSH_PG_HOST_PORT}` as literal unexpanded text in those URLs, write the result to `.env`, and print `ensure-env: created .env with freshly generated self-owned secrets`; third-party credential placeholders from `.env.example` must stay blank.
- **SPEC-10.81** `dev *args` must depend on `ensure-env`, rewrite `.env` so exactly one `USER=<value>` line exists (from `whoami`, trimmed, replacing any prior `USER=` line), print `Starting the dev stack as <user>, routed at https://<user>-mokosh-api.a8n.run`, then run `docker compose --file compose.dev.yml up {{args}}`, passing trailing args through unmodified.
- **SPEC-10.82** `dev-infisical *args` must depend on `ensure-env`, set `MOKOSH_SERVER_INFISICAL_ADDRESS=http://infisical:8080` in `.env` (replacing any prior line with that key), then run `docker compose --file compose.dev.yml --profile infisical up {{args}} infisical infisical-postgres`.
- **SPEC-10.83** `dev-s3 *args` must depend on `ensure-env` and must error with `MINIO_ROOT_USER / MINIO_ROOT_PASSWORD are missing or blank in .env; copy both keys from .env.example and give the password a value (a .env generated before PMS-958 has neither)` if either key is empty or absent; otherwise it must fill, only when currently blank, exactly `STORAGE_S3_ENDPOINT=http://minio:9000`, `STORAGE_S3_BUCKET=mokosh`, `STORAGE_S3_REGION=us-east-1`, `STORAGE_S3_PATH_STYLE=true`, `STORAGE_S3_ACCESS_KEY_ID=<MINIO_ROOT_USER>`, `STORAGE_S3_SECRET_ACCESS_KEY=<MINIO_ROOT_PASSWORD>` (never `STORAGE_BACKEND`), then run `docker compose --file compose.dev.yml --profile s3 up {{args}} minio`.
- **SPEC-10.84** `down` must depend on `ensure-env` and run `docker compose --file compose.dev.yml down --remove-orphans`, preserving named volumes.
- **SPEC-10.85** `infisical-bootstrap` must depend on `ensure-env`; if `.env.infisical` exists it must parse it as `name=value` lines (skipping comments and blank lines) and inject them as environment, then run `cargo run --quiet --bin mokosh-server -- bootstrap-infisical` with that environment.
- **SPEC-10.86** `dev-seed-portal` must depend on `ensure-env` and run, inside the `server` compose service with `--no-deps`, `DATABASE_URL="$MOKOSH_ADMIN_DATABASE_URL" cargo run --quiet --bin mokosh-bootstrap -- dev-seed-portal`, idempotently.
- **SPEC-10.87** `dev-clean` must depend on `ensure-env`, run `docker compose --file compose.dev.yml down --remove-orphans`, remove exactly the named volumes `dev-mokosh-postgres-data-${USER}`, `dev-mokosh-infisical-postgres-data-${USER}`, `dev-mokosh-server-target-${USER}`, `dev-mokosh-attachments-${USER}` if present, recursively remove the local `target` directory if it exists (printing `removed target`), remove `.env` if it exists (printing `removed .env`), and finish by printing `dev-clean: done`.
- **SPEC-10.88** `dev-clean-all` must depend on and run after `dev-clean`, then remove the Docker images `mokosh-server:check` and `mokosh-server:local` if present, run `docker buildx prune --force`, and print `dev-clean-all: done`.

### 10.12 `justfile`: test recipes

- **SPEC-10.89** `test` (overriding `common`'s `test`) must run `cargo test --workspace --lib --bins`, deliberately scoped to `--lib --bins` and never the workspace's `tests/*` integration binaries, because at least 19 of those suites depend on one-process-per-file semantics a merged `tests/suites/*.rs` module would break.
- **SPEC-10.90** `ensure-test-db-roles` must depend on `ensure-env`, run `docker compose --file compose.dev.yml up --detach --wait postgres`, then exec, inside the `postgres` service, `psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set=ON_ERROR_STOP=1` feeding it `scripts/test-db-roles.sql` from stdin, so a `psql` error fails the recipe.
- **SPEC-10.91** `test-integration` must depend on `ensure-env` and `ensure-test-db-roles`, then run, inside the `server` compose service via `docker compose run --rm` with `SQLX_OFFLINE=true`: `cargo install --locked --version 0.9.145 cargo-nextest`, then (with `DATABASE_URL` overridden to `$MOKOSH_ADMIN_DATABASE_URL`) `cargo nextest run --profile ci --no-capture -E 'test(/^suites::template_database::/)'` before `cargo nextest run --profile ci`, in that order.
- **SPEC-10.92** `test-integration-unsupported` must depend on `ensure-env` and `ensure-test-db-roles`, run `cargo install --locked --version 0.9.145 cargo-nextest` then `DATABASE_URL="$MOKOSH_ADMIN_DATABASE_URL" cargo nextest run --profile unsupported`; the pinned nextest version must match `test-integration`'s.
- **SPEC-10.93** `verify-providers *args` must exec, inside the already-running `server` compose service, `/app/target/debug/mokosh-server verify-providers {{args}}`, passing trailing args through so `--json` selects a JSON envelope and the default (`--text`) prints an operator table.
- **SPEC-10.94** `verify-demo` must depend on `ensure-env` and `ensure-test-db-roles`, and run, inside `server` with `SQLX_OFFLINE=true` and `DATABASE_URL` overridden to `$MOKOSH_ADMIN_DATABASE_URL`, `cargo test --test seed_demo --test data_transfer -- --test-threads=4`.
- **SPEC-10.95** `test-e2e *args` must, from the `e2e/` directory, run `bun install --frozen-lockfile`, then `bun x playwright install chromium firefox webkit` (all three browsers), then `bun x playwright test {{args}}` with trailing args passed through.

### 10.13 `justfile`: build, image and release recipes

- **SPEC-10.96** `ci-stalls days="3"` must run `nu scripts/check-ci-stalls.nu {{days}}` and must not be a prerequisite of `just check`, since it needs network access and `FORGEJO_TOKEN`.
- **SPEC-10.97** `ci-log *args` must run `nu scripts/ci-job-log.nu {{args}}`, passing `--workflow`, `--sha`, `--run`, `--list` through.
- **SPEC-10.98** `ci-stalls-self-test` must run `nu scripts/check-ci-stalls.nu --self-test` and must need no network token.
- **SPEC-10.99** `config-docs` must run `nu scripts/config-docs.nu generate`.
- **SPEC-10.100** `config-since version *args` must run `nu scripts/config-docs.nu since {{version}} {{args}}`.
- **SPEC-10.101** `config-release-notes version *args` must run `nu scripts/config-docs.nu release-notes {{version}} {{args}}`.
- **SPEC-10.102** `build` must run `cargo build --release --bins`.
- **SPEC-10.103** `build-docker` must build the full (non-`--target`) `oci-build/Dockerfile` image, tagged `mokosh-server:local`, with the same three build args as `check-docker` (10.79), computed identically.
- **SPEC-10.104** `migrate-run` must run `sqlx migrate run` against `$DATABASE_URL`.
- **SPEC-10.105** `migrate-create name` must run `sqlx migrate add {{name}}`.

### 10.14 `justfile`: variables

- **SPEC-10.106** `app` must be the literal `"mokosh-server"`, used by `common`'s `release_crate` default for a release's `cargo update --package` step.
- **SPEC-10.107** `compose_service` must be `"server"`, not `common`'s default `"app"` (no compose service in this repo is named `app`).
- **SPEC-10.108** `clippy_args` must be exactly `"--workspace --all-targets -- -D warnings"`, deliberately never `--all-features`, since `check.yml` compiles only the default feature set.
- **SPEC-10.109** `compile_step` must be `"check"` (not `"build"`), and `compile_args` must be `"--workspace --all-targets"`.
- **SPEC-10.110** `test_args` must be exactly `"--workspace --lib"` for the common-driven hook path; the doc-test invocation runs only in CI, never via this variable.
- **SPEC-10.111** `compose_file` must be the literal `"compose.dev.yml"`, used by every recipe invoking `docker compose --file {{compose_file}}`.

### 10.15 Dev image (`Dockerfile`)

- **SPEC-10.112** The dev image must build `FROM ghcr.io/niceguyit/rust-builder-glibc:v1.2.0-rust1.98.1-trixie` and install `pkg-config libssl-dev curl` via apt, removing `/var/lib/apt/lists/*` afterward.
- **SPEC-10.113** The dev image must create `/app /data /config`, set `WORKDIR /app`, `EXPOSE 8080`, and run `CMD ["cargo", "run", "--bin", "mokosh-server"]`, so the compose-mounted source compiles on every container start rather than running a baked binary. The real listen port comes from `$PORT`, which `compose.dev.yml` sets from `MOKOSH_PORT`; the `EXPOSE 8080` is a documentation default only.

### 10.16 Production OCI image (`oci-build/Dockerfile`)

- **SPEC-10.114** The builder stage must build `FROM ghcr.io/niceguyit/rust-builder-musl:v1.1.0-rust1.98.1-alpine`, install `musl-dev pkgconfig openssl-dev openssl-libs-static lld`, and set `RUSTFLAGS="-C link-arg=-fuse-ld=lld"`.
- **SPEC-10.115** The builder must populate a dependency-only layer by copying only `Cargo.toml`/`Cargo.lock` and each workspace crate's own `Cargo.toml`, stubbing every crate's `src/lib.rs`/`main.rs`/`build.rs` with `fn main() {}`, running `cargo build --release --bins` against the stubs, then `cargo clean --release` the five first-party packages (`mokosh-server`, `mokosh-types`, `build-metadata`, `mokosh-test-macros`, `mokosh-test`) while keeping third-party artifacts, so a change under `src/` or `crates/*/src/` cannot invalidate this layer and the stub binary is never shipped.
- **SPEC-10.116** Build args `MOKOSH_GIT_HASH`, `MOKOSH_GIT_DESCRIBE`, `MOKOSH_BUILD_DATE`, `SOURCE_DATE_EPOCH` must each default to `""` and be promoted to `ENV` of the same name below the dependency layer (not above it), so `build.rs` observes them without invalidating the dependency cache on every build; unset, `build.rs` falls back to `"unknown"` plus the package version.
- **SPEC-10.117** The real-source copy must land `migrations`, `build.rs`, `crates`, `src` (in that order) before the final `cargo build --release --bins`, because `sqlx::migrate!` reads `migrations/` at compile time and `build.rs` needs its own crate present.
- **SPEC-10.118** The runtime stage must be `FROM alpine:3.23` (pinned because `gosu` is only in Alpine 3.23's community repo), install `ca-certificates tzdata gosu shadow`, and create group+user `appuser` at fixed `uid:gid` 1001:1001 via `addgroup -g 1001 appuser && adduser -D -H -u 1001 -G appuser appuser`.
- **SPEC-10.119** The runtime stage must copy `mokosh-server`, `mokosh-bootstrap`, and `migrations` from the builder with `--chown=appuser:appuser`, and copy `src/pdf/fonts/OFL.txt` to `/app/licenses/NotoSans-OFL.txt`, a licence-obligation artifact nothing reads at runtime.
- **SPEC-10.120** The image must create `/app/attachments` and `chown -R appuser:appuser /app` before `ENV DATA_DIRS` is declared, so a freshly created named volume mounted over `/app/attachments` inherits `appuser` ownership instead of root's.
- **SPEC-10.121** The image must set `ENV APP_USER=appuser` and `ENV DATA_DIRS="/app/attachments"`, read by `gosu-entrypoint.sh`.
- **SPEC-10.122** The image must set OCI labels `org.opencontainers.image.description=Mokosh Server`, `...revision=${MOKOSH_GIT_HASH}`, `...version=${MOKOSH_GIT_DESCRIBE}`, `EXPOSE 8080`, and a `HEALTHCHECK` with `--interval=30s --timeout=3s --start-period=5s --retries=3` running `wget --no-verbose --tries=1 --spider http://localhost:8080/api/v1/health`, failing on any non-success.
- **SPEC-10.123** `ENTRYPOINT` must be `["/usr/local/bin/gosu-entrypoint.sh", "/app/mokosh-server"]`; a runtime `user:` pin that is non-root disables the remap and chown steps in the entrypoint (10.125).

### 10.17 Shared container entrypoint (`oci-build/gosu-entrypoint.sh`)

- **SPEC-10.124** On start, the script must fail if `APP_USER` is unset, printing `entrypoint: APP_USER must be set by the image`; `DATA_DIRS` may be empty but must be set. It must exit 1 with `entrypoint: no command to run...` if invoked with zero arguments.
- **SPEC-10.125** When started as non-root: the script must skip the PUID/PGID remap, root hooks and chown; if `PUID`/`PGID` are set but do not match the running uid/gid it must exit 1 naming the mismatch; for each `DATA_DIRS` entry it must exit 1 if the directory is missing or not writable by the current user, else `exec` the given command as-is.
- **SPEC-10.126** When started as root: `PUID`/`PGID`, if set, must be numeric and non-zero (rejecting non-numeric or `0` with exit 1, "refusing to run the workload as root"); if unset, the resolved uid/gid must be the owner of the first `DATA_DIRS` entry when that owner is non-root, else default to `1001:1001`.
- **SPEC-10.127** The script must remap `$APP_USER` to the resolved uid/gid via `groupmod -o -g ... && usermod -o -u ... -g ...`, log the resolution source (`PUID`/`PGID`/owner-of-dir/default) to stderr, then run every executable in `/etc/entrypoint.d/*.sh` as root (skipping if the glob matches nothing), aborting with that hook's exit code if any hook fails.
- **SPEC-10.128** For each `DATA_DIRS` entry the script must `chown` only entries whose uid or gid differs from the resolved pair, then must `exec gosu "$APP_USER" "$@"` (user form, not `uid:gid`, so supplementary groups resolve from `/etc/group`).

### 10.18 Image tagging (`oci-build/get-tags.nu`)

- **SPEC-10.129** `main` must accept only `release|latest|branch|dry-run` for `--mode`; any other value must error `[get-tags] Unknown mode: '<mode>'. Expected release|latest|branch|dry-run.`.
- **SPEC-10.130** Mode `release` must resolve `{train: "release", version: ref_name}` and error `[get-tags] release train requires a non-empty version...` if `ref_name` is empty. Mode `latest` must resolve `{train: "latest", version: ""}`. Mode `branch` must resolve `{train: "branch", version: ref_name}`. Mode `dry-run` must resolve to `release` when `--simulate-tag` is non-empty, to `branch` when `--ref-name` is non-empty and not `"main"`, else to `latest`.
- **SPEC-10.131** `BRANCH_ALLOW_LIST` must be the single source of truth for which branches may publish; a `branch`-train version not on the list must error `[get-tags] Branch '<name>' is not on the publish allow-list ...`. It is currently empty (no feature branch publishes); `scripts/check-oci-publish-tags.nu` keeps `build-oci-image.yml`'s own branch filter in sync with it.
- **SPEC-10.132** The final `tag` must be the version string for `release`, `branch-tag(version)` (every `/` replaced with `-`) for `branch`, and the literal `latest` for `latest`; `describe` (`git describe --tags --always`) is diagnostic only and never changes the train. With `--json`, the record `{mode, train, tag, describe}` must serialize via `to json --raw`.

### 10.19 Dev stack compose (`compose.dev.yml`)

- **SPEC-10.133** The compose project name must be `dev-mokosh-${USER}` and every `container_name`/volume/network name must carry the `dev-mokosh-` prefix plus `-${USER}` suffix, so two developers on one host never collide; `USER` has no default (`${USER:?USER missing - run via just dev}`).
- **SPEC-10.134** `infisical`, `infisical-postgres`, and `valkey` must start only under compose profile `infisical`; `minio` must start only under profile `s3`; no other service is profile-gated.
- **SPEC-10.135** `postgres`, `infisical-postgres`, and `mailpit` host-published ports must bind to `127.0.0.1` only, as must `minio`'s two published ports; the `server` service must publish no host port at all, reaching ingress solely through the external `network-traefik-public` Traefik network via its `labels`.
- **SPEC-10.136** `postgres`'s `PGDATA` must be pinned to `/var/lib/postgresql/data/pgdata`, a subdirectory of the named volume mount, to avoid both the Postgres-18 default-path change and the entrypoint's refusal to `initdb` into a non-empty directory.
- **SPEC-10.137** The `server` service must build from `Dockerfile` with `context: .`, depend on `postgres` with `condition: service_healthy` and on `mailpit` with `condition: service_started`, and must not declare a `depends_on` for `infisical`, since a hard dependency on a profiled-out service makes compose reject the whole project.
- **SPEC-10.138** `CARGO_BUILD_JOBS` must default to `1` inside the `server` container, serializing rustc to avoid earlyoom SIGTERM around roughly 1.5 GB free; an operator may override it in `.env`.
- **SPEC-10.139** The `server` service's volumes must mount `./src`, `./crates`, `./Cargo.toml`, `./Cargo.lock`, `./build.rs`, `./migrations`, `./tests`, `./e2e:ro`, and `./.config` individually, plus named volumes `server-target:/app/target` and `attachments:/data/attachments`; a new top-level directory this list omits is invisible inside the dev container.
- **SPEC-10.140** `STORAGE_ROOT` must default to `/data/attachments` in the `server` environment, matching the `attachments:/data/attachments` mount point.
- **SPEC-10.141** The `server`'s `extra_hosts` must pin `${USER}-bunyip-api.a8n.run` to `${BUNYIP_OP_TRAEFIK_IP:-172.30.0.11}` so the in-container OIDC discovery fetch reaches the local Traefik with a valid certificate rather than the host's public edge.
- **SPEC-10.142** Traefik routing labels for `server` must use YAML list syntax, not map syntax, since Compose does not interpolate `${USER}` inside map keys, only inside string values.
- **SPEC-10.143** `minio`'s image must be pinned by digest `docker.io/bitnamilegacy/minio@sha256:451fe6858cb770cc9d0e77ba811ce287420f781c7c1b806a386f6896471a349c`, with its data volume mounted at `/bitnami/minio/data`, not `/data`, because the Bitnami non-root image cannot `chown` a freshly created volume mounted at `/data`.

### 10.20 Devcontainer (`.devcontainer/`)

- **SPEC-10.144** `devcontainer.json` must use image `ghcr.io/niceguyit/opensuse-dev:v0.7.0-leap-16.0`, and must run `config-devcontainer.sh dev` via `sudo su --login --command` on `postCreateCommand`, `updateContentCommand`, and `postStartCommand` alike, a JetBrains-only workaround since JetBrains does not run those hooks as the configured user.
- **SPEC-10.145** `config-devcontainer.sh` must add the `dev` user to a `docker-host` group matching the host docker socket's gid (creating the group if absent) whenever that gid is non-zero and not already present in `/etc/group`, so `dev` can reach `/var/run/docker.sock`.
- **SPEC-10.146** Under JetBrains (`/.jbdevcontainer/` present), the script must move each of `chezmoi`, `nushell`, and `bun`'s config directories under `/.jbdevcontainer/config/` on first run and replace the original path with a symlink owned by `dev:dev`, so JetBrains' use of `XDG_CONFIG_HOME`/`XDG_DATA_HOME` still persists configuration across container rebuilds.
- **SPEC-10.147** When `bun` is on `PATH`, the script must globally install `prettier`, `cspell`, `corepack`, `@anthropic-ai/claude-code`, `@tailwindcss/cli`, then run `bun update --global --latest` against every global package.

### 10.21 Rust toolchain and workspace (`Cargo.toml`, `rust-toolchain.toml`, `.cargo/config.toml`)

- **SPEC-10.148** The workspace must resolve with `resolver = "2"` and contain exactly four members: the root `mokosh-server` package, `crates/mokosh-types`, `crates/build-metadata`, `crates/mokosh-test-macros`, `crates/mokosh-test`; a member outside this list, or a missing one, breaks `cargo check --workspace` with an unresolved-path error.
- **SPEC-10.149** `rust-toolchain.toml` must pin `channel = "1.98.1"` with `components = ["clippy", "rustfmt"]`; every `cargo`/`rustfmt`/`clippy` invocation in this repo, dev container and CI alike, must use exactly this patch, so formatting and lint output are identical everywhere.
- **SPEC-10.150** A bump of the `rust-builder-glibc` or `rust-builder-musl` image tags (10.112, 10.114) must be accompanied, in the same change, by the matching `channel` bump in `rust-toolchain.toml`; drift between the pin and the image's actual rustc produces the same class of silent formatting/lint divergence the pin exists to prevent.
- **SPEC-10.151** `[workspace.dependencies]` must list only crate entries that at least one member inherits via `{ workspace = true }` (enforced by `check-workspace-deps.nu`, 10.179): `serde 1.0.229` (derive), `serde_json 1.0.154`, `uuid 1.11` (v4, v7, serde), `chrono 0.4.45` (serde), `async-trait 0.1.92`, `secrecy 0.10.3` (serde), `ipnetwork 0.20`, `lettre 0.11.23` (default features off; tokio1-native-tls, builder, smtp-transport, pool).
- **SPEC-10.152** `[profile.release]` must build with `lto = true`, `codegen-units = 1`, `panic = "abort"`, `strip = true`; a release binary must abort rather than unwind on panic, and ship with symbols stripped.
- **SPEC-10.153** `[profile.dev]` must build with `debug = 0` and `codegen-units = 256` (not rustc's default `debug = 2`), to keep rustc's peak RSS under the OOM threshold of memory-constrained dev containers, leaving `overflow-checks` and `debug-assertions` at their profile defaults (on); `[profile.dev.package."*"]` must set `opt-level = 3` for every dependency crate, so only the root crate itself builds unoptimized.
- **SPEC-10.154** `.cargo/config.toml` must set `[net] git-fetch-with-cli = true`, so a `git`-dependency fetch (the `dunite-*` crates, pinned by `rev`) uses the system git CLI and its configured credential helper against the private `https://dev.a8n.run/psa-systems/dunite` repo, instead of libgit2, which can fail to authenticate against a private Forgejo remote.

### 10.22 Test runner configuration (`.config/nextest.toml`)

- **SPEC-10.155** `[profile.ci].default-filter` must read exactly `'not (test(/^suites::s3_storage::/) or test(/^suites::google_client_from_infisical::/))'`, character-for-character the negation of `[profile.unsupported]`'s filter `'(test(/^suites::s3_storage::/) or test(/^suites::google_client_from_infisical::/))'`.
- **SPEC-10.156** `cargo nextest run --profile ci` must still compile `tests/suites/s3_storage.rs` and `tests/suites/google_client_from_infisical.rs` into the one test binary on every pull request (a compile break in either fails the PR job) while never executing their cases; those suites run only via `[profile.unsupported]`, invoked weekly by `integration-unsupported.yml` (10.22-10.27) and locally by `just test-integration-unsupported` (10.92).
- **SPEC-10.157** `[profile.ci]` must run with `test-threads = 12` and `fail-fast = false`.
- **SPEC-10.158** `[profile.ci.slow-timeout]` must mark a case slow after `period = "60s"` and send it SIGTERM after `terminate-after = 3` consecutive periods (180s total), continuing the rest of the run rather than stalling the whole job.
- **SPEC-10.159** The override `[[profile.ci.overrides]]` for `filter = 'test(health_p99_does_not_regress_under_concurrent_argon2_burst)'` must set `threads-required = "num-test-threads"` and `retries = 2`; no other test in `[profile.ci]` is retried.
- **SPEC-10.160** `[profile.unsupported]` must `inherit = "ci"` (same slow-timeout, fail-fast, thread budget) and override only `default-filter`, plus set `failure-output = "immediate-final"` so a failing case in the weekly run prints its output without a local re-run.

### 10.23 Repo hygiene (`.gitignore`, `.gitmodules`)

- **SPEC-10.161** `.gitmodules` must declare submodule `common` at path `common`, url `https://dev.a8n.run/psa-systems/common.git`; a fresh clone must run `git submodule update --init` before `pre-commit`, `pre-push`, `install-hooks` or `create-release` resolve, since those recipes are implemented in the `common` submodule.
- **SPEC-10.162** `.gitignore` must exclude every `.env*` file except `.env.example` (`.env*` then `!.env.example`), so a generated `.env` with live secrets is never committed while the template always is.
- **SPEC-10.163** `.gitignore` must exclude `/secrets/` (generated OIDC signing keys), `/gen/` (build output), `/assets/styles.css` (Tailwind-generated CSS), `data/` (the dev Postgres bind-mount directory), `.claude/` (agent scratch/config), `For AI/` (local-only AI scratch context), and `/attachments/` (the default local-storage root for a bare `cargo run` or a test).

### 10.24 Secret-scan exemptions (`.noseyparker-ignore.txt`)

- **SPEC-10.164** `.noseyparker-ignore.txt` must list only individual file/directory paths, never a widened parent glob, each with a comment stating why its matches are not real secrets, and the comments must not quote the matched fixture strings themselves, since quoting would re-trigger the scanner on the ignore file itself.
- **SPEC-10.165** A real secret committed under any exempted path must be treated as the same incident class the scanner exists to catch on a clean path; the exemption is scoped to known-safe fixtures, never a blanket allowance for the listed paths.

### 10.25 Environment variable registry file (`.env.example`)

- **SPEC-10.166** `.env.example` must hold, as a comment-only key with an empty or documented-default value, every environment variable the config registry reads, checked by `check-env-example.nu` (10.189-10.193). Operators must not copy it to `.env` by hand; `ensure-env` (10.80) generates `.env` from it once per clone and fills every self-owned secret with a strong random value via `openssl rand`, so no placeholder password ever reaches a running `.env`.
- **SPEC-10.167** `MOKOSH_PG_HOST_PORT` (default `5433`) must be the single place the host-published Postgres port is written; `DATABASE_URL`, `MOKOSH_ADMIN_DATABASE_URL`, and `MOKOSH_APP_DATABASE_URL`'s host forms must interpolate it rather than repeat the literal, so resolving a port collision between two checkouts on one host cannot leave a host-side tool migrating a different checkout's database.
- **SPEC-10.168** `MOKOSH_APP_DATABASE_URL` must be the `mokosh_app` role's URL; if unset the server falls back to `DATABASE_URL` (`mokosh_migrator`, bypassing row-level security), which makes every `tenant_isolation` policy inert for request-serving connections. Outside `development`/`dev`/`test` `ENVIRONMENT` values, the server must refuse to boot if `MOKOSH_APP_DATABASE_URL` is unset.

### 10.26 CI gate scripts: migrations, pool safety, validate parity, mail copy

- **SPEC-10.169** `check-guarded-content-migrations.nu` must check only `migrations/*.sql` files whose numeric filename prefix is strictly greater than `209`; for such a file whose `UPDATE` matches `AND\s+<col>\s*(=|LIKE)\s*'` for any of `subject`, `body_text`, `body_html`, `name`, `description`, the file must also contain the literal `GET DIAGNOSTICS`, or the script exits 1 naming the file and the missing assertion; migrations numbered 209 or below are exempt unconditionally.
- **SPEC-10.170** `check-migration-versions-against-base.nu migrations_dir base_ref` must union migration filenames from `base_ref` (default `origin/main`, via `git ls-tree -r --name-only`) and the current `migrations_dir` on disk, group them by leading numeric prefix, and exit 1 listing every prefix shared by two or more distinct filenames as a post-merge collision.
- **SPEC-10.171** `check-pool-safety.nu` must scan every `src/**/*.rs` file except `src/db/pool.rs` for a non-comment line containing `.pool()` that is not a `migrator_pool` call; for each, it must look back up to 8 lines, and if none contain the substring `SAFETY (PMS-285`, record it as a violation and exit 1.
- **SPEC-10.172** `check-create-update-validate-parity.nu` must pair every `Create*Request`/`Upsert*Request` struct with its `Update*Request`/`Patch*Request` counterpart by stripped struct name; for each same-named field present on both sides, the normalized `#[validate(...)]` attribute text must be identical unless the pair-and-field is listed in the script's `ALLOWED` constant (currently empty); any mismatch, or a stale `ALLOWED` entry whose two sides no longer differ, exits 1.
- **SPEC-10.173** `check-no-duplicate-mail-copy.nu` must fail if any of the 8 seeded template phrases in its `PHRASES` constant (for example `"Welcome to {{app_name}}"`) appears as a substring anywhere under `src/`, and must separately fail unless the literal sentence `"has added an update to ticket"` appears verbatim in both `migrations/148_restore_ticket_note_org_identity.sql` and `src/modules/tickets/service.rs`.

### 10.27 CI gate scripts: rate limiting, route consumers, runner labels

- **SPEC-10.174** `check-rate-limit-helper.nu` must scan every `src/**/*.rs` file and fail if, outside `src/utils/error.rs`, a non-comment line contains `TOO_MANY_REQUESTS` or `AppError::RateLimited`, and must fail (even inside `src/utils/error.rs`) on any line containing the literal `let _ = retry_after`.
- **SPEC-10.175** `check-route-consumers.nu` must scan `src/modules/*/*.rs` for `.route("<path>", ...)` literals (with any `#[cfg(test)]` module stripped first); a route is exempt if every static path segment appears, delimiter-bounded, in `$MOKOSH_APPS_DIR/src/**/*.rs` (default `../mokosh-apps`), or if its own file carries a `//`-comment containing both `parity record` and a `YYYY-MM-DD` date and a separate comment naming that exact route literal; under CI (`$CI` set) a missing client checkout is a hard failure, else the check is skipped.
- **SPEC-10.176** For every job in every `.forgejo/workflows/*.yml` file, `check-runner-labels.nu` must fail a step that installs a toolchain package (`gcc`, `binutils`, `glibc-devel`, `libopenssl-devel`, `build-essential`) via a package manager at run time instead of requesting the dev image; must fail a job that runs `cargo ` natively without `RUNS_ON_OPENSUSE_BASE_HEAVY` in its `runs-on:`; and must fail any `runs-on:` line with no immediately preceding comment justifying its label.

### 10.28 CI gate scripts: OCI cache and publish-tag parity, workspace dependencies

- **SPEC-10.177** `check-oci-build-cache.nu` must select every `.forgejo/workflows/*.yml` file containing `docker buildx build`; after stripping `#`-comments, each must contain `--driver docker-container`, `crazy-max/ghaction-github-runtime@v3`, `cache_from = "type=gha"`, `cache_to = "type=gha,mode=max,ignore-error=true"`, `--cache-from`, `--cache-to`, and must contain none of `type=inline`, `type=registry`, `:buildcache`; any violation exits 1.
- **SPEC-10.178** `check-oci-publish-tags.nu` must verify `build-oci-image.yml`'s `on.push.branches` equals `["main"]` plus `oci-build/get-tags.nu`'s `BRANCH_ALLOW_LIST`, the `build-and-push` job's `if:` guard starts with `github.ref == 'refs/heads/main' || startsWith(github.ref, 'refs/tags/v')`, `check.yml`'s `on.pull_request.branches` includes `main` and its `on.push.branches` includes every allow-listed branch, and that `get-tags`'s own mode resolution and `branch-tag` (slash-to-hyphen) behave as specified in 10.129-10.132; a branch not on the allow-list must raise, never resolve a tag.
- **SPEC-10.179** `check-workspace-deps.nu` must fail when a `[workspace.dependencies]` entry has no workspace member that inherits it via `workspace = true`, and must fail when a member declares a dependency already in `[workspace.dependencies]` without `workspace = true` (its own pin shadowing the shared one); an unresolvable `workspace.members` manifest path exits 1 immediately.

### 10.29 CI gate scripts: documentation and configuration consistency

- **SPEC-10.180** `check-doc-links.nu` must resolve every Markdown link, image, reference-definition, and HTML `href`/`src` target in every `git ls-files "*.md"` file (skipping anchors, protocol-relative and scheme URLs, fenced code, and HTML comments), root-relative for a leading `/` and else relative to the containing file; any target that does not resolve on disk exits 1 naming `<file>:<line>`.
- **SPEC-10.181** `check-doc-recipes.nu` must check a fixed set of docs (`README.md`, `docs/README.md`, `docs/quickstart.md`, `docs/architecture.md`, `docs/binaries.md`, `docs/configuration.md`, `docs/recipes.md`, `docs/invariants/ci-release.md`, `docs/invariants/config-providers.md`) for every `just <recipe>` invocation and fail if the named recipe is absent from the union of `justfile`'s non-`[private]` recipes and `just --summary`'s resolved (imported) recipes; a missing submodule import failure must direct the operator to `git submodule update --init`.
- **SPEC-10.182** `check-config-doc-paths.nu` must scan `.env.example`, `compose.dev.yml`, and `justfile` for bare `docs/...`-shaped path references and exit 1 listing any that do not resolve on disk.
- **SPEC-10.183** `check-claude-md.nu` must exit 1 when `CLAUDE.md` exceeds `20000` UTF-8 bytes, when any non-fenced line exceeds `400` characters, or when a `](docs/...)` link's target or `#anchor` does not resolve; it must name `CLAUDE.md:<line>` for any violation.
- **SPEC-10.184** `check-build-target-storage.nu` must resolve cargo's target directory in cargo's own precedence (`CARGO_TARGET_DIR`, then `CARGO_BUILD_TARGET_DIR`, then `.cargo/config.toml`'s `build.target-dir`, then `<repo>/target`), determine its filesystem type via `stat --file-system --format=%T`, and exit 1 when that type is `tmpfs` or `ramfs` unless `MOKOSH_ALLOW_TMPFS_TARGET` is `1`/`true`/`yes`.
- **SPEC-10.185** `config-docs.nu check` must fail when the registry/`variables.toml` catalog has a duplicate variable name, a malformed `since`/`required_since`/`deprecated.release`/`removed.release` value, or a `required_since` without `required: true` at a release not after `since`; when any discovered env-var read in `src/**/*.rs` or `crates/**/*.rs` is absent from the registry, `variables.toml`, and the `NOT_SERVER_CONFIG` exemption list; when `docs/configuration.md`'s `## All variables` table disagrees with the catalog on `Required`/`Added in`, is malformed, or a variable has zero or more than one row; or when the generated `Recently added` block (between its fixed marker comments) is missing, out of order, or disagrees with the computed changelog for the covered release window.
- **SPEC-10.186** `config-docs.nu generate` must rewrite only the text between the `Recently added` marker lines and the `## All variables` table rows, and running it twice in a row must be idempotent (byte-identical the second time).
- **SPEC-10.187** `config-docs.nu since <version>` must print one row per catalog change released strictly after `<version>` (labelled `WON'T START`, `FEATURE OFF: <feature>`, or blank), sorted by release then breaking-level then required-first then name, or print exactly `No configuration changes after <version>.` when there are none.
- **SPEC-10.188** A registry entry whose `required` flag becomes true in the same release it was added (other than the `v0.1.0` baseline) must have a matching `[[change]]` record naming an `issue` (`^[A-Z]+-\d+$`) and a non-empty `action`, or the catalog build fails; a `[[change]]` with `breaking: "feature-off"` must set a non-empty `feature`, or the catalog build fails.

### 10.30 CI gate scripts: environment-variable parity

- **SPEC-10.189** `check-env-example.nu` must union env-var names read by code (`declare_keys!` entries in `src/config/registry.rs`, plus every `env::var`/`env::var_os`/`require_env`/`required_env`/`parse_tenant_arg_env` call site and const-aliased name across `src/**/*.rs` and `crates/**/*.rs`) into one `CODE` set.
- **SPEC-10.190** Every `CODE` name must have a key in `.env.example` (including a commented-out `# NAME=` line) unless listed in `CODE_NOT_IN_TEMPLATE`, and must appear in `compose.dev.yml`'s `services.server.environment` map unless listed in `CODE_NOT_IN_COMPOSE`; a missing entry exits 1 naming it.
- **SPEC-10.191** Every `.env.example` key must be read by code or interpolated (`${NAME`) in `compose.dev.yml` unless listed in `TEMPLATE_UNREAD`; an unread key exits 1 naming it dead.
- **SPEC-10.192** A stale `CODE_NOT_IN_TEMPLATE`, `CODE_NOT_IN_COMPOSE`, or `TEMPLATE_UNREAD` entry, one whose excused asymmetry no longer holds, must itself exit 1 naming the entry to delete.

### 10.31 Operational and diagnostic scripts

- **SPEC-10.193** `audit-portal-no-credential.nu` must error `DATABASE_URL is required (point it at the target deployment).` when `DATABASE_URL` is unset, otherwise query `contacts` for rows with `is_portal_user = TRUE AND portal_password_hash IS NULL`, print a per-row and per-tenant summary, and print a `WARNING:` line when any row's age exceeds 7 days. This script is a manual survey tool with no `just` wrapper and no CI invocation.
- **SPEC-10.194** `check-ci-stalls.nu days="3"` must read each workflow job's `timeout-minutes` from `.forgejo/workflows/*.yml` (never a value hardcoded in the script), exit 1 if `FORGEJO_TOKEN` is unset, fetch Forgejo actions runs from the last `days` days and compare each run's wall-clock time against its workflow's bound, and exit 1 naming every run that outlived its bound; a workflow with no `timeout-minutes` on any job is excluded from judgement, never counted as passing.
- **SPEC-10.195** `ci-job-log.nu` must resolve a target run from `--run <id>`, else the 50 most recent runs filtered by `--workflow`/`--sha`/failure status (newest match wins), then fetch and print that run's first failed job's log (or the first job overall if none failed) by calling the Forgejo actions API with a token read from `~/.local/share/forgejo-cli/keys.json`; `--list` must print the candidate run table without fetching a log.

### 10.32 E2E: environment resolution and auth state

- **SPEC-10.196** `e2e/lib/env.ts` must load `e2e/.env` via dotenv with `override: false` (a real environment variable always wins), and `required(name)` must throw `Missing required env var ${name}...` when the variable is unset or blank after trimming.
- **SPEC-10.197** `E2E_BASE_URL` must be required with no hardcoded fallback; `apiBaseURL` must resolve to `E2E_API_BASE_URL` if set, else `api.` prepended to the base URL's hostname, else the base URL itself when that hostname already starts with `api.` or fails to parse; `opBaseURL` must resolve to `E2E_OP_BASE_URL` if set, else fall back to `apiBaseURL`.
- **SPEC-10.198** `E2E_EMAIL`, `E2E_PASSWORD`, `E2E_TENANT_ID`, `E2E_OIDC_CLIENT_ID`, `E2E_OIDC_REDIRECT_URI`, `E2E_TOTP_SECRET` must each be required; `E2E_FOREIGN_COMPANY_ID` must be optional; `E2E_ENVIRONMENT` must default to `staging` when unset; `preflightRequiredEnv()` must collect every missing required variable into one thrown error rather than failing on the first.
- **SPEC-10.199** The bearer token must be read from `e2e/.auth/token.txt`, OP session cookies from `e2e/.auth/op-state.json`, and the foreign-company canary id from `e2e/.auth/foreign-company.txt`; each reader must throw when its file is absent or its content is empty/malformed, and the last-used TOTP step must persist to `e2e/.auth/totp-last-step` so a cross-process run never resubmits a code for a step bunyip already saw.

### 10.33 E2E: Playwright configuration

- **SPEC-10.200** The suite must run with `fullyParallel: false` and `workers: 1` (serial), since tests share one tenant and bearer token; `forbidOnly` must be true, and `retries` must be 1, only when `process.env.CI` is set (else `false`/`0`).
- **SPEC-10.201** The global test timeout must be 60000ms and `expect.timeout` 15000ms; `globalTeardown` must run `./global.teardown.ts` after every run regardless of outcome; reporters must be `list` plus an `html` reporter that never auto-opens.
- **SPEC-10.202** On failure, `trace`, `screenshot`, and `video` must each be retained/captured only on failure (`retain-on-failure` / `only-on-failure`).
- **SPEC-10.203** The `preflight` project must have no dependencies and run first; `setup` must run in Firefox, depend on `preflight`, and resolve `env.baseURL`; `chromium`/`firefox`/`webkit` projects must each run `(auth|form-validation).spec.ts`, depend on `preflight`, and use `env.baseURL` (`chromium` additionally passing `--disable-dev-shm-usage`); `ui-selectors` must run only in Firefox, depending on `setup`; `api` must depend on `setup` and use `env.apiBaseURL`, never `env.baseURL`; `guard` must depend on `preflight` only.

### 10.34 E2E: login helper and request fixtures

- **SPEC-10.204** `loginViaSpa` must retry at most 4 times total, only on a rate-limit rejection (parsed backoff, capped at 60000ms), a `no-form` outcome (backoff 3000ms), or an `unclear` outcome, and must fail fast with no retry on a definite credential rejection.
- **SPEC-10.205** When post-credential navigation lands on `/login/(2fa|mfa)`, a TOTP step must be filled: the code must be generated only when at least 5 seconds remain in the current 30-second step, must wait for a step later than the last one this run used, and must retry with a fresh code at most twice before falling back to a manual submit click; on `/oauth2/consent`, the helper must click the allow/authorize/approve control to persist the grant.
- **SPEC-10.206** `expectAuthenticated`/`expectAnonymous` must assert `GET <tickets>?per_page=1` returns 200 when authenticated and 401 or 403 when not; `expectAtLoginScreen` must poll the page URL for up to 30000ms until it matches `/^\/login(\/|$)/`.
- **SPEC-10.207** The default `test` fixture must attach `Authorization: Bearer <token>` (from the token file) to every request context; the `oidcTest` fixture must replay the OP cookie storage state against `opBaseURL` and must never attach a bearer header.

### 10.35 E2E: test data tagging, factories and teardown

- **SPEC-10.208** Every created record's run suffix must have the shape `e2e-<epochMs>-<runId>-<n>`, where `runId` resolves from `GITEA_RUN_ID`, else `GITHUB_RUN_ID`, else `E2E_RUN_ID`, else the process start timestamp, sanitized and truncated to 24 characters; `isStale(name)` must consider a record stale only once its embedded epoch is more than 24 hours old.
- **SPEC-10.209** `createCompany`/`createContact` must assert a 200 response with a truthy `id`; `enableModule` must `PUT` `{is_enabled: true}` to the module's settings route and assert success, so a 403 (missing admin privilege) surfaces as a test failure rather than being swallowed.
- **SPEC-10.210** `global.teardown.ts` must throw when the bearer token file is absent (rather than silently skipping cleanup), page every list endpoint at the server's max page size (treating a 404 as an empty, disabled module), sweep a fixed, ordered list of 23 resource kinds (children before the parents that refuse deletion while referenced, companies last) deleting any record this run owns or that is more than 24 hours stale, and throw one aggregated error naming every collected failure after the full sweep completes.

### 10.36 E2E: deploy-readiness scripts, package and TypeScript configuration

- **SPEC-10.211** `check-e2e-bootstrapped.mjs` must probe the OP's `/e2e-bootstrapped` endpoint with a 15000ms timeout and set the `skip=true` output only when the JSON body is exactly `{bootstrapped: false}`; any non-2xx, network error, or parse failure must fall through to running the suite.
- **SPEC-10.212** `health-check.mjs` must `GET <apiBaseURL>/api/v1/health` once with a 30000ms timeout, exiting 0 on an ok response and 1 otherwise.
- **SPEC-10.213** `wait-for-deploy.mjs` must resolve the expected SHA by walking `git log` back to the most recent commit touching one of the fixed build-trigger paths (`src`, `crates`, `migrations`, `.cargo`, `Cargo.toml`, `Cargo.lock`, `oci-build`, `.forgejo/workflows/build-oci-image.yml`, kept in lock-step with `build-oci-image.yml`'s own path filter, 10.39), self-healing with `git fetch --unshallow` then `git fetch --refetch` if the walk finds nothing, then poll `GET <apiBaseURL>/api/v1/version` every 15000ms for up to 600000ms until `body.git_hash` prefix-matches; on total resolution failure it must warn and exit 0 rather than fail the job.
- **SPEC-10.214** The suite must run under `bun` per the committed `bun.lock`, never `npm ci`; TypeScript compilation must target `ES2022`/`ESNext` modules with `strict: true` and `noEmit: true`; `node_modules/`, `.auth/`, `playwright-report/`, `blob-report/`, `test-results/`, `playwright/.cache/`, and `.env` must never be committed under `e2e/`.
- **SPEC-10.215** `e2e/lib/api.ts`'s `MAX_PER_PAGE` constant must equal `src/utils/pagination.rs`'s `PaginationParams::MAX_PER_PAGE` (100); a Rust unit test under `pms1427_e2e_page_size` must fail the build if any `per_page` literal under `e2e/` exceeds that constant, so the two values cannot drift apart silently.
- **SPEC-10.216** The `preflight` Playwright project (`e2e/tests/preflight.setup.ts`) must call `preflightRequiredEnv()` and run before every other project, so a missing required env var is reported once, naming every gap, rather than failing the first project that happens to read it.
- **SPEC-10.217** The `setup` Playwright project (`e2e/tests/global.setup.ts`) must drive a real browser login against the SPA, capture the bearer token from the OIDC token-endpoint response as its primary signal and from the first `Authorization: Bearer`-carrying request as a backstop, and persist the token, the OP session cookie state, and the foreign-company id to the fixed `e2e/.auth/` files read by `e2e/lib/auth-state.ts` (10.199); it must prefer the response-body capture because it survives an SPA that never fires an authenticated request.

### 10.37 Deployment and operations

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

## 12. Interfaces

### 12.1 HTTP API

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

### 12.2 Command line

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
