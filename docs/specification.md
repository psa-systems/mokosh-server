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
(section 5.2).

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

## 3. Functional requirements

Each statement is observable through the interfaces in section 4.

### 3.1 Identity, sessions and tenancy

- Staff log in with email and password at `POST /api/v1/auth/login`. A user belonging to several tenants selects one
  (`select-tenant`) or switches (`switch-tenant`). Memberships are listed at `GET /api/v1/auth/memberships`.
- Server-issued access tokens are HS256 JWTs with issuer and audience `mokosh-server`, valid 1 hour; refresh tokens
  are valid 7 days. Refresh, logout, logout-all and per-session revocation are supported.
- When the identity-provider verifier is configured (`OIDC_ISSUER` and `OIDC_AUDIENCE`), bearer tokens of type `at+jwt`
  are verified against the provider's JWKS first; a verified identity is mirrored into the local `users` table on first
  sight. Provider roles never map to `super_admin`. First-sight identities without an invitation are rejected unless
  `ALLOW_UNINVITED_BUNYIP_SIGNUP` is true and the provider has verified the email.
- A session the identity provider ended (back-channel logout) is refused even if the token has not expired. A deleted
  provider account tombstones the local user (soft delete, sessions and API keys removed).
- A deactivated user or a non-active tenant is refused on the next request, not at token expiry.
- TOTP multi-factor authentication can be enrolled, enabled and disabled. Recovery codes are accepted in place of a code.
  After 3 failed codes the account is locked for 30 seconds, doubling per further failure up to 1 hour.
- With `LOGIN_APPROVAL_ENABLED`, a login from a new country (needs the IP2Location database) or a new device (a
  client-supplied `device_id`) is withheld after password and MFA succeed until the single-use emailed code is sent back
  with the login request (5 wrong attempts destroy the challenge). With the flag off, a new-country login only triggers
  an alert.
- Password reset by emailed token (`forgot-password`, `reset-password`); a user-invite "set password" context lookup.
- Users can create personal API keys (prefix `psa_`, stored hashed, listed by prefix, revocable). The authentication
  middleware does not read the `api_keys` table: a key is not accepted as a request credential.
- Roles: `super_admin`, `admin`, `manager`, `technician`, `dispatcher`, `sales`, `finance`. Platform administrators are
  a separate plane (`platform_admins`, `POST /api/v1/platform/login`).
- Tenants have status `active`, `suspended` or `cancelled`. Platform admins create, list, suspend and activate tenants.
  A signed-in user can create an additional organization or, with an identity token, self-serve their first one.
  `MOKOSH_MAX_TENANTS` caps tenant creation (409 at the cap), re-read on each create.
- Teams with leader or member roles; per-tenant module switches (`/tenants/{id}/modules/{module}`, `/settings/modules`).
- Grant invitations let an organization owner invite an existing identity into the organization; invitees accept or
  decline by token or from their own list. When the directory client is configured, invitees are looked up at the
  identity provider.

### 3.2 Service desk

- Tickets carry number, title, description, status, priority, queue, optional type, category and subcategory, source
  (`portal`, `email`, `phone`, `api`, `chat`, `rmm`, `internal`), company, contact, site, assignee, team, parent ticket,
  contract, SLA due times, scheduling window, estimated and actual hours, billable flag, billing status
  (`not_billed`, `ready_to_bill`, `billed`, `prepaid`), asset, procedure article, tags and custom fields.
- Statuses, priorities, queues, types, categories and per-user saved views are tenant-configurable.
- Agents assign, reopen, add notes (types `internal`, `public`, `resolution`, `time_entry`) and attach files to tickets and notes; inline images are
  supported.
- Workflow rules fire inside the ticket transaction on `ticket.created`, `ticket.status_changed` and
  `ticket.priority_changed`. Actions include assign, set priority, set status, add tag and add internal note; cascading
  transitions are bounded by a per-tenant depth cap (default 3). Runs are listed per ticket.
- Rows in `ticket_automation_rules` are evaluated by the ticket service (`AutomationEngine`), including a `webhook` action
  that passes the outbound URL guard (section 7.3). No HTTP route or other code in `src` inserts such rows.
- Ticket templates; approval requests on tickets, time entries, change requests and quotes with a pending-approvals
  inbox and decision endpoint.
- Email-to-ticket intake: a mail gateway posts parsed messages to `POST /api/v1/email-intake` with a tenant intake
  bearer token. Messages are deduplicated by Message-Id, threaded by references, matched to a contact by sender, and
  create `email`-source tickets. Tokens are managed by admins.
- SLA: policies with targets, business hours with time zones, holiday calendars, per-ticket evaluation, status
  `on_track`, `warning`, `breached` or `not_applicable`, at-risk and breach notifications.
- RMM alerts posted to `POST /api/v1/rmm/alerts` (HMAC-signed with the connection secret) create tickets according to
  alert rules.

### 3.3 Time, projects, calendar

- Time entries with work types, billable flag, billing status and approval status (`draft`, `pending`, `approved`,
  `rejected`); rounding rules; start/stop timers; workday clock-in/out with breaks and editable segments; weekly
  timesheets submitted, withdrawn, approved or rejected per user and week start; mileage entries.
- Projects with phases, tasks, task statuses, task dependencies and project types; project summary.
- Appointments with RFC 5545 recurrence expanded in memory over the requested range, user availability windows, time
  off with approval, on-call schedules and "who is on call now", scheduling templates, and an aggregated dispatch board.

### 3.4 Commercial

- Contracts (statuses `draft`, `active`, `expired`, `cancelled`, `renewed`) with items, hour balances and rate cards.
- Invoices (statuses `draft`, `pending`, `sent`, `paid`, `partially_paid`, `void`, `written_off`) created manually or
  from time entries; write-off, void, amend, PDF, delivery options, payment readiness, payments list; products, tax rates
  with lookup, payment terms; credit notes (`issued`, `void`) with PDF; customer statements with PDF; manual payment
  recording and deletion.
- Online payment through Stripe or PayPal using each tenant's own gateway credentials (stored through the tenant secret
  provider). Inbound provider webhooks are verified per tenant before any parsing and reconciled idempotently; webhook
  deliveries are recorded and listed.
- Quotes (statuses `draft`, `submitted`, `approved`, `rejected`, `sent`, `accepted`, `declined`, `expired`, `converted`,
  `cancelled`) with lines, send, PDF, accept, decline and conversion; opportunities with stages `lead`, `qualified`,
  `proposal`, `negotiation`, `won`, `lost`.
- Expenses (`draft`, `submitted`, `approved`, `reimbursed`, `rejected`), vendors, expense categories, bills (`draft`,
  `approved`, `paid`, `void`) with bill payments.
- Delegated accounting: when the feature switches `delegated_invoice_issuer` and `delegated_bills` are on and a tenant
  has connected Xero or QuickBooks with the matching capability, invoices and bills are raised in that system.
  Mappings of companies, products, vendors, expense accounts and people to provider records are managed under
  `/invoice-issuer-mappings`. Xero and QuickBooks webhooks are verified by HMAC-SHA256.
- Invoices and quotes can be delivered by email through the configured mailer; per-user sends of request links and
  invoice emails are limited to 20 per hour.

### 3.5 Clients, assets, knowledge

- Companies (with industries, status, portal slug), contacts, sites, contact phones and company links; a website probe;
  deletion preview; contact notes.
- Portal access for contacts: grant, resend, revoke; portal roles with capabilities; access requests that staff resolve.
- Contact import from Google, Microsoft, iCloud (CardDAV) and `.vcf` upload: connect, preview, queued runs, a review
  queue for ambiguous matches, per-field locks, unlink and remove-imported-data. Import is one-way (read-only scopes).
- Assets with types and typed custom fields, relationships, impact view, configuration items, an encrypted credential
  vault whose reveal is audited, per-asset audit log, search with facets and bulk create (behind feature switches
  `assets_search_v2` and `assets_catalog`), asset models and templates. A per-company documentation view composes assets,
  credential references (never secret values) and knowledge-base articles.
- Knowledge base: categories, articles with drafts, versions and restore, publish states (`draft`, `published`,
  `archived`), attachments, comments with mentions and resolve, helpful votes, template rendering with a values map,
  ticket-driving article ranking and measured duration.
- Forms: definitions with ordered fields (types `text`, `textarea`, `email`, `date`, `select`, `boolean`) and the rule
  `required_if`; drafts, submissions, and tokenised request links that let a client submit a form without an account.
  Unknown field types or rules written by a newer version are read tolerantly but rejected on write.

### 3.6 Platform services

- Notifications: channels, templates, per-user preferences, rules, an in-app inbox, preview and dispatch endpoints.
- Search across tickets, contacts, companies, assets and projects (`GET /api/v1/search?q=`), tenant-scoped.
- Reports: dashboard, tickets, time, billing, request types, projects, clients, a custom report builder over a
  whitelisted catalog, CSV export, saved reports and dashboards with cron schedules.
- Client service status: monitored systems and observations posted by an HMAC-signed endpoint (source `tactical_rmm`),
  current-status lookup, backup success rate and uptime reports; observations older than 13 months are deleted.
- Audit log of entity changes with admin list and CSV export, and per-entity history.
- Tenant data export as a versioned JSON document (all tables with `tenant_id` minus secrets, identity and audit tables)
  and import; an admin action to load demo data. Demo data is seeded automatically on first visit in the `production`
  environment only, unless `MOKOSH_DEMO_SEED` is truthy.
- Branding: tenant logo, favicon and background; company-scoped logo, favicon and background (also manageable by a
  portal contact for their own company); public GET of these assets.
- Deployment-wide settings for the operator: SMTP relay settings with test send and verify, product name, the Google
  contacts OAuth client, feature switches, provider status report, IP enrichment lookup.
- Version information and an opt-in update check against `MOKOSH_UPDATE_CHECK_URL` (reports `disabled` and makes no
  outbound request when unset).

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

## 7. Security

### 7.1 Authentication and authorization

- Three credential planes with distinct JWT `typ` claims so a token cannot be replayed across planes: staff (`access`,
  `refresh`, `identity`, plus the identity provider's `at+jwt`), contact portal (`contact`, access 15 minutes, refresh
  30 days, refresh cookie `HttpOnly; Secure; SameSite=Lax; Path=/api/v1/contact/auth`), and platform admin (`platform`).
- Only access tokens are accepted as bearers; a refresh token used as a bearer is refused.
- Role checks are extractors (section 4.1). Roles are `super_admin`, `admin`, `manager`, `technician`, `dispatcher`,
  `sales`, `finance`; `RequireAdmin` admits `super_admin` and `admin`, `RequireManager` adds `manager`,
  `RequireFinance` adds `finance`.
- Passwords are hashed with Argon2id. Contact-portal passwords must be 12 to 128 characters, have a zxcvbn score of at
  least 3 and not be in a built-in common-password list.
- Password-reset, portal setup, login-approval, intake and API-key secrets are stored as hashes (portal setup and
  reset tokens also keep a SHA-256 lookup value so one row is verified rather than every candidate).
- MFA secrets are stored encrypted with `ENCRYPTION_KEY`.
- Cross-tenant access is prevented by row level security (section 5.2) in addition to service-layer scoping. Contact
  portal requests re-check tenant and contact access on every request, not only at token issue.

### 7.2 Secret handling

- Tenant integration credentials (payment gateways, RMM connections, notification channels) are
  AES-256-GCM ciphertext or live in the selected tenant secret provider; they are never returned to clients.
- Tenant data export excludes `payment_gateway_configs`, `credential_vault`, `api_keys`, `rmm_connections`, identity and
  session tables, and drops secret-looking columns from every row.
- Credential-vault reveal is a separate audited call; the company documentation view returns references only.
- `JWT_SECRET`, `ENCRYPTION_KEY` and `BUNYIP_WEBHOOK_SECRET` have development fallbacks that are refused outside
  dev/test (section 6.1).

### 7.3 Input validation and output hardening

- Request bodies are validated with `validator` derives; failures return field-level errors in the error envelope.
  String values in JSON bodies are sanitised before reaching handlers (excluding signature-verified paths).
- Upload size caps are enforced per route with `DefaultBodyLimit` sized to the configured cap.
- Outbound fetches of caller- or tenant-supplied URLs (company website probe, ticket automation `webhook` action, RMM provider)
  pass an SSRF guard that resolves the name, refuses any non-public address, and re-checks every redirect hop;
  `OUTBOUND_PRIVATE_ALLOWLIST` is the explicit exception list.
- Every response carries `Strict-Transport-Security` (1 year, includeSubDomains, preload), `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy`, and
  `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none';
  form-action 'none'` unless the handler already set the header.
- Client IP for rate limits and audit comes from `X-Forwarded-For` only when the socket peer is inside the trusted
  proxy ranges.

### 7.4 Rate limits

All limiters are in memory and per process; they do not survive a restart or coordinate across replicas.

| Scope | Limit |
|---|---|
| Staff login | 20 per minute per IP and 5 per minute per lowercased email |
| Staff forgot-password | 10 per minute per IP and 3 per minute per email |
| Password re-authentication | 10 per minute per IP and 5 per minute per account |
| Platform admin login | 20 per minute per IP and 5 per minute per email |
| Invoice pay | 20 per minute per caller and 10 per minute per invoice |
| Contact portal login intents | 20 per minute per IP |
| Request-link and invoice emails | 20 per hour per user |
| Grant invitation token lookups | 30 per minute per IP |
| `/api/v1/public/*` | 60 per minute per IP |

A limited request answers `429` with `Retry-After`.

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
