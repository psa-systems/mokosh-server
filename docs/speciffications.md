# Technical Requirements Document

Mokosh Server is a Professional Services Automation (PSA) REST API for managed service providers (MSPs). This document specifies what the server does: its runtime, its identity and tenancy model, its infrastructure layer, and every feature module with its data model, API surface, behaviour, background jobs and configuration.

## Reading this document

- **Scope.** The server crate (`src/`), its two binaries, the workspace crates, the SQL migrations and the CI and image build. The browser client is a separate repository and is out of scope.
- **Where the truth lives.** The code is authoritative. Every statement below was read from the code, the migrations or the generated configuration registry, and cites the file it came from. A statement the author could not confirm is marked `unverified:` with what is unclear.
- **What this document does not repeat.** The binding rules per domain live in [`invariants/`](invariants/billing.md) and the longer design write-ups in [`architecture.md`](architecture.md) and [`providers.md`](providers.md). This document summarises each contract and links to it.
- **No status.** Whether a capability is planned, in progress or finished is tracked in the issue tracker, never here. Sequencing is in [`ROADMAP.md`](ROADMAP.md).
- **Routes** are written relative to `/api/v1` unless a path starts with another prefix. The route list is in `src/api/router.rs`; this document must be re-derived from it when a module is mounted or removed.

## 1. System overview

### 1.1 Technology

| Concern | Choice | Source |
|---|---|---|
| Language and runtime | Rust (toolchain pinned in `rust-toolchain.toml`), Tokio | `Cargo.toml`, `rust-toolchain.toml` |
| HTTP | Axum 0.8 with Tower middleware: CORS, tracing, brotli and gzip compression, request limits, request id | [architecture](architecture.md#runtime-shape) |
| Database | PostgreSQL 18 through SQLx; migrations embedded at compile time and run at start when `RUN_MIGRATIONS` is true (the default) | [architecture](architecture.md#database-migrations) |
| Email | Lettre over SMTP when `SMTP_HOST` is set, else a logging mailer | [config and providers invariants](invariants/config-providers.md#email-backend) |
| Secrets | Tenant-supplied secrets are AES-256-GCM ciphertext in the database under `ENCRYPTION_KEY`, or held in Infisical when `SECRET_BACKEND=infisical`; an unrecognised value is a startup error | [architecture](architecture.md#runtime-shape) |
| Files | One storage seam, `crate::storage`, with a local-disk or S3 provider | section 3 |
| Packaging | A debug dev image and a multi-stage Alpine musl release image | section 3 |

### 1.2 Binaries

- `mokosh-server` (`src/main.rs`): the long-running HTTP API. It also dispatches operator subcommands before it binds a port (`src/cli/`).
- `mokosh-bootstrap` (`src/bin/mokosh-bootstrap.rs`): a one-shot operator CLI for first-run Infisical setup and data tasks.

### 1.3 Deployment model

The server is multi-tenant only. One process serves many tenants (MSPs); each tenant's customers are modelled as companies and contacts inside that tenant. A tenant status other than `active` refuses every request from that tenant's users on the next request.

### 1.4 Identity planes

Three identity planes exist and never share credentials. The full text is in [architecture](architecture.md#auth-two-independent-mechanisms-pms-295); section 4 specifies each route.

| Plane | Identity | Mount | Credential |
|---|---|---|---|
| Staff | A `users` row | `/api/v1/*` | A bunyip-issued `at+jwt` Bearer verified against the issuer's JWKS, or a legacy HS256 Bearer backed by a `user_sessions` row |
| Contact | A `contacts` row | `/api/v1/contact/*` | A contact-plane `at+jwt` Bearer backed by a `contact_sessions` rotation family |
| Platform | A `platform_admins` row | platform routes | A `typ="platform"` Bearer |

Both staff mechanisms pass the same principal gate: a user whose `status` is not `active`, or whose tenant status is not `active`, is refused. A caller's own tenant always comes from membership state held in the database, never from a token claim. Routes that serve both staff and contacts take the `RequireCallerContext` extractor, which resolves the caller once and dispatches to a staff branch or a contact branch.

### 1.5 Route trees

| Prefix | Authentication |
|---|---|
| `/api/v1/*` | Session (staff) through `auth_middleware`; handlers opt in through gate extractors |
| `/api/v1/public/*` | None, by design; each route carries its own credential or throttle |
| `/api/v1/contact/*` | Contact Bearer through `portal_contact_middleware` |
| `/api/v1/bunyip/*` | HMAC signature or a signed logout token, never a session |
| `/api/v1/stripe/*`, `/api/v1/paypal/*` | Provider webhook verification, keyed per tenant |
| fallback | A static HTML page, no authentication |

The authoritative description of each tree and the exact public route list is [architecture, routing model](architecture.md#routing-model).

### 1.6 Cross-cutting requirements

These hold for every module and are enforced by the mechanisms named.

1. **Tenant isolation.** Every service method takes a `TenantId`. Its constructor is reachable only through `CurrentUser::tenant()`, so a handler that forgets the caller's tenant does not compile. `TenantId::from_trusted` is the listed escape hatch for webhook receivers, super-admin handlers addressing a path tenant, contact sessions, seeders and cross-tenant workers. Database access also sets the transaction-local setting `app.current_tenant` and relies on row-level security (section 4, row-level security).
2. **Input sanitation.** Every JSON request body passes `sanitize_json_body` before any extractor: it strips format characters and soft hyphens, folds non-ASCII whitespace and trims, at every depth. Secret-named fields and the signature-verified receivers are exempt so that byte-for-byte comparison still works.
3. **Error envelope.** Errors leave the API as `{"error":{"code","message"}}`, produced by `normalize_error_envelope`. A failure never answers `200`. The contract and the status mapping are in section 3 (utilities) and [error-visibility invariants](invariants/error-visibility.md).
4. **Pagination.** `per_page` above 100 is rejected at parse time (`src/utils/pagination.rs`).
5. **Module gates.** A tenant enables optional modules through `module_config` rows. A gated route answers 404 when its module is off or has no row.
6. **Migrations.** A committed migration is immutable. A new table is granted to the `mokosh_app` role in the same migration, and a guarded content `UPDATE` asserts its row count. See [architecture, migration rules](architecture.md#migration-rules).
7. **Outbound requests.** An outbound URL that tenant data can influence passes `guard_outbound_url` so that private and reserved addresses are refused. See [config and providers invariants](invariants/config-providers.md#outbound-urls-pms-805-pms-809).
8. **Stored files** are addressed by an `ObjectKey` that puts the tenant first; no caller builds a path.
9. **Secrets in logs.** A log line names the offending value and never a credential.

## 2. Document map

| Section | Contents |
|---|---|
| 3 | Platform infrastructure: boot, configuration, secrets, storage, database, scheduler, PDF, utilities, operator CLI, middleware, environment variables, build and release, testing |
| 4 | Identity, tenancy and access modules, and row-level security |
| 5 | Service-desk modules |
| 6 | Billing and delivery modules |
| 7 | Assets, integrations, knowledge base and platform-feature modules |

## 3. Platform infrastructure

### Process boot sequence (`src/main.rs`)

The server binary is `mokosh-server` (`src/main.rs`, library crate `mokosh_server` in `src/lib.rs`). Cargo features `multi-tenant` and `server` are both on by default (`Cargo.toml`). Steps run strictly in this order inside one `#[tokio::main]` function; a `?` or `expect` at any step ends the process before a port is bound.

| # | Step | Failure behaviour |
|---|---|---|
| 0 | If `argv[1]` is an operator subcommand (`cli::is_subcommand`), run it and exit instead of serving (see CLI section) | subcommand error -> stderr + exit 1 |
| 1 | Install `tracing_subscriber::fmt` with `EnvFilter` from `RUST_LOG`, default `info` | n/a |
| 2 | Log the version banner (`VersionInfo::banner`) | n/a |
| 3 | `dotenvy::dotenv()` loads `.env` (missing file ignored) before anything reads a variable | ignored |
| 4 | `DeploymentMode::from_env_for_providers()`: strict read of `MOKOSH_DEPLOYMENT_MODE` (`self-hosted` or `saas`; blank = self-hosted) | unrecognised value -> boot error naming both legal values |
| 5 | `storage::env::check_boot_env_from_process()` | a pre-rename storage variable (`STORAGE_BACKEND`, `ATTACHMENT_DIR`, `S3_*`) set -> message to stderr and boot error |
| 6 | `config::init_from_env(profile default)` installs the configuration provider and resolves generation 1 of every registry key | unknown `CONFIG_BACKEND` or any value other than `environment` -> boot error; keys with a `feature` annotation that no provider holds log a `warn` |
| 7 | `AppConfig::from_env()` (struct in `src/main.rs`) reads the typed process config | `expect` -> panic on error; see "Secret and shape gates" below |
| 8 | `check_deployment_requirements(environment)` | outside dev/test, any unset essential variable -> one combined boot error listing each (purpose, options, example) |
| 9 | `db::provision::provision_roles(DATABASE_URL)` | error -> boot ends |
| 10 | `Database::new(app_url, migrator_url)` opens both pools | connect failure -> boot ends |
| 11 | `db.run_migrations()` when `RUN_MIGRATIONS` is true (default) | error logged and boot ends |
| 12 | `modules::auth::bootstrap::maybe_bootstrap_admin` (`ADMIN_EMAIL`/`ADMIN_PASSWORD`) | `warn` only; boot continues |
| 13 | `crypto::parse_encryption_key(ENCRYPTION_KEY)` | `expect` -> panic |
| 14 | `app_secrets::init_from_env(...)`: builds application-tier providers, surveys, `enforce`s | any Misplaced or Unavailable governed secret, or one half of a client pair set -> boot error |
| 15 | Google and Microsoft contact-sync OAuth clients and the invoice-issuer apps are built from the governed secrets | half-set pair -> boot error (`?`) |
| 16 | `settings::app_name::resolve_and_cache(&db)` | `warn`, default name used |
| 17 | Email: `EmailConfig::from_env` -> `resolve_mailer_config` (DB settings over `SMTP_*`) -> `build_mailer` -> `Mailer::verify()` | config error -> `expect` panic; verify failure -> logged `error` and boot ends |
| 18 | Bunyip bearer verifier (`oidc_rs::VerifierConfig::from_env`, needs `OIDC_ISSUER` + `OIDC_AUDIENCE`) | missing -> logged at `info`, verifier disabled, boot continues |
| 19 | Authentication provider chain (`auth::providers::from_env_with`), recorded and installed | bad `AUTH_PROVIDERS` -> boot error |
| 20 | Worker objects constructed (notifications dispatcher, RMM sync, contract lifecycle, SLA sweep, recurring invoicing) | n/a |
| 21 | Tenant-tier secret provider (`secrets::provider_from_env`), then `storage::init_from_env` | `expect` -> panic on bad `SECRET_BACKEND`/`STORAGE_PROVIDER` or incomplete S3 settings |
| 22 | `ProviderSelection::record()` logs the resolved hosting profile and per-kind providers | n/a |
| 23 | Feature snapshot, then `Scheduler` built with all 14 jobs and `start()`ed | duplicate job name panics |
| 24 | Spawn one-shot passes (`scheduler::one_shot::spawn_once`, plus `branding::mover::arm`) | failure is a `warn`; never blocks boot |
| 25 | Optional GeoIP (`IP2LOCATION_DB_PATH`) and IP enrichment (`IP2PROXY_DB_PATH`) databases | unset -> `info`; unloadable file -> `warn`, feature off |
| 26 | `api::create_api_router(...)`, bind `HOST:PORT`, `axum::serve(..., into_make_service_with_connect_info::<SocketAddr>())` | bind/parse error ends the process |

Facts about the sequence:
- There is no graceful-shutdown hook in `src/main.rs` (`axum::serve` is awaited without `with_graceful_shutdown`); a repo-wide grep for `graceful`/`ctrl_c` finds no signal handling in `src/`.
- `PORT` that fails to parse falls back to `8080`; `RUN_MIGRATIONS` that fails to parse falls back to `true` (`AppConfig::from_env`).
- `DATABASE_URL` unset falls back to a localhost development URL in `AppConfig::from_env`; it is not in `ESSENTIAL_DEPLOYMENT_REQUIREMENTS`, so outside dev/test the failure surfaces at pool connect, not at the requirement check.
- `MOKOSH_APP_DATABASE_URL` unset falls back to `DATABASE_URL` in dev/test (single role; RLS then does not bite); outside dev/test it is an essential requirement.

#### Secret and shape gates (`src/main.rs`)

- Dev/test environments are exactly `development`, `dev`, `test` (`env_allows_dev_secrets`); any other value, including empty or `Development`, is treated as non-dev.
- `JWT_SECRET`, `ENCRYPTION_KEY`, `BUNYIP_WEBHOOK_SECRET` go through `resolve_secret`: in dev/test an unset value takes a built-in development constant; elsewhere an unset value, or the development constant, is a boot error.
- Outside dev/test `JWT_SECRET` must be at least 32 bytes and `ENCRYPTION_KEY` must be exactly 64 hex characters. `crypto::parse_encryption_key` additionally accepts 32 raw non-hex bytes (dev/test form) and rejects a 32-character all-hex string as ambiguous.
- `ESSENTIAL_DEPLOYMENT_REQUIREMENTS` (five): `MOKOSH_DEPLOYMENT_MODE`, `MOKOSH_APP_DATABASE_URL`, `BASE_URL`, `CLIENT_ORIGIN`, `SPA_BASE_URL`. Blank counts as unset.
- `CORS_ORIGIN` entries are validated by `CorsOriginMatcher::from_entries` (`src/api/cors_origin.rs`), which `panic!`s on an empty or malformed entry during router construction.

Contract detail: [architecture](architecture.md), [configuration](configuration.md), [providers](providers.md) (section "What happens at boot").

### Configuration subsystem (`src/config`)

Purpose: one read path over a declared key registry; an undeclared key cannot be read.

- **Registry** (`src/config/registry.rs`): the `declare_keys!` macro declares each `ConfigKey` with `Tier` (`Bootstrap` or `Application`), `since "vX.Y.Z"`, and `required` or `optional` (optionally `required "vX.Y.Z"` for the release that made it required), plus an optional `#[feature = "..."]` sentence. `REGISTRY` holds 68 keys: 10 `Bootstrap`, 58 `Application`. The `required` set is pinned by a unit test to `DATABASE_URL`, `MOKOSH_APP_DATABASE_URL`, `ENCRYPTION_KEY`, `BASE_URL`, `JWT_SECRET`, `BUNYIP_WEBHOOK_SECRET`, `CLIENT_ORIGIN`, `SPA_BASE_URL`; the bootstrap set is pinned to `DATABASE_URL`, `MOKOSH_APP_DATABASE_URL`, `ENCRYPTION_KEY`, `APP_SECRETS_DIR`, `CONFIG_FILE_DIR`, `CONFIG_PROVIDERS`, `BUNYIP_CONFIG_URL`, `BUNYIP_CONFIG_CLIENT_ID`, `BUNYIP_CONFIG_CLIENT_SECRET`, `AUTH_PROVIDERS`.
- **Tiers**: Bootstrap keys resolve once per process and are carried unchanged across `refresh()` (a provider is built from them); Application keys re-resolve on every refresh.
- **Read API** (`src/config/mod.rs`): `config::get(&ConfigKey) -> Option<String>` (a present-but-blank value is `Some("")`; the caller owns its emptiness rule), `has`, `served_by`, `snapshot()` (one `Arc<Generation>` per request), `refresh()`, `try_refresh(RefreshRequest)`. A generation records value and serving provider per key, a number, a timestamp and the actor (`System` or `Operator(login)`).
- **Atomic refresh**: `try_refresh` returns `Applied` or `Rejected` (previous generation stays live); `required_keys` that fail to resolve, or a Bootstrap key named as required, reject. The admin route `POST /api/v1/admin/providers/status/refresh` calls it and answers 409 on rejection.
- **Providers** (`ConfigProviderKind`): `environment`, `file` (`CONFIG_FILE_DIR`, one file per key), `database` (table `app_config`, application-tier keys only, plaintext), `bunyip` (`BUNYIP_CONFIG_URL` + client id/secret, token exchange then one GET per key). Request-serving reads use only the `environment` provider: `ConfigSelection::resolve` rejects any other `CONFIG_BACKEND`, and `build()` panics for a non-environment kind. The multi-provider chain (`CONFIG_PROVIDERS`, `build_chain_from_env`, `classify`) is built by the operator subcommands and `verify-providers`, not by `main.rs`.
- **Provider selection**: hosting profile default (`MOKOSH_DEPLOYMENT_MODE`) unless the operator names one; see the Hosting profiles subsection of "Secrets and application secrets" below.
- **Single-read-path guard** (`src/config/guard.rs`): a unit test fails `cargo test --lib` on an environment read anywhere in `src/` outside `src/config` and the listed `ENTRY_POINTS` (bootstrap binary, `src/cli/*`, `src/db/provision.rs`, `src/secrets/{mod,infisical}.rs`, `src/app_secrets/{mod,env,bunyip}.rs`, `src/storage/{mod,env,s3}.rs`, `src/utils/deployment.rs`, each with a stated reason).
- **Variables read outside the registry** (the entry points above) are declared in `src/config/variables.toml` with `since`, `required`, `reader`, and `removed`. `just config-docs` renders registry plus `variables.toml` into `docs/configuration.md`; `just check-config-docs` fails on disagreement; `just check-env-example` requires each variable the code reads to appear in `.env.example` and `compose.dev.yml`.
- **Feature flags** (`src/config/flags.rs`): `Flag<bool>` over a registry key with a `FlagDefault` (constant or per profile). `ORGANIZATIONS_ENABLED` (self-hosted false, saas true), `LOGIN_APPROVAL_ENABLED` (false), `ALLOW_UNINVITED_BUNYIP_SIGNUP` (false). A raw value that does not parse as a bool falls back to the flag default.

Contract detail: [providers](providers.md), [configuration](configuration.md), [config and provider invariants](invariants/config-providers.md).

### Secrets and application secrets (`src/secrets`, `src/app_secrets`)

Two tiers with separate selectors and provider sets.

**Hosting profile** (`src/utils/deployment.rs`): `DeploymentMode` is `SelfHosted` (default) or `Saas`. Per-kind defaults (`ProviderKind`: configuration, secrets, authentication, email, storage):

| Kind | self-hosted | saas |
|---|---|---|
| configuration | environment | environment |
| secrets | database | database |
| authentication | local | bunyip, local |
| email | log | smtp |
| storage | local | local |

Known provider names per kind: configuration `environment`; secrets `database`, `infisical`; authentication `local`, `bunyip`; email `log`, `smtp`, `bunyip`; storage `local`, `s3`. `DeploymentMode::parse` (lenient, used for mail dispatch) logs a warning and falls back to self-hosted on an unknown value; `parse_for_providers` (strict, used in `main.rs`) errors. `ProviderSelection::record()` logs which kinds came from the profile and which were explicitly overridden.

**Tenant tier** (`src/secrets`): `SecretProvider` async trait (`get`, `put`, `put_if_absent`, `delete`) over `SecretKey { tenant_id, kind }`; `SecretKind` is `PaymentGateway`, `ContactSync{connection_id}`, `OauthClient`, `Integration`. Stored name is `{PREFIX}__{tenant uuid simple}__{DISCRIMINATOR UPPER}` with prefixes `PAYMENT_GATEWAY`, `CONTACT_SYNC`, `OAUTH_CLIENT`, `INTEGRATION`; the discriminator is 1-48 chars of lowercase ASCII, digits, underscore (else `AppError::Configuration`). Providers, chosen by `SECRET_BACKEND` (profile default when unset; unknown value errors; naming an application-tier provider here errors with a pointer to `APP_SECRET_BACKEND`):
- `database` (default): table `secrets (tenant_id, name, value_encrypted)`, AES-256-GCM under `ENCRYPTION_KEY`.
- `infisical`: writes under the `/mokosh/integrations` folder; needs `INFISICAL_ADDRESS`, `INFISICAL_PROJECT_ID`, `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET`, `INFISICAL_ENVIRONMENT`.

**Application tier** (`src/app_secrets`): deployment-wide secrets, not per tenant.
- **Governed-secret registry**: `GovernedSecret::ALL` has 11 entries: `SMTP_PASSWORD`, `GOOGLE_CONTACTS_CLIENT_ID`, `GOOGLE_CONTACTS_CLIENT_SECRET`, `MICROSOFT_CONTACTS_CLIENT_ID`, `MICROSOFT_CONTACTS_CLIENT_SECRET`, `XERO_CLIENT_ID`, `XERO_CLIENT_SECRET`, `XERO_WEBHOOK_KEY`, `QUICKBOOKS_CLIENT_ID`, `QUICKBOOKS_CLIENT_SECRET`, `QUICKBOOKS_VERIFIER_TOKEN`. Each carries a `feature()` sentence (what stops working when no provider holds it) and a `secret_file()` name (lowercase, used by the file provider).
- **Selector**: `APP_SECRET_BACKEND` (profile default when unset). Provider kinds: `environment` (reads only `{NAME}_FILE` compose-secret paths, never the plain variable; not writable), `file` (built only when `APP_SECRETS_DIR` is set; one file per `secret_file()`), `database` (table `app_secrets`, AES-256-GCM, preloaded once into a cache), `infisical` (folder `/app`; built only when `INFISICAL_ADDRESS` is set; preloaded), `bunyip` (read-only; built when `BUNYIP_SECRETS_URL` plus client id/secret are set, all three or none; fetches the single key `mokosh/google_oauth_client` once at load and serves both Google halves). `AppSecretProvider::get` is synchronous; a save through the database provider needs a reload to be seen by the running process.
- **Per-secret declaration**: `AppSecrets::declared_for(secret)` returns the secret's own declared provider, else the process-wide one. Declarations come only from the hosting profile table (`SAAS_SECRET_PROVIDERS` declares `GOOGLE_CONTACTS_CLIENT_ID` and `GOOGLE_CONTACTS_CLIENT_SECRET` to `bunyip`; `SELF_HOSTED_SECRET_PROVIDERS` is empty) via `per_secret_defaults`; no environment variable sets one. A declared provider is not a fallback.
- **Boot survey and `enforce`** (`app_secrets::init_from_env` builds environment always, file/infisical/bunyip conditionally, database always, then `AppSecretsSurvey::from_current` and `enforce`): per governed secret, `Used` (info), `Missing` (warn with the feature sentence), `Shadowed` (info plus a warn per duplicate holder), `Misplaced` (held elsewhere but not by the declared provider: fatal), `Unavailable` (declared provider could not be built: fatal). All fatal rows are joined into one boot error.
- **Status**: `app_secrets::status(survey)` yields names, holders, declared and serving provider; values are never rendered.

Contract detail: [providers](providers.md) (sections "A secret can be declared to its own provider", "Hosting profiles"), [operator runbook](operator-provider-runbook.md), [config and provider invariants](invariants/config-providers.md#per-secret-declaration-pms-1537).

### Object storage (`src/storage`)

- **Seam**: `ObjectProvider` async trait (`put`, `read`, `open` (streaming reader), `delete`, `exists`, `rename`, `location`) over `ObjectKey { tenant_id, kind }`; a caller is handed a tenant and an identity, never a path. Process-wide handle via `storage::shared()`; `storage::init_from_env` installs it once.
- **Providers**: `local` (`LocalProvider`, root `STORAGE_ROOT`, default `./attachments`) and `s3` (`s3::S3Provider`, no client crate, hand-written SigV4 with `reqwest`, 10 s connect and 300 s request timeouts, path-style by default, requires endpoint, bucket and both credentials). Selected by `STORAGE_PROVIDER` (`local`/`s3`; unknown value errors rather than falling back). The deprecated pre-rename names are refused at boot, not aliased (`check_boot_env`, step 5 above).
- **`ObjectKind` and relative path** (`ObjectKey::relative_path`, identical string for local and S3):

| Kind | Path under root | Retention |
|---|---|---|
| `TicketAttachment{id}` | `{tenant}/{id}` | while referenced |
| `TenantLogo{extension}` | `{tenant}/logo.{ext}` | while referenced |
| `KbAttachment{id}` | `{tenant}/kb-articles/{id}` | while referenced |
| `FinancialDocument{id}` | `{tenant}/documents/{id}` | 7 years |
| `BrandingLogo{digest}` | `{tenant}/branding/{digest}` | while referenced (content-addressed, shared) |
| `ContactImport{id}` | `{tenant}/contact-imports/{id}` | while referenced |
| `LegacyKbAttachment{id}` | `kb-articles/{id}` (read fallback) | while referenced |
| `LegacyTenantLogo{extension}` | `tenant-logos/{tenant}.{ext}` (read fallback) | while referenced |

  Branding assets (favicon, background, company pairs) are laid out by `src/modules/branding/assets.rs` under `{tenant}/branding/...`. Caller-supplied segments (extension, digest) are validated. A unit test (`every_object_kind_puts_its_tenant_first`) fails a new kind that does not start with its tenant.
- **File ledger** (`src/storage/ledger.rs`): one row per stored file in table `files`, keyed by `ObjectKey::relative_path`, so tenant storage usage is queryable; feature-table `file_size` columns remain the per-feature source for their own responses.
- **Upload caps** are env-driven per feature (see environment variables: `ATTACHMENT_MAX_BYTES`, `KB_ATTACHMENT_MAX_BYTES`, `TENANT_LOGO_MAX_BYTES`, `BRANDING_*_MAX_BYTES`); `utils::upload_limits::body_limit_bytes` sizes each route's `DefaultBodyLimit`.

Contract detail: [stored file layout in configuration](configuration.md#storage-layout), [architecture](architecture.md), [config and provider invariants](invariants/config-providers.md#storage-seam-pms-910).

### Database layer (`src/db`)

- **Two pools** (`db::pool::Database`): `pool()` is the request-serving pool (role `mokosh_app`, `NOSUPERUSER NOBYPASSRLS`), `migrator_pool()` is the privileged pool (role `mokosh_migrator`, `BYPASSRLS`; used for migrations, bootstrap, cross-tenant workers, pre-auth paths). Each pool: max 20, min 2 connections, 30 s acquire timeout, 600 s idle timeout, 1800 s max lifetime. When both URLs are identical a single pool is shared. A `.pool()` call on a serving path must carry an adjacent `// SAFETY (PMS-285` note, enforced by `just check-pool-safety`.
- **Migrations**: `sqlx::migrate!("./migrations")` embedded at compile time (`build.rs` emits `rerun-if-changed=migrations`), run on `migrator_pool` with `set_ignore_missing(true)`. 290 files in `migrations/` (`NNN_name.sql`). Immutability and unique-prefix rules are CI guards (see build section).
- **Role provisioning** (`src/db/provision.rs`): at boot, probes whether `DATABASE_URL` connects and `mokosh_app` exists and can log in. Both present -> skip. Otherwise, with `MOKOSH_ADMIN_DATABASE_URL`, creates or reconciles `mokosh_migrator` (`LOGIN BYPASSRLS`, schema and `CREATE ON DATABASE` grants, default privileges granting DML/sequence/function rights to `mokosh_app`) and `mokosh_app` (`LOGIN NOSUPERUSER NOBYPASSRLS`, connect/usage/DML grants), passwords from `MOKOSH_MIGRATOR_PASSWORD` and `MOKOSH_APP_PASSWORD`. If only the app role's password does not authenticate, only the app statements run (the migrator password is left alone). Admin variable unset when needed -> `AppError::Database` naming the state; the privileged pool is closed right after.
- **Tenant isolation**: `Database::begin_with_tenant(tenant_id)` begins a transaction on `pool()` and runs `SELECT set_config('app.current_tenant', $1, true)` (transaction-local GUC); returns `TenantTransaction` (derefs to `PgConnection`; `commit`, `rollback`, `tenant_id`). RLS policies read `current_setting('app.current_tenant')` (referenced across migrations; 173 ENABLE or FORCE ROW LEVEL SECURITY statements across `migrations/`). Two further GUCs: `app.skip_users_identity_mirror` (set transaction-local from `src/modules/auth/service.rs` to suppress the users-to-identities mirror trigger) and `app.allow_system_writes` (read by a migration policy/trigger; no setter found in `src/`, unverified who sets it). Service methods take a `TenantId` newtype obtainable only from `CurrentUser::tenant()` (`TenantId::from_trusted` is the listed escape hatch).
- **Other**: `identity.rs` (read helpers over `identities` / `tenant_memberships`), `platform_admin.rs` (platform super-admin store), `Database::health_check` (`SELECT 1` on the app pool, used by `/ready`).

Contract detail: [architecture](architecture.md) (Multi-tenancy, Database migrations, Migration rules), [postgres security Q&A](postgres-security.md) (dated discussion; takeaway: three identities, app role must be NOBYPASSRLS and not the owner), [RLS per user](rls-per-user-isolation.md).

### Scheduler (`src/scheduler`)

- `Job` trait: `name() -> &'static str` (unique; duplicate registration panics) and `async run() -> AppResult<()>`. `Scheduler::register(job, interval)` / `register_wakeable(job, interval, &JobWake)`; `start()` spawns one tokio task per job with `tokio::time::interval` and `MissedTickBehavior::Skip`. The first tick is immediate, so every job runs once at process start. A tick error is logged at `warn` and the loop continues; there is no scheduler-level retry. `JobWake::wake()` runs a wakeable job now (permit coalesces; only affects the current process).
- All 14 registered jobs (`src/main.rs`):

| Job name | Cadence | Owner module |
|---|---|---|
| `feature_toggle_refresh` | 60 s | `modules/features` |
| `asset_signature_detector_refresh` | 60 s | `modules/asset_catalog` (refreshes materialized view `asset_signature_candidates_mv`) |
| `notifications_dispatcher` | 5 s | `modules/notifications` |
| `rmm_sync` | 60 s | `modules/rmm` |
| `contact_sync` (wakeable) | 60 s | `modules/contact_sync` |
| `contract_lifecycle` | 3600 s | `modules/contracts` |
| `recurring_invoicing` | 3600 s | `modules/billing` |
| `sla_sweep` | 60 s | `modules/sla` |
| `calendar_reminders` | 60 s | `modules/calendar` |
| `grant_invitations_expiry_sweep` | 3600 s | `modules/auth` |
| `scheduled_reports` | 60 s | `modules/saved_reports` |
| `scheduled_dashboards` | 60 s | `modules/dashboards` |
| `invoice_reminders` | 3600 s | `modules/billing` |
| `status_retention` | 6 h | `modules/status` |

- **One-shot passes** (`scheduler::one_shot::spawn_once(name, future)`): spawned once per process start, never awaited, failure logged at `warn` ("runs again at the next restart"). Registered: `kb_attachment_move` (`modules/knowledge_base`), `tenant_logo_move` (`modules/tenants`), `branding_mover_pms_1397` (`modules/branding`, via `mover::arm`), `gateway_credential_move` (`modules/billing`), `contact_sync_client_secret_cleanup` (`modules/contact_sync`).
- Every job's interval and name appear in a `scheduler: spawning job` log line.

### PDF rendering (`src/pdf`)

`pdf::render(Document, generated_on: NaiveDate) -> AppResult<Vec<u8>>` (async; runs the synchronous renderer on the blocking pool). Pure Rust via `printpdf` (no native renderer, static musl image). A `Document` is a title, optional subtitle, optional `Logo`, a `Template` (`classic`, `modern`, `compact`; `Template::KEYS`) and a list of `Section`s whose `Body` is `Fields`, `Lines`, `Table{headers, rows, align}`, `Columns`, or `Totals`. Not a layout engine. Noto Sans Regular and Bold are vendored in `src/pdf/fonts/` and embedded; only glyphs actually drawn are subset into each document (`allsorts`); characters outside Noto Sans coverage render as `?` and one `warn` names them. Output is deterministic for the same input and date (unit test). The release image carries the font licence at `/app/licenses/`.

### Provider status report (`src/providers/status`)

`collect()` builds a `ProviderStatusReport` (wire types from the shared `dunite_provider_status` crate) covering configuration, application-tier secrets, tenant-tier secrets, storage, authentication, email; only names, booleans, integers and timestamps, never values. Two pure renderers: `renderer_json::render_json`, `renderer_html::render_html`. Routes (mounted under `/api/v1`):
- `GET /admin/providers/status`, `GET /admin/providers/status.html`, `POST /admin/providers/status/refresh` (`src/providers/status/route.rs`). Gate `RequireAdminOrBunyipMachine` (`auth.rs`): HTTP Basic matching `BUNYIP_STATUS_CLIENT_ID`/`_SECRET` (constant-time compare; a wrong Basic credential is 401 even with a staff session), else a staff admin session. With both variables unset only the staff-admin path exists. The refresh route requires an admin user and answers 200 (applied) or 409 (rejected) with the outcome in the JSON envelope.
- `GET /providers` (`public_summary_route.rs`): unauthenticated identity summary (hosting profile name, provider names for the deployment-scoped kinds, schema version); no values, URLs or per-key rows; tenant-tier secrets omitted.

### Utilities (`src/utils`)

- **Error type** (`error.rs`): `AppError` variants and (status, `error.code`) mapping:

| Variant | Status | Code |
|---|---|---|
| `Unauthorized` | 401 | `UNAUTHORIZED` |
| `TokenExpired` | 401 | `TOKEN_EXPIRED` |
| `Payment` | 402 | `PAYMENT_ERROR` |
| `Forbidden` | 403 | `FORBIDDEN` |
| `NotFound` | 404 | `NOT_FOUND` |
| `Conflict` | 409 | `CONFLICT` |
| `Gone` | 410 | `GONE` |
| `AccountDeleted` | 410 | `ACCOUNT_DELETED` |
| `PayloadTooLarge` | 413 | `PAYLOAD_TOO_LARGE` |
| `Validation{message, errors}` | 422 | `VALIDATION_ERROR` |
| `QueryError{message, errors}` | 400 | `BAD_REQUEST` |
| `BadRequest`, `Tenant`, `File` | 400 | `BAD_REQUEST`, `TENANT_ERROR`, `FILE_ERROR` |
| `RateLimited` | 429 | flat body, see below |
| `Database`, `Internal`, `Configuration`, `Email` | 500 | `DATABASE_ERROR`, `INTERNAL_ERROR`, `CONFIGURATION_ERROR`, `EMAIL_ERROR` |
| `ExternalService`, `Integration` | 502 | `EXTERNAL_SERVICE_ERROR`, `INTEGRATION_ERROR` |

  Body shape: `{"error": {"code": "...", "message": "...", "errors": [{"field","message","code"}]}}`; `errors` appears only for `Validation` and `QueryError`. `Database` messages are replaced by the generic "Database operation failed"; other variants return their own `Display` text. `RateLimited` always renders through `rate_limited_response`: status 429, flat body `{"error": "rate_limited", "message", "retry_after_seconds"}`, headers `Retry-After` and `Cache-Control: no-store` (default 60 s when unknown; `just check-rate-limit-helper` forbids building a 429 elsewhere). `From<sqlx::Error>`: `RowNotFound` -> `NotFound("Record")`, Postgres `23505` -> `Conflict("That record already exists")` logged at `debug`, any other -> `Database` logged at `error`. `normalize_error_envelope` (middleware) replaces a non-JSON 4xx (extractor rejection) with the canonical envelope (`BAD_REQUEST`, `UNSUPPORTED_MEDIA_TYPE`, `PAYLOAD_TOO_LARGE`, `LENGTH_REQUIRED`, `METHOD_NOT_ALLOWED`; a 422 from a failed JSON body becomes `BAD_REQUEST`). Logging rules: [error visibility invariants](invariants/error-visibility.md).
- **Pagination** (`pagination.rs`): `PaginationParams {page=1, per_page=25, sort, sort_dir="desc"}`; `MAX_PER_PAGE=100`; `per_page` above 100 fails deserialization (and `reject_over_cap_per_page` returns a 422 field error); a zero `per_page` is clamped to 1; `order_by` / `order_by_mapped` accept only an allow-list and return a 422 `sort` field error otherwise. Response `PaginatedResponse<T> {data, meta{page, per_page, total, total_pages, has_next, has_prev}}`. Filters must not set `deny_unknown_fields` (pagination is parsed from the same query string by a second extractor).
- **Email** (`email.rs`): `Mailer` async trait: `send_multipart`, `send_text`, `send_with_attachments`, `verify`, plus typed senders `send_invoice_sent`, `send_invoice_reminder`, `send_new_login_location`, `send_login_approval_code`. Implementations: `LogMailer` (no bytes leave), `SmtpMailer` (lettre; `SmtpTls` = `none`/`starttls`/`implicit`; `verify` is an SMTP NOOP), `ApiMailer` (Bunyip mailer relay, `MAIL_PROVIDER=bunyip`, needs `BUNYIP_MAILER_URL` + client id/secret). `SharedMailer` wraps the live mailer in an `RwLock` so admin email-settings changes can `swap` it. Provider choice (`EmailConfig::resolve`): explicit `MAIL_PROVIDER` wins, else `smtp` when `SMTP_HOST` is set, else the hosting profile default; `log` with `SMTP_HOST` set warns; `smtp` without `SMTP_HOST` errors.
- **Crypto** (`crypto.rs`): `encrypt`/`decrypt` AES-256-GCM, output base64 of `nonce(12) || ciphertext`; `parse_encryption_key`; `generate_token`, `generate_api_key`, `sha256_hex`, `generate_numeric_code`; passwords Argon2 (default params) on the blocking pool (`hash_password`, `verify_password`, `verify_password_or_dummy`). Also `totp.rs` (RFC 6238, 30 s step, 6 digits, 20-byte secret) and `password_policy.rs` (min length 12, max 128, zxcvbn min score 3 by default).
- **Validation** (`validation.rs`): `validator`-crate custom validators (email, phone, slug, password strength, cron, contract type/status, billing cycle, money/payment/budget/hours/tax-rate decimals, IP and MAC address, scheduling template kind) and `slugify`, `truncate`. Create/Update request pairs must validate a field identically (`just check-validate-parity`).
- **Rate limiters** (live in `src/modules/auth/rate_limit.rs`, not `src/utils`): in-memory `governor` keyed limiters, per process, lost on restart, not shared across replicas. `AuthRateLimiter` per (IP, email): login 20/5 per minute, forgot-password 10/3 per minute, platform login 20/5; `ReauthRateLimiter` 10/5; `PayInvoiceRateLimiter`; `UserMailLimiter` 20 per hour; `PublicIpLimiter` 60 per minute on `/api/v1/public/*`; `GrantInvitationTokenLimiter` 30 per minute; plus `BackchannelLogoutLimiter` (`auth/backchannel_logout.rs`), `RequestFormLimiter` (`forms/public_routes.rs`), `WebsiteProbeLimiter` (`contacts/website_probe.rs`). Over quota -> 429 via `rate_limited_response`.
- **`sanitize_json_body`** (`text.rs`): global middleware; for `application/json` (and `+json`) request bodies, buffers up to 25 MiB, strips invisible characters from string values and keys (skips fields recognised as secrets), re-emits the body. Skipped for raw-body prefixes that verify signatures over the exact bytes: `/api/v1/bunyip/`, `/api/v1/rmm/alerts`, `/api/v1/rmm/status`, `/api/v1/stripe/`, `/api/v1/paypal/`, `/api/v1/webhooks/`. A body that cannot be buffered answers `PayloadTooLarge`.
- **`guard_outbound_url`** (`net.rs`): async SSRF guard. Requires `http`/`https` scheme and a host, optionally restricts ports (`WEB_PORTS` = 80, 443), resolves the host and rejects any address in a non-public range (`is_non_public_ip`) unless exempted by `OUTBOUND_PRIVATE_ALLOWLIST` (hosts, IPs or CIDRs; a named host skips resolution screening). Errors: `UrlGuardError::{Scheme, Port, NoHost, Dns, Blocked}`. Every outbound fetch of a request- or tenant-supplied URL calls it and re-screens each redirect hop (website probe, automation `webhook` action, RMM provider). A unit test pins exactly one definition in the crate.
- **Other modules**: `client_ip.rs` (`X-Forwarded-For` trusted only from `TRUSTED_PROXY_CIDR`; default 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, ::1/128, fc00::/7, fe80::/10), `security_headers.rs`, `deployment.rs`, `geoip.rs`, `upload_limits.rs`, `content_disposition.rs`, `login_location.rs`, `app_name.rs`, `money.rs`, `datetime.rs`, `html.rs`, `inline_image.rs`, `json.rs`, `recovery.rs`, `unresolved_person.rs`.

### Operator subcommands (`src/cli`)

`mokosh-server <subcommand>` runs the task and exits instead of serving (`cli::is_subcommand`, dispatched in `main` before tracing setup). `run_cli` loads `.env.infisical` then `.env`, installs a plain `info`-default tracing filter, and on error prints `error: ...` to stderr and exits 1. The subcommand set:

| Subcommand | Purpose | Inputs |
|---|---|---|
| `bootstrap-infisical` | First-run setup of a fresh Infisical instance; writes `INFISICAL_*` to the env file | `INFISICAL_ADMIN_EMAIL`, `INFISICAL_ADMIN_PASSWORD` required; optional `INFISICAL_ADMIN_FIRST_NAME`, `_LAST_NAME`, `INFISICAL_URL`, `INFISICAL_PROJECT_NAME`, `INFISICAL_IDENTITY_NAME`, `INFISICAL_ENVIRONMENT`, `MOKOSH_ENV_FILE` |
| `qa-seed`, `qa-teardown` | Load or remove the QA walkthrough dataset; fail-closed against a tenant not marked QA | `--tenant <uuid>` or `MOKOSH_QA_TENANT_ID`; `DATABASE_URL` (used as both pools) |
| `showcase-seed`, `showcase-refresh`, `showcase-teardown` | Create, reset or remove the showcase demo dataset; fail-closed against a tenant not marked `is_showcase` | `--tenant <uuid>` or `MOKOSH_SHOWCASE_TENANT_ID`; `DATABASE_URL` |
| `provider-status` | Per-key, per-provider presence matrix (names only) | `--json` / `--text` |
| `provider-migrate` | Copy values from one provider to another, write then read back, never deletes the source | `--from <provider> --to <provider>`, `--json` / `--text` |
| `provider-set` | Write one value with no previous home to the declared provider only; value read from a named environment variable; read-back from a freshly built provider | `--secret <NAME> --from-env <VAR>` |
| `provider-purge` | Remove a copy from a provider; refuses per key unless that provider is disabled and the key is live in the serving provider | `--provider <name> --confirm` |
| `verify-providers` | Boot every provider seam (configuration, app and tenant secrets, storage, authentication, email incl. SMTP NOOP) and report build/answer per capability; non-zero on any failure | `--json` / `--text` |

Provider subcommands render names and statuses only and assert at runtime that no value reaches output. Role provisioning is part of normal boot, not a subcommand.

### Bootstrap binary (`src/bin/mokosh-bootstrap.rs`)

Standalone binary `mokosh-bootstrap`; loads `.env.infisical` then `.env`; exit code `SUCCESS`/`FAILURE`. Subcommands: `bootstrap-infisical`, `qa-seed`, `qa-teardown`, `dev-seed-portal` (dev-only portal login fixtures, refuses outside dev/test), `normalize-company-industries` (re-runnable, all tenants), `--version`/`-V`, `--help`/`-h`. Its set overlaps `mokosh-server`'s subcommands without matching it (`provider-*`, `showcase-*`, `verify-providers` exist only on `mokosh-server`). The runtime image ships both binaries. See [binaries](binaries.md).

### Version and update check (`src/version.rs`, `src/version_check.rs`, `build.rs`)

- `build.rs` calls `crates/build-metadata` to export `MOKOSH_GIT_HASH` (12 chars), `MOKOSH_GIT_DESCRIBE`, `MOKOSH_BUILD_DATE`; the OCI build passes them as build args because `.git` is not in the build context. `VersionInfo {name, version, git_describe, git_hash, build_date}` backs `GET /api/v1/version` and the startup banner.
- `GET /api/v1/version/check`: `UpdateCheck` tagged enum (`disabled`, `up_to_date`, `update_available{release_url}`, `error`). With `MOKOSH_UPDATE_CHECK_URL` unset it is `disabled` and makes no outbound request. Otherwise it fetches a JSON manifest `{ "version", "release_url"? }` with a 5 s timeout and caches the result (15 min on success, 60 s on error). The probe client is cached in a `OnceLock`.

### Router and middleware stack (`src/api/router.rs`)

`create_api_router` takes the shared services and returns the root `Router`. Mount points: `/api/v1` (session), `/api/v1/public` (no auth), `/api/v1/contact` (contact bearer), `/api/v1/bunyip` (account-deleted webhook, grant-changed webhook, back-channel logout when the verifier exists), `/api/v1/stripe/webhooks/{tenant_id}`, `/api/v1/paypal/webhooks/{tenant_id}`, `/api/v1/webhooks/xero` and `/quickbooks`; a `GET` fallback serves an HTML "not a frontend" page. Operational routes under `/api/v1`: `GET /health` (liveness, `OK`), `GET /ready` (DB ping bounded to 3 s plus optional Infisical probe when `INFISICAL_ADDRESS` is set; 503 with a JSON `checks` breakdown on failure, `Cache-Control: no-store`), `GET /version`, `GET /version/check`, `GET /providers`. Full route list: [architecture](architecture.md#routing-model).

Layer order. In axum the LAST `.layer` is outermost, so a request passes these from first to last:

| Order | Layer | Applies to |
|---|---|---|
| 1 | `security_headers` (HSTS, nosniff, X-Frame-Options DENY, no-referrer, restrictive Permissions-Policy, CSP `default-src 'none'`; a header the handler already set wins) | every response |
| 2 | `CorsLayer`: origin predicate from `CORS_ORIGIN` (exact entries plus scheme-locked `https://*.suffix` wildcards), methods GET POST PUT DELETE PATCH OPTIONS, headers Authorization, Content-Type, Accept, X-Forwarded-Host, credentials allowed, preflight cached 600 s | every route |
| 3 | `CompressionLayer::new()` (tower-http defaults; gzip and brotli negotiated, pinned by unit tests) | every route |
| 4 | `TraceLayer::new_for_http()` (default spans) | every route |
| 5 | `sanitize_json_body` | every route (raw-body prefixes skipped) |
| 6 | per-nest layers below | per nest |

Per-nest layers (request order, outermost first): `/api/v1`: `normalize_error_envelope`, extensions (`PlatformAdminService`, `SettingsService`, `Database`), contact-plane `portal_contact_middleware`, `auth_middleware`, first-visit `seed_middleware`, handler. `/api/v1/public`: `normalize_error_envelope`, `PublicIpLimiter` (60 per minute per IP). `/api/v1/contact`, `/api/v1/bunyip`, provider webhooks: `normalize_error_envelope`.

Not present in the global stack (grep of `src/` for these names): no request-id layer, no global request timeout layer, no global body-size limit layer. Body limits are per route: `DefaultBodyLimit::max(body_limit_bytes(cap))` on upload routes (tickets attachments, KB attachments, tenant logo, branding assets, contact-sync vCard upload) and a 25 MiB cap on tenant data import; everything else uses axum's extractor default.

### environment variables

Source of truth: `src/config/registry.rs` (68 declared keys), `src/config/variables.toml` (variables read outside the registry), rendered into [configuration](configuration.md). "Required" means the server refuses to start without it when `ENVIRONMENT` is not `development`, `dev` or `test` (the declared fact; enforcement mechanism is noted in the boot section). Tier B = bootstrap (restart to change), A = application (re-resolved on refresh). Defaults and purposes were checked against the code readers named in the boot and subsystem sections; the `since` column is the registry's release string.

**Registry keys**

| Name | Required | Since | Default | Purpose |
|---|---|---|---|---|
| `DATABASE_URL` (B) | yes | v0.1.0 | localhost development URL in code | Privileged `mokosh_migrator` connection (migrations, bootstrap, cross-tenant workers) |
| `MOKOSH_APP_DATABASE_URL` (B) | yes (from v0.14.0) | v0.3.0 | falls back to `DATABASE_URL` in dev/test | Request-serving `mokosh_app` connection (NOBYPASSRLS) |
| `ENCRYPTION_KEY` (B) | yes (from v0.4.0) | v0.1.0 | dev constant in dev/test | AES-256-GCM key; 64 hex chars outside dev/test |
| `APP_SECRETS_DIR` (B) | no | v0.14.0 | unset (file provider off) | Directory for the file application-secret provider |
| `CONFIG_FILE_DIR` (B) | no | v0.14.0 | unset (file config provider off) | Directory for the file configuration provider |
| `CONFIG_PROVIDERS` (B) | no | v0.14.0 | hosting profile provider | Priority list of configuration providers (`environment,file,database,bunyip`); used by the operator subcommands |
| `BUNYIP_CONFIG_URL` (B) | no | v0.14.0 | unset | Base URL for the Bunyip configuration provider |
| `BUNYIP_CONFIG_CLIENT_ID` (B) | no | v0.14.0 | unset | Machine client id for that provider |
| `BUNYIP_CONFIG_CLIENT_SECRET` (B) | no | v0.14.0 | unset | Machine client secret for that provider |
| `AUTH_PROVIDERS` (B) | no | v0.14.0 | profile (`bunyip,local` saas; `local` self-hosted) | Authentication provider priority list |
| `ENVIRONMENT` | no | v0.1.0 | `development` | Dev/test vs enforced environment |
| `HOST` | no | v0.1.0 | `0.0.0.0` | Listen address |
| `PORT` | no | v0.1.0 | `8080` (also on parse failure) | Listen port |
| `BASE_URL` | yes (from v0.14.0) | v0.1.0 | `http://localhost:8080` | Base of platform-owned emailed links |
| `RUN_MIGRATIONS` | no | v0.1.0 | `true` (also on parse failure) | Apply pending migrations at start |
| `JWT_SECRET` | yes (from v0.4.0) | v0.1.0 | dev constant in dev/test | HS256 session signing key, >= 32 bytes outside dev/test |
| `BUNYIP_WEBHOOK_SECRET` | yes | v0.6.0 | dev constant in dev/test | Shared HMAC secret for Bunyip webhooks |
| `CLIENT_ORIGIN` | yes (from v0.14.0) | v0.2.0 | `http://localhost:4301` | Browser origin of the client; CORS default and OAuth popup origin |
| `CORS_ORIGIN` | no | v0.2.0 | `[CLIENT_ORIGIN]` | Comma-separated CORS allow-list; invalid entry panics at router build |
| `PORTAL_COOKIE_DOMAIN` | no | v0.19.0 | unset (host-scoped cookie) | `Domain=` for the contact-portal refresh cookie |
| `SPA_BASE_URL` | yes (from v0.14.0) | v0.12.0 | `CLIENT_ORIGIN` | Base for emailed links to SPA-only pages |
| `PUBLIC_API_BASE_URL` | no | v0.12.0 | unset (logo omitted from request-form email) | Public API base used to absolutize the tenant logo |
| `ABUSE_CONTACT_EMAIL` | no | v0.12.0 | unset (line omitted) | Report-abuse address in request-form email |
| `MOKOSH_MAX_TENANTS` | no | v0.14.0 | unset (uncapped; `<=0` or unparseable also uncapped) | Cap on tenants a super-admin can create; 409 at the cap |
| `MOKOSH_UPDATE_CHECK_URL` | no | v0.3.0 | unset (check disabled) | Manifest URL for `/version/check` |
| `MAIL_PROVIDER` | no | v0.14.0 | `smtp` if `SMTP_HOST` set, else profile (`log`/`smtp`) | `log`, `smtp` or `bunyip` |
| `SMTP_HOST` | no | v0.2.0 | unset (LogMailer) | SMTP relay host (admin email settings override per field) |
| `SMTP_PORT` | no | v0.2.0 | `587` | SMTP relay port |
| `SMTP_USERNAME` | no | v0.2.0 | unset | SMTP login (without `SMTP_PASSWORD` fails startup) |
| `SMTP_PASSWORD` | no | v0.2.0 | n/a | Governed application-tier secret, not a plain variable |
| `SMTP_FROM` | no | v0.2.0 | unset | Sender mailbox |
| `SMTP_TLS` | no | v0.2.0 | `starttls` | `none`, `starttls`, `implicit` |
| `BUNYIP_MAILER_URL` | no | v0.16.0 | unset | Bunyip mailer relay base URL (`MAIL_PROVIDER=bunyip`) |
| `BUNYIP_MAILER_CLIENT_ID` | no | v0.16.0 | unset | Basic credential id for the relay |
| `BUNYIP_MAILER_CLIENT_SECRET` | no | v0.16.0 | unset | Basic credential secret for the relay |
| `OIDC_ISSUER` | no | v0.3.0 | unset (Bunyip sign-in off) | Expected token issuer |
| `OIDC_AUDIENCE` | no | v0.3.0 | unset (Bunyip sign-in off) | Expected audience |
| `OIDC_JWKS_CACHE_TTL_SECS` | no | v0.3.0 | `600` (also on parse failure) | JWKS cache lifetime |
| `OIDC_LEEWAY_SECONDS` | no | v0.3.0 | `30` (also on parse failure) | Token clock leeway |
| `OIDC_DEFAULT_TENANT_ID` | no | v0.3.0 | tenant `00000000-0000-0000-0000-000000000001` (also on parse failure) | Landing tenant for a newly provisioned Bunyip user |
| `OIDC_BACKCHANNEL_CLIENT_ID` | no | v0.15.0 | unset (every logout token refused) | Client id logout tokens are addressed to |
| `ADMIN_EMAIL` | no | v0.1.0 | unset (skip) | First-run super-admin email |
| `ADMIN_PASSWORD` | no | v0.1.0 | unset (skip) | First-run super-admin password |
| `LOGIN_APPROVAL_ENABLED` | no | v0.8.0 | `false` | Suspicious-login notify-and-approve gate |
| `ALLOW_UNINVITED_BUNYIP_SIGNUP` | no | v0.16.0 | `false` | Allow verified-email Bunyip identity to provision a personal tenant |
| `BUNYIP_STATUS_CLIENT_ID` | no | v0.14.0 | unset | Basic credential id for the provider-status aggregator |
| `BUNYIP_STATUS_CLIENT_SECRET` | no | v0.14.0 | unset | Matching secret (constant-time compare) |
| `BUNYIP_API_BASE_URL` | no | v0.16.0 | unset | Bunyip API base for invitee lookup |
| `BUNYIP_DIRECTORY_CLIENT_ID` | no | v0.16.0 | unset | Basic credential id for `/v1/users/lookup` (all three or none) |
| `BUNYIP_DIRECTORY_CLIENT_SECRET` | no | v0.16.0 | unset | Matching secret |
| `ORGANIZATIONS_ENABLED` | no | v0.14.0 | profile (self-hosted `false`, saas `true`) | Organizations feature flag |
| `IP2LOCATION_DB_PATH` | no | v0.7.0 | unset (country lookup off) | IP2Location BIN for login-location alerts |
| `IP2PROXY_DB_PATH` | no | v0.11.0 | unset (enrichment off) | IP2Proxy BIN for ASN/VPN enrichment |
| `TRUSTED_PROXY_CIDR` | no | v0.7.0 | loopback plus private ranges (list in Utilities) | CIDRs whose `X-Forwarded-For` is trusted |
| `OUTBOUND_PRIVATE_ALLOWLIST` | no | v0.14.0 | unset (all private targets refused) | Hosts, IPs, CIDRs exempt from the outbound-URL guard |
| `INFISICAL_ADDRESS` | no | v0.12.0 | unset (probe `skipped`; Infisical app-secret provider not built) | Infisical base URL |
| `STRIPE_API_BASE` | no | v0.10.0 | `https://api.stripe.com` | Stripe REST base (test override) |
| `PAYPAL_API_BASE` | no | v0.14.0 | PayPal live or sandbox host | PayPal REST base (test override) |
| `ATTACHMENT_MAX_BYTES` | no | v0.4.0 | 25 MiB | Ticket attachment cap |
| `KB_ATTACHMENT_MAX_BYTES` | no | v0.14.0 | 5 MiB | KB embedded image cap |
| `TENANT_LOGO_MAX_BYTES` | no | v0.12.0 | 1 MiB | Tenant logo cap |
| `BRANDING_TENANT_FAVICON_MAX_BYTES` | no | v0.14.0 | 512 KiB | Tenant favicon cap |
| `BRANDING_TENANT_BACKGROUND_MAX_BYTES` | no | v0.14.0 | 2 MiB | Tenant sign-in background cap |
| `BRANDING_COMPANY_LOGO_MAX_BYTES` | no | v0.14.0 | 1 MiB | Company logo cap |
| `BRANDING_COMPANY_FAVICON_MAX_BYTES` | no | v0.14.0 | 512 KiB | Company favicon cap |
| `BRANDING_COMPANY_BACKGROUND_MAX_BYTES` | no | v0.14.0 | 2 MiB | Company background cap |
| `MOKOSH_SEED_TENANT_ID` | no | v0.3.0 | migration seed tenant | Template tenant the demo seed copies from; non-UUID fails startup (per [configuration](configuration.md); reader `src/modules/tenants/service.rs`) |
| `MOKOSH_DEMO_SEED` | no | v0.3.0 | off outside production; production always seeds | Demo-data seeding override (`src/modules/seed/service.rs`) |

**Read outside the registry** (`src/config/variables.toml`; bootstrap or provider-of-record reads)

| Name | Required | Since | Default | Purpose |
|---|---|---|---|---|
| `MOKOSH_DEPLOYMENT_MODE` | yes | v0.14.0 | blank = self-hosted in dev/test | `self-hosted` or `saas`; selects hosting profile |
| `CONFIG_BACKEND` | no | v0.14.0 | `environment` | Single-provider configuration slot; only `environment` accepted |
| `SECRET_BACKEND` | no | v0.14.0 | profile (`database`) | Tenant-tier secret provider (`database`, `infisical`) |
| `APP_SECRET_BACKEND` | no | v0.16.0 | profile (`database`) | Application-tier provider (`environment`, `file`, `database`, `infisical`, `bunyip`) |
| `BUNYIP_SECRETS_URL` | no | v0.18.0 | unset | Bunyip host-secrets base URL (set with the next two or none) |
| `BUNYIP_SECRETS_CLIENT_ID` | no | v0.18.0 | unset | Basic credential id |
| `BUNYIP_SECRETS_CLIENT_SECRET` | no | v0.18.0 | unset | Basic credential secret |
| `GOOGLE_CONTACTS_CLIENT_ID` / `_SECRET` | no | v0.14.0 | unset (import off) | Governed secrets; one half set is a boot error |
| `MICROSOFT_CONTACTS_CLIENT_ID` / `_SECRET` | no | v0.17.0 | unset (import off) | Governed secrets |
| `XERO_CLIENT_ID` / `_SECRET`, `XERO_WEBHOOK_KEY` | no | v0.17.0 | unset (feature off; deliveries refused) | Governed secrets for delegated invoice issuing |
| `QUICKBOOKS_CLIENT_ID` / `_SECRET`, `QUICKBOOKS_VERIFIER_TOKEN` | no | v0.17.0 | unset | Governed secrets for delegated invoice issuing |
| `MOKOSH_ADMIN_DATABASE_URL` | no | v0.4.0 | unset | Privileged URL used once to create roles |
| `MOKOSH_MIGRATOR_PASSWORD` | no | v0.3.0 | unset | Password for `mokosh_migrator` when provisioned |
| `MOKOSH_APP_PASSWORD` | no | v0.3.0 | unset | Password for `mokosh_app` (reconciled at boot when it drifts) |
| `INFISICAL_PROJECT_ID`, `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET` | no | v0.1.0 | unset | Infisical machine identity |
| `INFISICAL_ENVIRONMENT` | no | v0.1.0 | `dev` | Infisical environment slug |
| `STORAGE_PROVIDER` | no | v0.15.0 | profile (`local`) | `local` or `s3` |
| `STORAGE_ROOT` | no | v0.15.0 | `./attachments` | Root for the local provider |
| `STORAGE_S3_ENDPOINT` | no | v0.15.0 | unset | S3-compatible endpoint (required with `s3`) |
| `STORAGE_S3_BUCKET` | no | v0.15.0 | unset | Bucket (required with `s3`) |
| `STORAGE_S3_REGION` | no | v0.15.0 | `us-east-1` | Signing region |
| `STORAGE_S3_PATH_STYLE` | no | v0.15.0 | `true` | `false` selects virtual-hosted; non-bool errors |
| `STORAGE_S3_ACCESS_KEY_ID`, `STORAGE_S3_SECRET_ACCESS_KEY` | no | v0.15.0 | unset | S3 credentials (required with `s3`) |
| `STORAGE_BACKEND`, `ATTACHMENT_DIR`, `S3_ENDPOINT`, `S3_BUCKET`, `S3_REGION`, `S3_PATH_STYLE`, `S3_ACCESS_KEY_ID`, `S3_SECRET_ACCESS_KEY` | no | v0.4.0 to v0.14.0 | n/a | Pre-rename names; setting any refuses boot and names the replacement |
| `OAUTH_SUPER_ADMIN_EMAILS` and the three `GOOGLE_OAUTH_*` names | no | v0.2.0/v0.3.0 | n/a | Retired; marked `removed` v0.14.0 in `variables.toml`/[configuration](configuration.md); ignored |
| `RUST_LOG` | no | n/a | `info` | Tracing filter (read by `tracing_subscriber`; documented in [configuration](configuration.md)) |

Dev-stack-only variables (compose ports, `USER`, `MINIO_*`, `MOKOSH_PG_*`) are listed in [configuration](configuration.md#development-stack-variables).

### build, CI and release

**Toolchain.** Rust toolchain pinned by `rust-toolchain.toml` (1.98.1 per `CLAUDE.md`); edition 2021; workspace resolver 2. Task runner is `just`; shared recipes come from the `common` git submodule imported by `justfile` (`set allow-duplicate-recipes`, local definitions shadow imported ones). Scripts are Nushell under `scripts/` and `oci-build/get-tags.nu`.

**Justfile recipes** (from `just --list`, grouped):
- Gates: `check` (every `check.yml` step except the cargo test steps), `check-compile`, `check-clippy` (`-D warnings`), `check-fmt`, `check-build`, `check-docker` (OCI builder stage; not in `check`), `pre-commit` (fmt check plus tree-ownership), `pre-push` (fmt, clippy, compile, unit tests in the dev container), `install-hooks`.
- Repo guards: `check-migrations`, `check-migration-versions`, `check-migration-versions-against-base`, `check-migration-immutability`, `check-guarded-content-migrations`, `check-pool-safety`, `check-validate-parity`, `check-route-consumers`, `check-mail-copy`, `check-rate-limit-helper`, `check-runner-labels`, `check-oci-cache`, `check-oci-publish-tags`, `check-workspace-deps`, `check-unused-deps` (cargo-machete), `check-env-example`, `check-config-docs`, `check-config-doc-paths`, `check-doc-recipes`, `check-doc-links`, `check-claude-md`, `check-build-target-storage`, `check-justfile`, `check-tree-ownership`.
- Tests: `test` (unit: `cargo test --workspace --lib` family), `test-integration` (nextest, `ci` profile), `test-integration-unsupported`, `ensure-test-db-roles`, `verify-providers`, `verify-demo`, `test-e2e`.
- Build and run: `build` (release bins), `build-docker`, `build-docker-export`, `dev`, `dev-infisical`, `dev-s3`, `down`, `dev-clean`, `dev-clean-all`, `dev-local*`, `dev-logs`, `dev-seed-portal`, `infisical-bootstrap`, `migrate-run`, `migrate-create <name>`, `run`, `lint`, `typecheck`, `fmt`.
- Docs and release: `config-docs`, `config-since`, `config-release-notes`, `create-release <major|minor|hotfix>`; CI tooling `ci-log`, `ci-stalls`, `ci-stalls-self-test`, `job-metrics-report`.

**Workflows** (`.forgejo/workflows/`; runner labels come from repository variables, compiling jobs use the dev-image label):

| File | Trigger | Purpose |
|---|---|---|
| `check.yml` (Check) | pull request into `main` | Merge gate: all repo guard steps (migration prefix/immutability/base-ref, guarded content, mail copy, pool safety, validate parity, rate-limit helper, runner labels, OCI cache and publish tags, workspace deps, env parity, build target storage, documented recipes, config doc paths, configuration docs, link targets, CLAUDE.md budget, unused deps, route consumers), then fmt, clippy, compile, unit tests, doc tests; plus a `secrets` scan job using a shared action |
| `integration.yml` (Integration) | pull request into `main` | `build` job compiles one nextest archive; `test` matrix of 3 hash-partitioned shards each with a Postgres service, builds the template database and runs `--profile ci`; `summary` job is the single required check name |
| `integration-unsupported.yml` | weekly cron (Monday) and manual | Runs the suites the `ci` profile filters out (S3 storage against MinIO, Infisical Google-client suite) |
| `e2e.yml` (E2E) | push to `main`, pull request into `main`, manual (staging or production) | Playwright suite against a deployed staging instance; serialized by one concurrency group; deploy-sync wait on push, reachability check on PR |
| `build-oci-image.yml` | push to `main`, `v*` tags (path filtered to `src/`, `crates/`, `migrations/`, `.cargo/`, Cargo files, `oci-build/`), manual dry-run | Builds `oci-build/Dockerfile` with buildx and the Actions cache, pushes to the registry |
| `cache-warm.yml` | push to `main` | Compiles (no tests) what check and integration compile so later PR runs restore a warm cache |
| `post-merge-guards.yml` | push to `main` | Re-runs migration prefix uniqueness and immutability against the merged history; no cargo or docker |
| `create-release.yml` | closed (merged) PR from a `release/v*` branch into `main` | Calls the shared reusable workflow to create the release |
| `renovate.yml` | every 4 hours and manual | Dependency updates via a shared reusable workflow |

`main` branch protection requires `Check`, `E2E` and `Integration` pull-request checks ([ci-release invariants](invariants/ci-release.md#integration-required-pms-1426)).

**Images.** `Dockerfile` (repo root) is the development image: a glibc builder base, adds `pkg-config libssl-dev curl`, `CMD cargo run --bin mokosh-server`, source mounted by `compose.dev.yml`, exposes 8080. `oci-build/Dockerfile` is the release image: multi-stage; builder on a musl Alpine Rust image with `lld`, dependencies cached in their own layer from stub crates, git metadata passed as build args; runtime `alpine:3.23` with `ca-certificates tzdata gosu shadow`; copies `mokosh-server`, `mokosh-bootstrap`, `migrations/` and the Noto Sans licence; `appuser` uid 1001; `/app/attachments` pre-created and owned; `ENTRYPOINT gosu-entrypoint.sh /app/mokosh-server` (starts as root, remaps to `PUID`/`PGID` or volume owner, drops privileges; a compose `user:` pin disables the remap); `HEALTHCHECK` is `wget --spider http://localhost:8080/api/v1/health` every 30 s; exposes 8080. Publish tags are derived from the trigger by `oci-build/get-tags.nu`: `v*` tag -> `:vX.Y.Z` only, `main` push -> `:latest` only, push to a branch on `BRANCH_ALLOW_LIST` -> that branch's tag only, manual -> dry-run unless `dry_run=false`.

**Release process.** `just create-release <major|minor|hotfix>` (from `common`) bumps `Cargo.toml`, pushes `release/vX.Y.Z` and opens the PR. Merging it triggers `create-release.yml` (tag and release creation via the shared workflow) and the `v*` tag triggers `build-oci-image.yml` in release mode. Release notes carry the block printed by `just config-release-notes <version>`. Configuration changes are tracked per release in [configuration](configuration.md#recently-added). Details: [ci-release invariants](invariants/ci-release.md), [architecture](architecture.md#releases).

### testing

- **Unit tests**: inline `#[cfg(test)]` modules in `src/` (about 1,360 `#[test]`/`#[tokio::test]` attributes). Run by `just test` / `cargo test --workspace --lib`; doc tests run in `check.yml`. Several are repo guards that read the tree: `config::guard` (single env read path), `utils::net` (single `guard_outbound_url` definition), `storage` (tenant-first keys), `api::router` (no route overlap on the tickets attachments surface), `repo_hygiene` in `src/lib.rs` (a former repository name must not reappear), `.config/nextest.toml` filter complement check in `src/lib.rs`, `db::provision` (every migration table grants DML to `mokosh_app`).
- **Integration tests**: one test binary, `tests/all.rs`, which declares `mod common;` and `mod suites;`. `tests/suites/mod.rs` lists every suite as a module (about 265 files in `tests/suites/`; adding a suite means a file plus a line in `mod.rs`). Helpers in `tests/common/mod.rs` (`TestApp`, `boot`, `boot_rls` (app-role pool so RLS bites), `boot_with_bunyip`, `boot_with_google_client`, `seed_admin`, `seed_tenant_with_admin`, `login`, `platform_login`, seeding helpers, `storage_root`, `init_tracing`); fixtures in `tests/fixtures/` (CardDAV samples).
- **`#[mokosh_test]`** (`crates/mokosh-test-macros`, runtime in `crates/mokosh-test`): database-backed test attribute taking one `pool: PgPool` argument (about 1,770 uses in `tests/`; no `#[sqlx::test]` remains). One template database named by a digest of the embedded migration set is built once (session advisory lock, built under a `_building` name then renamed), and each test database is `CREATE DATABASE ... TEMPLATE` of it. The runtime is current-thread, the pool is closed with a 10 s timeout, the database is dropped on success and kept (name printed) on panic. Roles the migrations grant to must exist first (`just ensure-test-db-roles`).
- **Runner**: cargo-nextest only; the integration binary is not runnable under plain `cargo test` (process-global state). `.config/nextest.toml` profile `ci`: `default-filter` excludes the unsupported suites (`suites::s3_storage`, `suites::google_client_from_infisical`), `test-threads = 12`, `fail-fast = false`, slow-timeout 60 s terminating after 3 periods, one latency test takes all threads with `retries = 2`. Profile `unsupported` inherits `ci` with the complement filter. CI shards by `--partition hash:k/3`.
- **End to end**: `e2e/` is a Playwright project (TypeScript, Bun lockfile) with 23 files in `e2e/tests/` (auth, OIDC, contacts, billing, contracts, calendar, SLA, assets, knowledge base, notifications, projects, reports, RMM, settings, dispatch, audit, form validation, external-guard), helpers in `e2e/lib/`, gate scripts in `e2e/scripts/` (`wait-for-deploy.mjs`, `health-check.mjs`, `check-e2e-bootstrapped.mjs`). It runs against a deployed instance (staging by default), not a CI-built artifact; some specs are marked `test.fixme` in its README. `just test-e2e`. See [e2e](e2e.md).
- **Not unit tested by design**: static documentation files carry no test (repository rule).

### Workspace crates (`crates/`)

Root package `mokosh-server` is workspace member `.` with the three bins/libs below plus:

| Crate | Role |
|---|---|
| `crates/mokosh-types` | Shared wire-format DTOs between the server and the SPA (modules `auth`, `billing`, `contacts`, `datetime`, `forms`, `integrations`, `members`, `mileage_tracking`, `sort`, `teams`, `tenants`, `text`, `tickets`, `time_tracking`, `validation`); no database, network, axum or HTTP types |
| `crates/build-metadata` | Build-script helper `emit(".git")` exporting `MOKOSH_GIT_HASH`, `MOKOSH_GIT_DESCRIBE`, `MOKOSH_BUILD_DATE` |
| `crates/mokosh-test-macros` | Proc-macro crate exporting `#[mokosh_test]` |
| `crates/mokosh-test` | Runtime for `#[mokosh_test]` (template database management); re-exports the macro; dev-dependency of the root package only |

`[workspace.dependencies]` lists only crates that members inherit (`just check-workspace-deps`); `cargo machete` rejects unused dependencies (`just check-unused-deps`).


## 4. Identity, tenancy and access modules


All paths below are under `/api/v1` unless stated. Mounting is in `src/api/router.rs`: the staff plane is `/api/v1/*` behind `auth_middleware`; the contact plane is `/api/v1/contact/*`; unauthenticated routes are `/api/v1/public/*`; signed receivers are `/api/v1/bunyip/*`. Every `/api/v1` response passes `normalize_error_envelope` (errors are `{error:{code,message}}`) and `sanitize_json_body`. Pagination: `per_page` above 100 is rejected at parse time (`src/utils/pagination.rs`).

Auth gate vocabulary (defined in `src/modules/auth/middleware.rs`):

| Gate | Admits |
| --- | --- |
| `RequireAuth` | any authenticated staff principal (bunyip `at+jwt` bearer or legacy HS256 bearer), user active and tenant active |
| `RequireAdmin` / `RequireAdminUser` | roles `super_admin`, `admin` |
| `RequireManager` | `super_admin`, `admin`, `manager` |
| `RequireFinance` | `super_admin`, `admin`, `finance` |
| `RequireSuperAdmin` | `super_admin` only |
| `RequirePlatformAdmin` | a `typ="platform"` bearer for a `platform_admins` row with `status='active'` (`src/modules/platform/routes.rs`) |
| `TenantOrPlatformCaller` | platform bearer (any tenant) or a tenant user (own tenant only); `require_admin_write_access` additionally needs `role.is_admin()` for tenants (`src/modules/tenants/routes.rs`) |
| `DeploymentOperator` | platform bearer, or an admin of the system tenant `00000000-0000-0000-0000-000000000001` (`SYSTEM_TENANT_ID`) |
| `RequireContactAuth` | a `typ="contact"` bearer or the `mokosh:contact_token` cookie whose `sid` family is live (`src/modules/contact_portal/middleware.rs`) |
| module gates (`RequireBilling`, etc.) | authenticated + `module_config.is_enabled` for the tenant, else 404 (owned by other modules) |

### auth

**Purpose.** Staff authentication and session management (legacy HS256 path), the Bunyip resource-server path that places callers into tenants, MFA, personal API keys, staff user management, and the grant-invitation lifecycle for cross-account access. Contract: [identity invariants](invariants/identity-auth.md), [architecture: auth](architecture.md#auth-two-independent-mechanisms-pms-295), [first-run onboarding](first-run-onboarding.md).

**Data model** (`migrations/003_auth.sql` plus later ALTERs):
- `users`: `UNIQUE(tenant_id,email)`; `role` CHECK in `super_admin|admin|manager|technician|dispatcher|sales|finance` (default `technician`); `status` CHECK `active|inactive|pending`; `password_hash` nullable; `mfa_enabled`, `mfa_secret` (AES-256-GCM sealed), `mfa_recovery_codes_hashes TEXT[]`, `mfa_last_used_step`, `mfa_failed_attempts INT`, `mfa_locked_until` (084), `password_changed_at` (093), `deleted_at` tombstone (087), `last_login_country`, `login_location_alerts` default TRUE (089), `profile_completed_at` (046), `theme_base_mode` CHECK `light|dark|system` (054), `theme_accent_id` <= 32 chars, `date_format_string` <= 64 chars (037), `bunyip_user_id` with `UNIQUE(bunyip_user_id,tenant_id)` (226).
- `identities` (157): one row per lower(email) (`UNIQUE` on `lower(email)`), cross-tenant human profile; `status` CHECK `active|inactive`. `tenant_memberships` (157, RLS added by 195): `UNIQUE(identity_id,tenant_id)`, same role CHECK as `users`. `users` mirrors to `identities` one way ([mirror rule](invariants/identity-auth.md#identity-mirror-pms-1120)); `mfa_secret` and `password_hash` are outside the mirror.
- `user_sessions` (`token_hash` = SHA-256 of an opaque value, `expires_at`, `ip_address`, `user_agent`), `password_reset_tokens` (`token_hash` Argon2, `lookup_hash` SHA-256 added by 234, `expires_at`, `used_at`), `api_keys` (`key_prefix` 10 chars, `key_hash` Argon2, `scopes` JSONB default `["*"]`, `expires_at`, `is_active`), `login_approvals` (`code_hash`, `attempts`, `expires_at`, `consumed_at`, RLS), `user_login_devices` (`UNIQUE(tenant_id,user_id,device_hash)`, RLS), `user_oauth_identities` (table kept, no mounted route).
- `mokosh_bunyip_grants` (225, 236, 245, 269; RLS-exempt): `UNIQUE(grantee_bunyip_user_id,mokosh_account_id)` where `mokosh_account_id` is a tenant slug; `role` CHECK `admin|manager|technician|finance|read_only` and non-NULL exactly while `revoked_at IS NULL`; `event_at` (newest-event watermark), `revoked_by` CHECK `owner|grantee|system`, `grantee_email`.
- `mokosh_grant_invitations` (267): `status` CHECK `pending|accepted|declined|canceled|expired` with terminal-timestamp CHECKs; `accept_token_hash` Argon2; partial `UNIQUE(tenant_id, lower(invitee_email)) WHERE status='pending'`; `role` CHECK `admin|manager|technician|finance|read_only`; inviter cannot equal invitee. No RLS (allowlisted in `tests/suites/rls_coverage.rs`); scope is pinned in WHERE clauses.

**API** (`src/modules/auth/routes.rs`, `grant_invitations_routes.rs`, `my_grants.rs`, `bunyip_webhook.rs`, `backchannel_logout.rs`):

| Method | Path | Auth gate | Purpose |
| --- | --- | --- | --- |
| POST | `/auth/login` | public, per-(IP,email) limiter | Password login. With `tenant_id`/`tenant_slug` runs tenant-scoped `AuthService::login`; without one runs identity-first flow (auto-scope, `needs_selection`, or `needs_setup`) |
| POST | `/auth/select-tenant` | public (carries 5-minute `typ="identity"` token) | Finish a `needs_selection` login |
| POST | `/auth/switch-tenant/{tenant_id}` | `RequireAuthState` + active membership | Re-mint tokens scoped to another membership |
| POST | `/auth/logout` | `RequireAuth` | Delete the caller's session row |
| POST | `/auth/logout-all` | `RequireAuth` | Delete every session row of the user |
| POST | `/auth/refresh` | public (refresh token) | Rotate access and refresh tokens |
| POST | `/auth/forgot-password` | public, per-(IP,email) limiter | Email a reset link; always 200 |
| POST | `/auth/reset-password` | public (token) | Redeem a reset or welcome token |
| GET | `/auth/set-password/context/{token}` | public (token) | Client name for the set-password page; 404 on unknown or expired |
| GET, PUT | `/auth/me` | `RequireAuth` | Read and update own profile (cannot change own role or status) |
| GET | `/auth/memberships` | `RequireAuthState` | Active memberships of the identity |
| POST | `/auth/me/complete-onboarding` | `RequireAuth` | Mark profile complete |
| PUT | `/auth/me/password` | `RequireAuth` + reauth limiter | Change password |
| GET | `/auth/me/sessions` | `RequireAuth` | List own sessions |
| DELETE | `/auth/me/sessions/{session_id}` | `RequireAuth` | Revoke one own session |
| POST | `/auth/me/mfa/setup` | `RequireAuth` | Stage a TOTP secret |
| POST | `/auth/me/mfa/enable` | `RequireAuth` | Verify code, enable, return recovery codes once |
| POST | `/auth/me/mfa/disable` | `RequireAuth` + reauth limiter | Disable MFA (current password required) |
| GET, POST | `/auth/me/api-keys` | `RequireAuth` | List, create personal API keys |
| DELETE | `/auth/me/api-keys/{key_id}` | `RequireAuth` | Revoke a key |
| GET | `/auth/directory` | `RequireAuth` | Staff directory projection for @mentions (any tenant user) |
| GET | `/auth/users` | `RequireManager` | List users (filters validated) |
| POST | `/auth/users` | `RequireAuth` + `role.is_admin()` + `can_grant(role)` | Create user |
| GET | `/auth/users/{user_id}` | `RequireAuth`; admin or self | Read user |
| PUT | `/auth/users/{user_id}` | `RequireAuth` + `role.is_admin()` + `can_grant(role)` | Update user |
| POST | `/grants/invitations` | `RequireAdminUser` | Create a pending grant invitation |
| GET | `/grants/invitations` | `RequireAdminUser` | Owner outbox |
| DELETE | `/grants/invitations/{id}` | `RequireAdminUser` | Cancel a pending invitation |
| GET | `/grants/invitations/by-token/{token}` | public (token is the credential), per-IP 30/min | Invitation metadata |
| POST | `/grants/invitations/by-token/{token}/accept` | `RequireAuth` handler gate, per-IP 30/min | Accept |
| POST | `/grants/invitations/by-token/{token}/decline` | `RequireAuth` handler gate, per-IP 30/min | Decline |
| GET | `/my-grants/invitations` | `RequireAuth` | Grantee inbox (cross-tenant) |
| POST | `/my-grants/invitations/{id}/accept`, `/{id}/decline` | `RequireAuth` | Accept or decline by id |
| DELETE | `/my-grants/{id}` | `RequireAuth` | Grantee leaves an account; 204 also on replay, 404 on another's id |
| POST | `/bunyip/webhooks/account-deleted` | signed webhook (`X-Webhook-Signature`, hex HMAC-SHA256 of the body keyed by `BUNYIP_WEBHOOK_SECRET`) | Tombstone the user |
| POST | `/bunyip/webhooks/mokosh-grant-changed` | signed webhook (same HMAC) | Mirror a grant grant/revoke into `mokosh_bunyip_grants` |
| POST | `/bunyip/oauth2/backchannel-logout` | logout token signed by the OP (form `logout_token`), mounted only when a verifier exists | Revoke a session `sid` |

**Behaviour.**
- Roles (`mokosh_types::auth::UserRole`): `super_admin` (rank 3), `admin` (2), `manager` (1), `technician`, `dispatcher`, `sales`, `finance` (0). `can_grant(target)` requires caller rank >= target rank, so only a `super_admin` creates or assigns `super_admin`. Invitable roles exclude `super_admin` (`src/modules/invitations/models.rs`).
- Legacy tokens: access JWT 1 hour, refresh 7 days (`AuthService::new`), JWT `iss`/`aud` both `mokosh-server`, access tokens require `typ="access"`. Session row lifetime 7 days, or 30 days with `remember_me`. Every access token names a `user_sessions` row in `sid`; a deleted row fails the next request. Identity token 5 minutes. A password change invalidates tokens issued before `password_changed_at`.
- Bunyip path: tokens verified against the issuer's JWKS (`OIDC_JWKS_CACHE_TTL_SECS` default 600, force refresh on `kid` miss with a 60 s cooldown, `OIDC_LEEWAY_SECONDS` default 30). The caller's tenant comes from membership state (pending invite for a verified email, else existing placement, else a new `personal` tenant), never from a claim. Any present `bunyip_role` yields `UserRole::Admin` (`effective_role_from_bunyip`, never `super_admin`). An identity with no placement and no pending invite is refused unless it is the platform admin (`bunyip_role="admin"`) or `ALLOW_UNINVITED_BUNYIP_SIGNUP` is on and the email is verified. A grant-carrying token resolves through `mokosh_bunyip_grants` (cache TTL 30 s, webhook invalidates); `map_grant_role` maps `read_only` to `Technician`. Principal gate on both paths: `users.status='active'` and `tenants.status='active'`.
- Login (tenant-scoped): tenant identifier mandatory (401 otherwise); local password refused with 403 when `deployment_mode` is `saas` AND the bunyip verifier is mounted. Per-(IP,email) limiter 20/min per IP and 5/min per email (in-memory, per process, keyed on the peer address); `/auth/forgot-password` 10/min per IP and 3/min per email; password re-auth on `/auth/me/password` and `/auth/me/mfa/disable` is a failure-counted limiter, 10/min per IP and 5/min per user. Over-quota answers 429 with `Retry-After`.
- MFA: TOTP RFC 6238 plus recovery codes (hashed, single use; a recovery code wins when both sent). Persistent lockout on failed second factor: none under 3 failures, then 30 s doubling per failure (3 -> 30 s, 4 -> 60 s, 5 -> 120 s) capped at 3600 s at 10+; stored in `users.mfa_failed_attempts` and `mfa_locked_until`, answered 429 with `Retry-After`. Setup, enable and disable require the current password. There is no password-failure lockout on the staff plane beyond the rate limiter.
- Login approval (`LOGIN_APPROVAL_ENABLED`, default off): new country (needs `IP2LOCATION_DB_PATH`) or new `device_id` withholds the session and emails a 6-digit code valid 15 minutes, max 5 attempts, newest challenge supersedes older ones. New-country alert mail is sent unless `login_location_alerts` is false. See [login approval](invariants/identity-auth.md#login-approval-pms-658).
- Password rules (staff DTOs): `new_password` >= 8 characters and must match `confirm_password`. Reset tokens are `{user_id}.{secret}`, 24 hours; welcome tokens (create user with `send_welcome_email`) 7 days; both single use, Argon2 plus SHA-256 lookup hash. No reset or welcome mail is sent when local password auth is closed (PMS-904 behaviour in `AuthService::sends_local_account_email`).
- API keys: `generate_api_key` raw key shown once, 10-char prefix stored, Argon2 hash stored, create/revoke audited. Unverified: no code path that authenticates a request with an API key was found in `src` (only create, list, revoke exist).
- Grant invitations: TTL 7 days (`DEFAULT_TTL`), accept and decline gate on `status='pending' AND expires_at > NOW()`; accept registers the grant on Bunyip (SaaS mode) before the guarded local UPDATE, cancel and a lost-race accept revoke the Bunyip grant; invitee lookup on Bunyip when `BUNYIP_API_BASE_URL`, `BUNYIP_DIRECTORY_CLIENT_ID`, `BUNYIP_DIRECTORY_CLIENT_SECRET` are all set (all three or none). Contract: [grant invitations](invariants/identity-auth.md#grant-invitations-pms-1208).
- `mokosh-grant-changed` ordering: applies only when payload `at` is strictly newer than stored `event_at`; an `at` more than 5 minutes in the future is refused 400. `account-deleted`: sets `deleted_at`, rewrites email to `deleted-<uuid>@deleted.local`, deletes sessions, API keys and reset tokens, writes an audit row; idempotent; runs on the migrator pool.
- Back-channel logout: audience is `OIDC_BACKCHANNEL_CLIENT_ID` (unset refuses everything); `iat` must be within 300 s; revoked `sid` set is in memory, entries live 900 s, capped at 50,000, emptied on restart.
- Bootstrap: `maybe_bootstrap_admin` (`src/modules/auth/bootstrap.rs`) inserts a verified `platform_admins` row from `ADMIN_EMAIL` and `ADMIN_PASSWORD` only when `platform_admins` is empty (dev only; sign in at `/platform/login`). Doc discrepancy: `docs/first-run-onboarding.md` says it seeds a `super_admin` `users` row and logs in at `/api/v1/auth/login`. Doc discrepancy: `docs/first-run-onboarding.md` says the bunyip platform admin maps to `super_admin`; `effective_role_from_bunyip` in code returns `Admin`.
- Side effects: failed and successful logins write `audit_log` rows (entity type `auth`); the failed-login audit write is out of band and a commit failure is logged at error.

**Background jobs.** `grant_invitations_expiry_sweep`: every 3600 s, sets `pending` rows past `expires_at` to `expired` (migrator pool, cross-tenant), logs the count at info (`src/modules/auth/grant_invitations_worker.rs`).

**Config.** `JWT_SECRET`, `ENCRYPTION_KEY`, `BUNYIP_WEBHOOK_SECRET`, `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_JWKS_CACHE_TTL_SECS`, `OIDC_LEEWAY_SECONDS`, `OIDC_DEFAULT_TENANT_ID`, `OIDC_BACKCHANNEL_CLIENT_ID`, `AUTH_PROVIDERS` (bootstrap), `ALLOW_UNINVITED_BUNYIP_SIGNUP`, `LOGIN_APPROVAL_ENABLED`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `IP2LOCATION_DB_PATH`, `TRUSTED_PROXY_CIDR`, `SPA_BASE_URL`, `BUNYIP_API_BASE_URL`, `BUNYIP_DIRECTORY_CLIENT_ID`, `BUNYIP_DIRECTORY_CLIENT_SECRET`, `BUNYIP_STATUS_CLIENT_ID`, `BUNYIP_STATUS_CLIENT_SECRET` (all in `src/config/registry.rs`).

### contacts

**Purpose.** The staff-owned CRM: companies (clients, prospects, vendors, partners, the tenant's own company), contacts, sites, the company industry lookup, and the portal-access lifecycle of a contact. Contract: [contacts invariants](invariants/contacts.md).

**Data model.**
- `companies` (004 and later): `company_type` CHECK `client|prospect|vendor|partner|internal` (062); `status` CHECK `active|inactive|prospect`; `parent_company_id`; billing address columns; `default_billing_contact_id`, `default_technical_contact_id` (FK ON DELETE SET NULL); `tags TEXT[]`; `custom_fields JSONB`; `portal_enabled`; `portal_slug VARCHAR(32) UNIQUE` (167, legacy); `portal_id BIGINT UNIQUE` CHECK 100000000..999999999 (174); `branding JSONB` (182); `invoice_prefix VARCHAR(4)` from a restricted alphabet, unique per tenant (243); unique `(tenant_id, lower(btrim(name)))` for non-internal companies (062). `tenants.own_company_id` points at the `internal` company.
- `contacts` (004 and later): `company_id` nullable, FK ON DELETE SET NULL (060, 110) plus free-text `company_name`; `contact_type` CHECK `primary|technical|billing|other` (label only, grants nothing); `status` CHECK `active|inactive`; portal columns `is_portal_user`, `portal_password_hash`, `portal_role` CHECK `admin|user`, `portal_failed_login_count`, `portal_locked_until` (082), `portal_mfa_enabled`, `portal_mfa_secret` (sealed), `portal_mfa_recovery_codes_hashes` (137), `portal_last_login_country`, `portal_login_location_alerts` (138), `portal_tokens_valid_from` (112, retired model); `contacts.company_id` mirrors the primary `contact_companies` row.
- `contact_companies` (108, 109): `UNIQUE(contact_id,company_id)`, one primary per contact (partial unique index), `sort_order`. `contact_phones` (108): `phone_type` CHECK `mobile|work|home|fax|other`, one primary per contact. `sites` (004): per-company address, `is_primary`, lat/long. `company_industries` (086): per-tenant lookup, `UNIQUE(tenant_id, lower(name))`, `is_active`, seeded with a default list. `portal_access_requests` (214): `status` CHECK `open|granted|declined|withdrawn`, one open request per `(tenant_id,contact_id,area)`.
- All of these carry `tenant_isolation` RLS.

**API** (`src/modules/contacts/routes.rs`, nested at `/contacts`; the whole router is wrapped by `reject_contact_plane`, so a contact bearer gets 403):

| Method | Path | Auth gate | Purpose |
| --- | --- | --- | --- |
| GET, POST | `/contacts/companies` | `RequireAuth` | List (filter validated), create company |
| GET | `/contacts/companies/website-probe` | `RequireAuth`, 30 probes/min limiter | Resolve a company website (SSRF-guarded) |
| GET, PUT | `/contacts/companies/{company_id}` | `RequireAuth` | Read, update |
| DELETE | `/contacts/companies/{company_id}` | `RequireAuth` + `RequireManager` | Delete (refused while blockers exist) |
| GET | `/contacts/companies/{company_id}/deletion-preview` | `RequireAuth` | What a delete would block, unlink, remove |
| GET | `/contacts/companies/{company_id}/contacts`, `/sites` | `RequireAuth` | Children of a company |
| GET, POST | `/contacts/companies/{company_id}/portal-roles` | `RequireAdmin` | Company-scoped portal roles |
| GET, PUT, DELETE | `/contacts/companies/{company_id}/portal-roles/{role_id}` | `RequireAdmin` | One company-scoped role |
| GET, POST | `/contacts/contacts` | `RequireAuth` | List (filter validated), create contact |
| GET | `/contacts/contacts/field-values` | `RequireAuth` | Distinct title or department values for autocomplete |
| GET, PUT | `/contacts/contacts/{contact_id}` | `RequireAuth` | Read, update |
| DELETE | `/contacts/contacts/{contact_id}` | `RequireAuth` + `RequireManager` | Delete |
| GET | `/contacts/contacts/portal-roles` | `RequireManager` | Roles assignable to contacts |
| POST | `/contacts/contacts/{contact_id}/grant-portal-access` | `RequireManager` | Grant portal access with `role_ids`, mail setup link |
| POST | `/contacts/contacts/{contact_id}/resend-portal-invite` | `RequireManager` | New setup link (also the portal password reset) |
| POST | `/contacts/contacts/{contact_id}/revoke-portal-access` | `RequireManager` | Revoke access and sessions |
| GET, PUT | `/contacts/contacts/{contact_id}/portal-roles` | `RequireManager` | Read, replace role assignments |
| GET | `/contacts/contacts/{contact_id}/access-requests` | `RequireAuth` | Portal access requests of a contact |
| POST | `/contacts/contacts/access-requests/{request_id}/resolve` | `RequireManager` | Grant (assign built-in role) or decline |
| GET, POST | `/contacts/company-industries` | read `RequireAuth`; write `RequireAdmin` | Industry lookup |
| PUT, DELETE | `/contacts/company-industries/{id}` | `RequireAdmin` | Edit, delete industry |
| POST | `/contacts/sites` | `RequireAuth` | Create site |
| GET, PUT | `/contacts/sites/{site_id}` | `RequireAuth` | Read, update |
| DELETE | `/contacts/sites/{site_id}` | `RequireAuth` + `RequireManager` | Delete |

**Behaviour.**
- `grant_portal_access`: `role_ids` non-empty (field error), contact must have a `company_id`, company must not be the tenant's `own_company`, every role must be tenant-wide or scoped to the contact's company (otherwise one 400 shape that does not leak existence). Setup token TTL 72 hours (`PORTAL_SETUP_TOKEN_TTL_HOURS`), emailed by `send_setup_email` (unverified: the exact notification template or event name it dispatches). Doc discrepancy: `docs/architecture.md` states 24 hours.
- `revoke_portal_access`: deletes role assignments and pending setup tokens, sets `is_portal_user=false`, revokes live `contact_sessions`; keeps the password hash and the company slug.
- Company delete is blocked by `COMPANY_BLOCKERS`: invoices, payments, contracts, time entries, mileage entries (retained financial records), tickets (pre-flight count), assets, quotes, stored credentials; it unlinks contacts, projects, appointments, active timers, RMM device mappings; it removes sites, request-form links, contact-company links, portal exports, portal login intents, company-scoped portal roles. Refusal is 400 naming the blocker and suggesting archiving.
- Website probe: guard applied before connect and for each redirect; ports 80 and 443 only; at most 5 hops; 5 s per attempt; no body read; results cached 15 minutes.
- Billing contact: designating a billing contact assigns the built-in `Billing Contact` role if the contact is a portal user lacking `invoices:read`, in the same transaction, with an audit row (`src/modules/contacts/billing_contact.rs`).
- Mirror rule: any insert of a contact company/phone mirror writes `contact_companies`/`contact_phones` in the same transaction ([company mirror](invariants/contacts.md#company-mirror-pms-1069)).

**Background jobs.** none. One-off operator command: `mokosh-bootstrap normalize-company-industries` (`src/modules/contacts/industry_backfill.rs`).

**Config.** none read directly by this module (`SPA_BASE_URL` reaches it through the service builder).

### contact_portal

**Purpose.** The contact (customer) identity plane at `/api/v1/contact/*`: credential lifecycle, stateful sessions, MFA, self-service profile and branding, access requests, saved payment methods, dashboard. Fully separate from `users`. Contract: [architecture: contact plane](architecture.md#the-contact-plane-is-a-third-fully-separate-identity-plane).

**Data model.** `contact_sessions` (170, 194): `refresh_token_hash`, `expires_at`, `revoked_at`, `family_id NOT NULL` (first session of a rotation chain), `ip_address INET`. `portal_setup_tokens` (042, 234): `{contact_id}.{secret}`, Argon2 `token_hash`, `lookup_hash`, `expires_at`, `used_at`. `portal_login_intents` (172, 176): magic-link intents (`email`, `secret_hash`, `company_id`, `expires_at`, `used_at`). `contact_payment_methods` (218): `provider` CHECK `stripe|paypal`, `UNIQUE(tenant_id,provider,provider_pm_id)`, one default per contact, `exp_month` 1..12. Also present: `contact_notification_preferences` (149), `portal_exports`/`portal_delegations` (144), `portal_refresh_tokens` (135) and `portal_password_reset_tokens` (136) kept from the retired model. All RLS-forced by tenant.

**API** (`src/modules/contact_portal/routes.rs`; full path prefix `/api/v1/contact`). Dual-plane routes owned by other modules (tickets, invoices, quotes) are not listed here.

| Method | Path | Auth gate | Purpose |
| --- | --- | --- | --- |
| POST | `/contact/auth/login` | public | Login by `portal_id` (preferred) or `slug`, email, password, optional `mfa_code`/`recovery_code` |
| POST | `/contact/auth/refresh` | public (refresh token) | Rotate within the family |
| POST | `/contact/auth/logout` | public (refresh token) | Revoke the family |
| POST | `/contact/auth/set-password` | public (setup token), limiter 10/min per IP and 3/min per contact id | Redeem invite or reset: 204, then 410 on replay, 400 on expired or unknown |
| POST | `/contact/auth/login-link` | public | Request a magic link; always 204 |
| POST | `/contact/auth/login-link/redeem` | public | Redeem the link (MFA two-step) |
| GET, PUT | `/contact/auth/me` | `RequireContactAuth`; PUT needs `settings:manage_own` | Own profile |
| PUT | `/contact/auth/me/password` | `RequireContactAuth` + reauth limiter 10/min per IP, 5/min per contact | Change password, keeps own family |
| POST | `/contact/auth/me/mfa/setup`, `/enable`, `/disable` | `RequireContactAuth` + current password | TOTP enrolment |
| GET | `/contact/auth/me/sessions` | `RequireContactAuth` | One row per family |
| DELETE | `/contact/auth/me/sessions/{session_id}` | `RequireContactAuth` | Revoke another family; own family 400; foreign id 204 |
| GET, PATCH | `/contact/companies/self/branding` | `RequireContactAuth` + `settings:manage_company_branding` | Own company brand |
| POST | `/contact/access-requests` | `RequireContactAuth` | Ask the MSP for an area |
| GET | `/contact/dashboard/summary` | `RequireContactAuth` | Company-scoped counters and last 10 events |
| GET | `/contact/portal/{handle}/host` | public | Resolve a numeric Portal ID or legacy slug to tenant and branding hint |
| GET | `/contact/portal/{slug}/resolve-to-portal-id` | public | Legacy slug to Portal ID |
| GET, POST | `/contact/payment-methods` | `RequireContactAuth` + `payment_methods:manage_own` | List, start add (hosted provider page) |
| DELETE | `/contact/payment-methods/{id}` | same | Detach at provider then delete row |
| PUT | `/contact/payment-methods/{id}/default` | same | Set default |

**Behaviour.**
- Tokens: access JWT `typ="contact"` 15 minutes (the `caps` claim is dropped by the middleware; capabilities are read from the database on every request); refresh token 30 days, also set as cookie `mokosh:contact_token` (Max-Age 30 days); magic-link intent 15 minutes; selection token `typ="contact_login_select"` 5 minutes.
- Per-request checks: tenant active and `ensure_session_active` (a family with a live row is accepted; a family with none, or an unknown `sid`, is refused).
- Rotation: refresh marks the presented row superseded and mints a successor in the same family; a rotated token presented again revokes the family (after verifying the secret; a wrong secret is plain 401). Setting or resetting a password revokes every open session; changing it keeps the caller's family.
- Lockout: each wrong password or wrong second-factor code increments `portal_failed_login_count`; at 5 failures `portal_locked_until` = now + 5 minutes (constant window; later failures while the counter stays >= 5 re-arm it). Doc discrepancy: `docs/architecture.md` calls this the PMS-501 doubling schedule; `register_failed_login` is a constant 5-minute window.
- MFA: enforced on password login and on magic-link redeem when `portal_mfa_enabled`; response `mfa_required:true` with empty tokens when no code given; TOTP one step of skew; recovery code single use; secret staged by setup and only flipped on by enable after a live code.
- Password policy for set-password and change-password: 12-character minimum, zxcvbn score >= 3, common-password blocklist (`utils::password_policy`), context hints from the contact's name, tenant and email.
- Magic link request: silent-drop rate limits (always 204): 20 per IP per minute and 5 per email per 15 minutes.
- Audit: `audit_portal_event` writes `entity_type='portal_contact'`, `user_id` NULL, subtype in `new_values.event` (`portal.login`, `portal.login_failed`, `portal.mfa_failed`, `portal.login_link`, `portal.logout`, `portal.refresh_replay_detected`, `portal.refresh_refused_inactive`, `portal.setup_password`, `portal.password_changed`, `portal.mfa_setup_started`, `portal.mfa_enabled`, `portal.mfa_disabled`, `portal.session_revoked`); a failed audit write logs a warning and never changes the response.
- Forgot-password and reset-password endpoints do not exist; the MSP reissues the link ([MSP-owned reset](architecture.md#the-contact-plane-is-a-third-fully-separate-identity-plane)).
- Capability catalog (`capabilities.rs`, 26 strings): `tickets:{read,write,comment,reopen,attach_file,edit_own,request_approval}`, `invoices:{read,pay,pay_partial,download_pdf}`, `payment_methods:manage_own`, `quotes:{read,accept,download_pdf}`, `contracts:read`, `assets:{read,report_issue}`, `projects:read`, `kb:read`, `notifications:read`, `approvals:decide`, `settings:{manage_own,manage_company_branding}`, `contacts:{invite_sub_user,manage_sub_user}`. A route gates on `CallerContext::require_capability` (DB-loaded effective set).
- Payment methods: card data never reaches the server; add flow is a Stripe SetupIntent checkout session, row written by the provider webhook; remove detaches at the provider first.

**Background jobs.** none.

**Config.** `SPA_BASE_URL`, `JWT_SECRET`, `ENCRYPTION_KEY` (seals `portal_mfa_secret`), `PORTAL_COOKIE_DOMAIN`, `TRUSTED_PROXY_CIDR`, `IP2LOCATION_DB_PATH`.

### portal_roles

**Purpose.** MSP-admin CRUD of contact-plane roles (named capability sets), tenant-wide or scoped to one company.

**Data model.** `portal_roles` (168, 177, 239): `name VARCHAR(80)`, `capabilities TEXT[]`, `is_builtin`, nullable `company_id` (FK CASCADE), `builtin_key` (`billing_contact|support_contact|read_only`); unique `(tenant_id, lower(name))` for tenant-wide rows and `(tenant_id, company_id, lower(name))` for scoped rows; unique `builtin_key` per scope. `contact_role_assignments` (169): PK `(contact_id, role_id)`, both FK CASCADE. Built-in roles: Billing Contact (10 capabilities incl. `invoices:read/pay/pay_partial/download_pdf`, `quotes:read/accept/download_pdf`, `payment_methods:manage_own`), Support Contact (12 incl. `tickets:*` basics, `approvals:decide`), Read-Only (8 `*:read` capabilities); seeded per new tenant by `TenantService::seed_builtin_portal_roles`.

**API** (`src/modules/portal_roles/routes.rs`, nested at `/portal-roles`; all `RequireAdmin`):

| Method | Path | Auth gate | Purpose |
| --- | --- | --- | --- |
| GET, POST | `/portal-roles` | `RequireAdmin` | List with contact counts, create |
| GET | `/portal-roles/capabilities` | `RequireAdmin` | Capability catalog |
| GET, PUT, DELETE | `/portal-roles/{id}` | `RequireAdmin` | Read, update, delete |

The company-scoped surface is `/contacts/companies/{company_id}/portal-roles[/{role_id}]` (see contacts).

**Behaviour.** Name trimmed, 1..64 characters; capabilities non-empty and each must be in `ALL_CAPABILITIES` (400 `Unknown capability`); built-in roles cannot have capabilities changed or be deleted (400); duplicate name is 409; deleting a role held by any contact is 409 with the count. Mutations are audited.

**Background jobs.** none. **Config.** none.

### contact_sync

**Purpose.** One-way import of contacts into the CRM from Google Contacts, Microsoft 365, iCloud (CardDAV) or an uploaded `.vcf` file. Nothing is written back (Google scope is `contacts.readonly`). Contract: [sync labels and contact-sync home](invariants/contacts.md#sync-labels-psa-70-e-pms-1358).

**Data model** (220, 221, 227, 228, 229, 238, 254, 276; RLS on all tenant tables):
- `contact_sync_connections`: `provider` CHECK `google|vcard|icloud|microsoft`; one live row per `(tenant_id,provider)` (partial unique on `disconnected_at IS NULL`); `sync_interval_minutes` default 60, CHECK >= 5; `sync_status` CHECK `never|in_progress|success|failed|throttled|reconnect_required`; `sync_token`; `selected_groups JSONB` (the import filter); `consecutive_failures`, `failure_notified_at`.
- `contact_sync_links`: `(connection_id, external_id)` unique while not unlinked; `origin` CHECK `created|linked`; `unlink_reason` CHECK `unlinked|disconnected`; `deleted_in_source_at`; `suggested_company_id`; `import_file_id`.
- `contact_sync_candidates` (review queue): `match_reason` CHECK `email_ambiguous|phone|name_company`; `status` CHECK `open|linked|created|skipped`; `source_snapshot JSONB`.
- `contact_sync_runs` (queue): `trigger` CHECK `initial|manual|scheduled`; `status` CHECK `queued|running|completed|failed|cancelled`; counters (`processed`, `created`, `linked`, `updated`, `queued_for_review`, `skipped`, `deleted_in_source`, `failed_records`), `failures JSONB`, `cursor`, `not_before`, `heartbeat_at`, `cancel_requested_at`; at most one `queued|running` run per connection (partial unique).
- `contact_field_locks` (`UNIQUE(contact_id,field)`: an edit in Mokosh locks the field against the source), `contact_sync_suppressions` (SHA-256 of external id, reason `data_removed`), `contact_sync_oauth_states` (single-use state, PKCE `code_verifier`, `expires_at`), `contact_import_files` (held upload metadata, `expires_at`, `discarded_at`).
- Unverified: migration 221 constrains `contact_sync_oauth_states.provider` to `('google')` and no later migration alters that constraint, yet `src/modules/contact_sync/service.rs` inserts provider `microsoft` into it; whether the Microsoft connect INSERT succeeds was not run.

**API** (`src/modules/contact_sync/routes.rs`):

| Method | Path | Auth gate | Purpose |
| --- | --- | --- | --- |
| GET | `/integrations/contact-sync` | `RequireAuth` | Connection status for the settings card |
| POST | `/integrations/contact-sync/google/authorize` | `RequireAdmin` | Start Google OAuth (returns consent URL) |
| POST | `/integrations/contact-sync/google/disconnect` | `RequireAdmin` | Disconnect |
| POST | `/integrations/contact-sync/microsoft/authorize`, `/microsoft/disconnect` | `RequireAdmin` | Microsoft 365 connect and disconnect |
| POST | `/integrations/contact-sync/icloud/connect`, `/icloud/disconnect` | `RequireAdmin` | iCloud (Apple ID plus app-specific password) |
| PUT | `/integrations/contact-sync/selection` | `RequireAdmin` | Choose labels (blank selection refuses to import); `provider` query param, default `google` |
| PUT | `/integrations/contact-sync/schedule` | `RequireAdmin` | Set `sync_interval_minutes`, 5 to 1440 |
| POST | `/integrations/contact-sync/preview` | `RequireAdmin` | Preview and list source labels |
| GET, POST | `/integrations/contact-sync/runs` | GET `RequireAuth`; POST `RequireAdmin` | List runs, queue a run (202) |
| GET | `/integrations/contact-sync/runs/{run_id}` | `RequireAuth` | Run progress |
| POST | `/integrations/contact-sync/runs/{run_id}/cancel` | `RequireAdmin` | Cancel |
| GET | `/integrations/contact-sync/review-queue` | `RequireAuth` | Open candidates |
| POST | `/integrations/contact-sync/review-queue/resolve` | `RequireAuth` | Link, create or skip a candidate |
| GET, POST | `/integrations/contact-sync/vcard/uploads` | `RequireAdmin` | List recent uploads, upload `.vcf` (body limit from the reader's cap) |
| POST | `/integrations/contact-sync/vcard/uploads/{file_id}/preview`, `/import` | `RequireAdmin` | Preview with chosen categories, import |
| GET | `/contacts/contacts/{contact_id}/sync` | `RequireAuth` | Provenance and locks |
| DELETE | `/contacts/contacts/{contact_id}/sync/locks/{field}` | `RequireManager` | Release a field lock |
| POST | `/contacts/contacts/{contact_id}/sync/unlink` | `RequireAuth` | Unlink contact from source |
| POST | `/contacts/contacts/{contact_id}/sync/remove-imported-data` | `RequireAdmin` | Delete an imported person (reason required) |
| GET | `/public/contact-sync/google/callback` | public (single-use `state`) | OAuth redirect; always redirects to the SPA |
| GET | `/public/contact-sync/microsoft/callback` | public (single-use `state`) | Entra redirect; always redirects to the SPA |

**Behaviour.**
- OAuth state TTL 10 minutes, PKCE, stored hashed. Google scopes `contacts.readonly openid email`; client id and secret are deployment-wide governed secrets (set via the settings route owned by another module), not per tenant.
- Import filter: records carrying none of the selected labels are not imported (`NotSelected`); a record present in a full read counts as seen even when filtered; absent-from-full-read means deleted-in-source. Matching reasons: ambiguous email, phone, name plus company, routed to the review queue.
- Run tick (below): recover `running` rows with heartbeat older than 30 minutes back to `queued`; schedule a run for each live connection with a selection past its interval and no active run (a `reconnect_required` connection is skipped); claim up to 5 queued runs oldest first with `FOR UPDATE SKIP LOCKED`. Rate-limited runs return to `queued` with `not_before` and the connection reads `throttled`. Google page size 1000, max 1000 pages, backoff base 1 s capped 32 s. Up to 50 failures are recorded per run; records are processed in chunks of 25.
- Failure streak: after 3 consecutive failed runs (or at once on a revoked grant) the `contact_sync.failing` notification is dispatched once per streak. A `vcard` run is never scheduled, has no streak, and the held upload is discarded at run end; uploads are held 24 hours.
- Provider on/off switches live in the integrations module; a cancelled run names the provider switch.

**Background jobs.** `ContactSyncRunner` (`src/modules/contact_sync/runs.rs`): every 60 s via `register_wakeable` (also woken when a run is queued); recovers stale runs, schedules due connections, runs up to 5 queued runs, discards expired uploads. One-shot at process start: `ClientSecretCleanup` (removes legacy per-tenant Google client secrets from the secret provider).

**Config.** Governed secrets `GoogleContactsClientId`/`GoogleContactsClientSecret` (via `SECRET_BACKEND`), `SPA_BASE_URL`, `PUBLIC_API_BASE_URL` (callback URL), `OUTBOUND_PRIVATE_ALLOWLIST`; upload cap from `crate::utils::upload_limits` (reader's own cap).

### invitations

**Purpose.** Tenant invitations: an admin invites an email to join the tenant with a role (and optional team); consumed on the invitee's first verified Bunyip login.

**Data model.** `tenant_invitations` (035, 211): `role` CHECK `admin|manager|technician|dispatcher|sales|finance`; `status` CHECK `pending|accepted|revoked`; `expires_at`; `invited_by`, `accepted_by`; `team_id` (FK ON DELETE SET NULL); partial unique `(tenant_id, lower(email)) WHERE status='pending'`. RLS enforced; `newest_pending_for` reads across tenants on the migrator pool for the pre-session login path.

**API** (`src/modules/invitations/routes.rs`; merged at `/api/v1`):

| Method | Path | Auth gate | Purpose |
| --- | --- | --- | --- |
| GET | `/invitations` | `RequireAuth` + `RequireAdmin` | List pending (paginated) |
| POST | `/invitations` | `RequireAuth` + `RequireAdmin` | Create or refresh an invite |
| DELETE | `/invitations/{id}` | `RequireAuth` + `RequireAdmin` | Revoke |

**Behaviour.** TTL 14 days (`INVITE_TTL_DAYS`). `role` defaults to `admin`, must be in `INVITABLE_ROLES` (no `super_admin`). `team_id` must belong to the same tenant (422 field error). Re-inviting a pending email upserts role, inviter, expiry and team. First invite promotes a `personal` tenant to `org` and starts the timesheets module default. Mail goes through the `invitations.created` dispatcher event after commit; a dispatch failure leaves the invite and logs a warning. Acceptance (`accept`) marks the invite and inserts the `team_members` row in one transaction; only a verified email consumes an invite.

**Background jobs.** none. **Config.** `SPA_BASE_URL` (invite link).

### members

**Purpose.** One reader merging native `users` with active cross-account grantees from `mokosh_bunyip_grants` for the "who has access" page.

**Data model.** No tables of its own; reads `users`, `mokosh_bunyip_grants`, `team_members`.

**API** (`src/modules/members/routes.rs`):

| Method | Path | Auth gate | Purpose |
| --- | --- | --- | --- |
| GET | `/members` | `RequireManager` | Merged, sorted, paginated members |

**Behaviour.** Filters: `q` (case-insensitive substring over email and names, max 200 chars), `role`, `kind` in `user|guest|everyone` (default `everyone`), `team_id` (unplaced guests excluded when set); bad enum literals are 422. Sort is fixed `(last_name, first_name, email)`; a `sort` query parameter is rejected. A placed grantee collapses to one `User` row with `placed_by_grant_id`; a grant with no users row is an `UnplacedGuest`. Standalone-mode implementation only (reads the local grant mirror).

**Background jobs.** none. **Config.** none.

### tenants

**Purpose.** Tenant provisioning and administration (organisations), tenant profile and logo, per-tenant module configuration. Multi-tenant is a default Cargo feature (`default = ["multi-tenant","server"]`); the `/tenants` mount exists only with that feature.

**Data model.** `tenants` (002, 019, 036, 062): `slug UNIQUE`, `status` CHECK `active|suspended|cancelled`, `kind` CHECK `personal|org` (no default), `personal_owner_id` (unique when set), `own_company_id`, `branding JSONB` (PATCH document; keys limited to `KNOWN_KEYS` in `src/modules/tenants/branding.rs`), `settings JSONB`, billing and subscription columns. RLS-exempt root table. `tenant_settings` (017, `UNIQUE(tenant_id,category,key)`), `module_config` (017, `UNIQUE(tenant_id,module_name)`, `is_enabled` default FALSE), `tenant_membership_entitlements` (154, RLS-exempt, `status` CHECK `active|suspended|unknown`), `files` ledger rows for logos. Default tenant id `00000000-0000-0000-0000-000000000001`, slug `default`.

**API** (`src/modules/tenants/routes.rs`, nested at `/tenants`; public logo merged into the public nest):

| Method | Path | Auth gate | Purpose |
| --- | --- | --- | --- |
| GET | `/tenants` | `RequirePlatformAdmin` | List tenants |
| POST | `/tenants` | `RequirePlatformAdmin` | Provision a tenant plus its admin user (welcome mail) |
| POST | `/tenants/self-serve` | public (identity token from login `needs_setup`) | Create first tenant, returns a session |
| POST | `/tenants/additional` | `RequireAuthState` | Authenticated identity creates another org, becomes admin |
| GET | `/tenants/current` | `RequireAuth` | Own tenant |
| PUT | `/tenants/current` | `RequireAuth` + `role.is_admin()` | Update own tenant |
| PUT | `/tenants/current/organization` | `RequireAuth` + `role.is_admin()` | Submit the organisation record whole |
| PUT, DELETE | `/tenants/current/logo` | PUT `RequireAuth` + admin check; DELETE `RequireAdmin` | Upload, remove logo |
| GET | `/tenants/{tenant_id}` | `TenantOrPlatformCaller` read access | Read |
| PUT | `/tenants/{tenant_id}` | `TenantOrPlatformCaller` admin write access | Update |
| POST | `/tenants/{tenant_id}/suspend`, `/activate` | `RequirePlatformAdmin` | Status changes |
| GET | `/tenants/{tenant_id}/usage` | `TenantOrPlatformCaller` read access | Counts: users, companies, contacts, tickets, assets, storage bytes |
| GET | `/tenants/{tenant_id}/modules/{module}` | `TenantOrPlatformCaller` read access | Module config |
| PUT | `/tenants/{tenant_id}/modules/{module}` | `TenantOrPlatformCaller` admin write access | Toggle module |
| GET | `/public/tenants/{tenant_id}/logo` | public | Logo for emails and request forms |

Handlers `cancel_tenant`, `get_tenant_admin`, `update_tenant_admin`, `resend_admin_welcome` exist in `routes.rs` but have no `.route(...)` mount.

**Behaviour.**
- `CreateTenantRequest`: `name` 1..255, `slug` 1..100 (slug normalised; empty after slugify is a validation error), `admin_email` valid. Instance cap `MOKOSH_MAX_TENANTS` (empty means no cap; over cap is an error naming the variable). Creation seeds per-tenant sequences, copies default lookup/config rows (`copy_default_config`, skipped when the tenant already has `ticket_statuses`), seeds the three built-in portal roles and the `internal` own company in one transaction. `ensure_personal_tenant` provisions `kind='personal'` tenants for new Bunyip users.
- Logo: allowed MIME `image/png|jpeg|webp|gif` (SVG rejected); size cap `TENANT_LOGO_MAX_BYTES` default 1 MiB; layout box 220 x 56; stored under the tenant's own prefix, ledgered in `files`.
- Branding values validated by one table shared with the settings and organisation routes (`validate_branding_patch`): bounded name/phone/email/path/address lengths; `logo_url` must sit under `/api/v1/public/tenants/` (or `/api/v1/public/companies/` for company rows); `portal_domain` and `invoice_template` are tenant-only.
- Suspension: `ensure_principal_usable` refuses any request for a tenant whose `status != 'active'` on the next request; a suspended tenant cannot log in or refresh.

**Background jobs.** One-shot at process start: `TenantLogoMover` moves legacy `tenant-logos/` objects under the tenant prefix; reads fall back to the old location until moved.

**Config.** `MOKOSH_MAX_TENANTS`, `TENANT_LOGO_MAX_BYTES`, `MOKOSH_SEED_TENANT_ID` (source tenant for lookup seeding, default the default tenant), `OIDC_DEFAULT_TENANT_ID`, `PUBLIC_API_BASE_URL`, `ORGANIZATIONS_ENABLED`, `STORAGE_*` (storage seam).

### platform

**Purpose.** Credential store and API for platform super-admins, separate from tenant users.

**Data model.** `platform_admins` (160, 241): `UNIQUE(lower(email))`, `password_hash`, `mfa_enabled`, `mfa_secret`, `mfa_last_totp_step`, `mfa_recovery_codes_hashes TEXT[]`, `status` CHECK `active|inactive`. RLS-exempt, accessed on the migrator pool.

**API** (`src/modules/platform/routes.rs`, nested at `/platform`):

| Method | Path | Auth gate | Purpose |
| --- | --- | --- | --- |
| POST | `/platform/login` | public, own limiter 20/min per IP and 5/min per email | Issue platform session (TOTP or recovery code when MFA on) |
| PUT | `/platform/me/password` | `RequirePlatformAdmin` | Change password |
| POST | `/platform/me/mfa/setup`, `/enable`, `/disable` | `RequirePlatformAdmin` + current password | MFA enrolment; enable returns recovery codes once |

**Behaviour.** Platform JWT `typ="platform"`, lifetime 2 hours (`PLATFORM_SESSION_TTL`); `RequirePlatformAdmin` re-reads `platform_admins.status` on every request, so offboarding takes effect immediately. New password >= 12 characters. Login failures all answer 401 (no distinction). On login a best-effort heal creates a `users` row in the default tenant for the admin email if none exists anywhere (failure logged, never blocks login). The first platform admin is seeded by `maybe_bootstrap_admin` from `ADMIN_EMAIL`/`ADMIN_PASSWORD` when `platform_admins` is empty.

**Background jobs.** none. **Config.** `JWT_SECRET`, `ENCRYPTION_KEY`.

### audit

**Purpose.** Append-only audit trail written in the same transaction as the mutation, plus read APIs. Contract documented in `src/modules/audit/mod.rs`.

**Data model.** `audit_log` (015, 205): `action` CHECK `create|update|delete|view|login|logout|export|import`; `entity_type VARCHAR(50)`, `entity_id`, `old_values`/`new_values JSONB`, `ip_address`, `user_agent`, `timestamp`; `user_id` nullable (contact-plane events leave it NULL and use `entity_type='portal_contact'`); partial expression index on `new_values->>'ticket_id'`; tenant RLS.

**API** (`src/modules/audit/routes.rs`):

| Method | Path | Auth gate | Purpose |
| --- | --- | --- | --- |
| GET | `/audit-log` | `RequireAuth` + `RequireAdmin` | Tenant audit log; filters `user_id`, `entity_type`, `action` (max 100 chars each), `from`, `to` |
| GET | `/audit-log/export.csv` | `RequireAuth` + `RequireAdmin` | CSV export, hard cap 50,000 rows, header `timestamp,actor,actor_id,action,entity_type,entity_id,entity_name,ip_address,user_agent` |
| GET | `/audit-log/entity/{entity_type}/{entity_id}` | `RequireAuth` (any tenant user) | Per-record change history; `entity_type` limited to `tickets|tasks|projects|assets|kb_articles`, otherwise 404 |

**Behaviour.** `audit_write` only INSERTs; there is no update or delete route. Writers: `audit_write` (in-transaction), `audit_auth_event` (entity type `auth`), `audit_portal_event` (contact plane). Retention is 24 months, enforced out of band (no in-repo job). History feed drops noise fields (`updated_at`, `created_at`, `id`, `tenant_id`, `last_updated_by_id`) and includes ticket-note rows excluding their `create` rows. `GET /audit-log` always scopes to the caller's own tenant.

**Background jobs.** none. **Config.** none.

### branding

**Purpose.** Company-scoped and tenant-scoped brand assets (logo, favicon, background) and the tenant plus company brand merge.

**Data model.** Colours and names live in `tenants.branding` and `companies.branding` JSONB; image bytes live in the storage seam under `{tenant}/branding/...` with ledger rows in `files`.

**API** (`src/modules/branding/routes.rs`; `{asset}` is `logo|favicon|background`):

| Method | Path | Auth gate | Purpose |
| --- | --- | --- | --- |
| PUT, DELETE | `/companies/{company_id}/{asset}` | `RequireAuth` + `role.is_admin()` + tenant check | Company override asset |
| PUT, DELETE | `/tenants/current/branding/{asset}` | `RequireAuth` + `role.is_admin()` | Tenant default asset (writes the same file as `/tenants/current/logo`) |
| PUT, DELETE | `/contact/companies/self/{asset}` | contact bearer + `settings:manage_company_branding` | Contact edits own company asset |
| GET | `/public/companies/{company_id}/{asset}` | public | Serve company asset (`Cache-Control: public, max-age=3600`, ETag) |
| GET | `/public/tenants/{tenant_id}/{asset}` | public | Serve tenant asset |

**Behaviour.** Per-company field `company.field.or(tenant.field)` merge (`effective_branding`, pure); absent on both sides stays null. MIME allowlist `image/png|jpeg|webp|gif`. Default size caps: logo 1 MiB, favicon 512 KiB, background 2 MiB, overridable per scope and kind (`BRANDING_TENANT_FAVICON_MAX_BYTES`, `BRANDING_TENANT_BACKGROUND_MAX_BYTES`, `BRANDING_COMPANY_LOGO_MAX_BYTES`, `BRANDING_COMPANY_FAVICON_MAX_BYTES`, `BRANDING_COMPANY_BACKGROUND_MAX_BYTES`, `TENANT_LOGO_MAX_BYTES`); upload routes raise the body limit to the largest cap for the scope. The public nest is behind the per-IP 60/min limiter. Doc point: contact-plane branding JSON is read and patched at `/contact/companies/self/branding` (contact_portal), assets at `/contact/companies/self/{asset}` (here).

**Background jobs.** One-shot at process start: `branding::mover::arm` moves the five non-logo (scope, kind) pairs from legacy shared directories to `{tenant}/branding/...`; reads fall back to the legacy layout until moved.

**Config.** `BRANDING_*_MAX_BYTES` keys above, `TENANT_LOGO_MAX_BYTES`, storage seam keys (`STORAGE_*`).

### row-level security and DB roles

**Purpose.** Tenant isolation enforced by Postgres, independent of application filters. Contract: [per-user isolation](rls-per-user-isolation.md) and [Postgres security notes](postgres-security.md). Where the two docs and the code disagree, the code (`src/db/`, `migrations/`, `tests/suites/rls_coverage.rs`) is cited here.

**Model.**
- Isolation boundary is the tenant. Each Bunyip user without an invite gets their own `kind='personal'` tenant; collaboration is via org tenants, invitations and cross-account grants.
- Policy (migration `038_rls_fail_closed.sql`, applied to every public table with a `tenant_id` column except `tenants`): `ENABLE` and `FORCE ROW LEVEL SECURITY`; policy `tenant_isolation` with `USING` and `WITH CHECK` of `tenant_id = NULLIF(current_setting('app.current_tenant', true), '')::uuid`. Unset GUC means zero rows on read and SQLSTATE 42501 on write. Each new tenant table must carry the same three statements in its own migration; `every_tenant_table_has_rls_or_is_allowlisted` fails the build otherwise.
- Tables without `tenant_id` are covered by a parent-join policy (`041`, `128`: `kb_article_versions`, `invoice_lines`, `rate_card_items`, `sla_targets`, `quote_lines`, `credit_note_lines`) or by a denormalised column (`user_oauth_identities`).
- Exemptions (`tests/suites/rls_coverage.rs`): tenant tables without RLS `mokosh_grant_invitations`, `tenant_membership_entitlements` (pre-auth or token-scoped reads); tenantless exempt `_sqlx_migrations`, `app_config`, `app_secrets`, `feature_toggles`, `identities`, `mokosh_bunyip_grants`, `platform_admins`, `tenants`. Doc discrepancy: `docs/rls-per-user-isolation.md` states the tenant-table allowlist holds one entry; the test holds two.
- System-shared class (`039`, `130`): `SELECT mokosh_enable_system_shared('<table>')` makes `tenant_id IS NULL` rows globally readable and guards writes with trigger function `mokosh_guard_system_shared_row()` unless `app.allow_system_writes='on'`. Unverified whether any table has opted in (docs say none).

**Roles and pools** (`src/db/pool.rs`, `src/db/provision.rs`):
- `mokosh_app` (`LOGIN NOSUPERUSER NOBYPASSRLS`, owns nothing) serves requests through `Database::pool()`; `mokosh_migrator` (`LOGIN BYPASSRLS`, owns the schema, `CREATE` on the database for trusted extensions) is `Database::migrator_pool()` and is reserved for migrations, bootstrap, cross-tenant workers and pre-auth paths.
- Grants: `mokosh_app` gets connect, usage and SELECT/INSERT/UPDATE/DELETE on all tables and sequences and EXECUTE on functions in `public`, plus `ALTER DEFAULT PRIVILEGES FOR ROLE mokosh_migrator` for future objects; every migration creating a table must end with `GRANT SELECT, INSERT, UPDATE, DELETE ON <table> TO mokosh_app;` (a test scans for it).
- Self-provisioning at startup (`provision_roles`): if `DATABASE_URL` (migrator) logs in and `mokosh_app` can log in, nothing happens; otherwise the privileged `MOKOSH_ADMIN_DATABASE_URL` creates and reconciles both roles idempotently (role passwords from env), then closes. The role split exists only when `MOKOSH_APP_DATABASE_URL` is set; unset means both pools are the same connection and RLS does not bite.
- Pools: app pool `max_connections(20)`, `acquire_timeout` 30 s, `idle_timeout` 600 s (`Database::new`); migrations run on the migrator pool at startup (`RUN_MIGRATIONS`).
- Request path: `Database::begin_with_tenant(TenantId)` opens a transaction and runs `set_config('app.current_tenant', $1, true)` (transaction-local, bound parameter). `TenantId` is constructible only from `CurrentUser::tenant()` (`TenantScoped`); `TenantId::from_trusted` is the listed escape hatch (workers, pre-auth, created tenants).
- Gate: `scripts/check-pool-safety.nu` (`just check-pool-safety`) fails a bare `.pool()` serving call without an adjacent `// SAFETY (PMS-285` note.
- Cross-tenant pre-auth paths on the migrator pool (each noted in code): `AuthService::find_user_placement`, `find_bunyip_principal`, `InvitationsService::newest_pending_for`, the Bunyip account-deleted webhook, contact login/refresh lookups, `IdentityRepo` and `PlatformAdminRepo` (identities, tenant_memberships, platform_admins).
- Tests: `rls_coverage.rs` (schema sweep), `rls_isolation.rs` and `tenantless_table_rls.rs` (behaviour through a NOBYPASSRLS role), `rls_serving_reads.rs`, `per_user_isolation.rs`, `worker_tenant_isolation.rs`.

**Config.** `DATABASE_URL`, `MOKOSH_APP_DATABASE_URL`, `MOKOSH_ADMIN_DATABASE_URL` and the role password variables read directly in `src/db/provision.rs` (provisioning runs before configuration is built), `RUN_MIGRATIONS`.

## 5. Service-desk modules


Conventions used below. All paths are under `/api/v1` and are mounted in `src/api/router.rs`. Gate names are the extractors in `src/modules/auth/middleware.rs`: `RequireAuth` (any signed-in staff user), `RequireManager` (roles super_admin, admin, manager), `RequireAdmin` / `RequireAdminUser` (super_admin, admin), `RequireFinance` (super_admin, admin, finance), `RequireReports` (staff user AND tenant module `reports` enabled in `module_config`; disabled -> 404), `RequireCallerContext` (staff OR contact-plane bearer; contact arms additionally check a DB-loaded portal capability). Every service call runs in a tenant-scoped transaction (`begin_with_tenant`, RLS GUC `app.current_tenant`); see [architecture, multi-tenancy](architecture.md#multi-tenancy) and [routing model](architecture.md#routing-model). Failure-shape rules: [error-visibility invariants](invariants/error-visibility.md).

### tickets

**Purpose.** Core service-desk record: tickets, notes, attachments, and the tenant lookup tables (status, priority, queue, type, category). Source: `src/modules/tickets/` (`routes.rs`, `service.rs`, `attachments.rs`, `automation.rs`), DTOs in `crates/mokosh-types/src/tickets.rs`.

**Data model** (`migrations/005_tickets.sql` plus later ALTERs).
- `ticket_statuses` (name VARCHAR(50), color VARCHAR(7), `is_closed`, `is_default`, sort_order), `ticket_priorities` (name, color, icon, `sla_multiplier` DECIMAL(3,2) default 1.00, `is_default`), `ticket_queues` (name VARCHAR(100), color, icon, `is_default`; also unused-by-API columns visible_to_roles, assignable_to_team_id, default_sla_id, auto_assign_rules), `ticket_types` (name, description, icon, `is_active`), `ticket_categories` (name, `parent_id` self-FK, `is_active`; same-tenant parent enforced by `migrations/047_ticket_category_parent_same_tenant.sql`). Partial unique index `(tenant_id) WHERE is_default` on statuses, priorities and queues (`migrations/049_lookup_single_default.sql`): one default each per tenant.
- `tickets`: `ticket_number` VARCHAR(20), UNIQUE(tenant_id, ticket_number); title VARCHAR(500); description; status_id, priority_id, queue_id (NOT NULL FKs); type_id, category_id, subcategory_id; `source` CHECK in (portal, email, phone, api, chat, rmm, internal); company_id NOT NULL; contact_id, site_id, assigned_to_id, team_id, `parent_ticket_id` (self FK, default RESTRICT), contract_id, sla_id, asset_id (no FK constraint on contract_id, sla_id, asset_id in 005); SLA timestamps `sla_due_date`, `first_response_due`, `first_response_at`, `resolution_due`, `resolved_at`, `closed_at`; scheduled_start/end; estimated_hours DECIMAL(10,2); actual_hours; `is_billable`; `billing_status` CHECK in (not_billed, ready_to_bill, billed); `email_message_id`, `email_thread_id` (partial UNIQUE (tenant_id, email_message_id) WHERE NOT NULL, `migrations/067_email_intake.sql`); `custom_fields` JSONB; `tags` TEXT[]; created_by_id NOT NULL; last_updated_by_id. Added later: `source_kb_article_id` (`068`, ON DELETE SET NULL) and `procedure_kb_article_id` (`099`, ON DELETE SET NULL). Trigram GIN indexes on title (005), ticket_number and description (`107_search_trigram_indexes.sql`).
- `ticket_sequences` (tenant_id PK, last_number); `ticket_number` is `T` + 6-digit zero-padded counter, incremented with `UPDATE ... RETURNING` (`TicketService::next_ticket_number`).
- `ticket_notes`: note_type CHECK in (internal, public, resolution, time_entry); content, content_html, `is_email_sent`, email_sent_at, email_recipients; created_by_id NOT NULL; `created_by_contact_id` (`069`, ON DELETE SET NULL); `time_minutes` (>0), `work_summary` VARCHAR(200), `parts_used` TEXT[], `follow_up` JSONB requiring boolean key `needed` (`264_note_structured_fields.sql`). Notes cascade-delete with the ticket.
- `ticket_attachments`: file_name VARCHAR(255), file_size INTEGER, mime_type, storage_path, ticket_id, optional note_id (cascade), `uploaded_by_id` (nullable since `079`), `created_by_contact_id` (`079`), `is_inline` BOOLEAN default false (`118`). Blobs live behind `crate::storage`, addressed by (tenant_id, attachment_id); see [storage seam invariant](invariants/config-providers.md#storage-seam-pms-910).
- `ticket_automation_rules` (trigger_type CHECK in on_create, on_update, on_schedule, on_sla_breach, on_sla_warning, on_aging; `conditions` JSONB array; `actions` JSONB array; priority default 100; last_run_at; run_count).
- `ticket_saved_views` (`262`): per-user, UNIQUE(tenant_id, user_id, name), name 1-100 chars, `filter` and `sort` JSONB, RLS forced.

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/tickets` | RequireCallerContext (contact needs `tickets:read`, forced to own company) | Paginated list; filter fields in `TicketFilter` (q, status/priority/type/queue/company/contact/assignee/team ids, `my_teams`, asset_id, parent_ticket_id, is_unassigned, is_overdue, is_open, billing_status, created_from/to, tags) |
| POST | `/tickets` | RequireCallerContext (contact needs `tickets:write`) | Create; contact arm forces company/contact from session, `source=portal`, `is_billable=false` |
| GET | `/tickets/{ticket_id}` | RequireCallerContext (contact `tickets:read`, own company else 404) | Fetch one |
| GET | `/tickets/{ticket_id}/sla` | RequireCallerContext (contact `tickets:read`, own company else 404) | SLA state: due/actual times, `on_track`/`warning`/`breached`/`not_applicable`, status name |
| PUT | `/tickets/{ticket_id}` | RequireAuth | Update (staff) |
| PATCH | `/tickets/{ticket_id}` | RequireCallerContext (contact `tickets:edit_own`) | Staff: same as PUT. Contact: only title/description, only on a ticket it reported; empty body -> 400 |
| DELETE | `/tickets/{ticket_id}` | RequireManager | Hard delete |
| POST | `/tickets/{ticket_id}/assign` | RequireAuth | Body `{assigned_to_id}` |
| POST | `/tickets/{ticket_id}/approvals/request` | RequireCallerContext (contact `tickets:request_approval`) | Body `{note}` (1-2000 chars); files an approval addressed to role `admin` |
| POST | `/tickets/{ticket_id}/reopen` | RequireCallerContext (contact `tickets:reopen`) | Reopen a closed ticket, optional `{reason}` |
| POST | `/tickets/{ticket_id}/attachments` | RequireCallerContext (contact `tickets:attach_file`) | JSON body `{filename, content_type?, data_base64}` ticket-level attachment |
| POST | `/tickets/{ticket_id}/attachments/inline` | RequireAuth | Multipart image-only upload for embedding in markdown; sets `is_inline` |
| GET | `/tickets/{ticket_id}/notes` | RequireCallerContext (contact `tickets:read`, public notes only) | Paginated notes; staff rows carry `can_edit` |
| POST | `/tickets/{ticket_id}/notes` | RequireCallerContext (contact `tickets:comment`, `note_type` must be `public`) | Add note |
| PUT | `/tickets/{ticket_id}/notes/{note_id}` | RequireAuth (+ tenant edit policy) | Edit note content only |
| GET | `/tickets/{ticket_id}/notes/{note_id}/attachments` | RequireAuth | List note attachments |
| POST | `/tickets/{ticket_id}/notes/{note_id}/attachments` | RequireAuth | Multipart upload |
| GET | `/tickets/{ticket_id}/notes/{note_id}/attachments/{attachment_id}` | RequireAuth | Stream download (ETag / If-None-Match, 304) |
| DELETE | `/tickets/{ticket_id}/notes/{note_id}/attachments/{attachment_id}` | RequireAuth | Delete, 204 |
| GET | `/contacts/{contact_id}/notes` | RequireAuth | All public notes authored by a contact |
| GET | `/public/tickets/attachments/{attachment_id}` | none (public nest; attachment UUID is the credential; serves only `is_inline` rows, else 404) | Inline-image read; `nosniff`, public cache |
| GET, POST | `/tickets/statuses`, `/tickets/priorities`, `/tickets/queues`, `/tickets/types`, `/tickets/categories` | GET: RequireAuth; POST: RequireAdmin | List (paginated) and create lookup rows |
| PUT, DELETE | `/tickets/statuses/{id}`, `/tickets/priorities/{id}`, `/tickets/queues/{id}`, `/tickets/types/{id}`, `/tickets/categories/{id}` | RequireAdmin | Update and delete lookup rows |
| GET, POST | `/tickets/saved-views` | RequireAuth (own rows only) | List / create saved list views |
| PUT, DELETE | `/tickets/saved-views/{id}` | RequireAuth (own rows only) | Rename / change / delete a saved view |

Routes `/tickets/{id}/approvals` and `/tickets/{id}/workflow-runs` belong to the approvals and workflows sections.

**Behaviour.**
- Create (`TicketService::create_ticket`): status is the tenant's `is_default` status (missing default -> configuration error); priority and queue default to their `is_default` rows; every FK in the body (companies, ticket_types, ticket_categories, contacts, sites, users, teams, contracts, sla_policies, assets) must exist in the tenant else 400 `Referenced <table> not found in this tenant`. `parent_ticket_id` must be a same-tenant, same-company ticket that is not itself a child (one nesting level, 422 field error). Title 1-500 chars; `estimated_hours` 0..=99_999_999.99. After insert in the same transaction: audit row, then workflow rules `ticket.created`. After commit: `calculate_sla_dates`, then (if tenant setting `scheduling/default_due_business_days` N > 0 and no SLA date was set) `sla_due_date` = now + N business days, then `on_create` automation rules (failure is logged at warn and does not fail the create).
- `calculate_sla_dates`: policy is the ticket's `sla_id` else the tenant default policy; if the policy has a `sla_targets` row for the ticket priority, sets `first_response_due`, `sla_due_date` and `resolution_due` as now + hours in wall-clock minutes (ignores business hours and `operational_hours`). It is run on create and when a priority is supplied on update. `SlaService::evaluate_for_ticket` (business-hours aware) is not called by the ticket service; its only caller is `POST /sla/tickets/{id}/evaluate`.
- Update (`update_ticket`): only these inputs have a SET statement: title, description, status_id, priority_id, assigned_to_id, queue_id, asset_id (double-option: absent = keep, null = clear). FK validation also covers contact, site, team, contract, sla_id, but no UPDATE writes type_id, category_id, contact_id, site_id, team_id, contract_id, sla_id, scheduled_*, estimated_hours, is_billable, billing_status, custom_fields or tags. Moving into a status with `is_closed` when `closed_at` is null sets `closed_at = NOW()` and `resolved_at = COALESCE(resolved_at, NOW())`. Audit row written unless the change is a description edit that only toggles markdown task-list checkboxes. Workflow triggers `ticket.status_changed` / `ticket.priority_changed` fire in the same transaction when the value differs; `on_update` automation runs after commit (warn on failure).
- Reopen (`reopen_portal_ticket`): if the current status is not closed, returns the ticket unchanged; else sets the default status, clears `closed_at` and `resolved_at`, appends a public note "Ticket reopened by customer." (plus " Reason: ...") in one transaction. Staff callers use the same path.
- Delete: 404 if absent; FK violation 23503 (time entries, child tickets, billing rows) -> 400 with message; attachment blobs are purged after commit; audit row in same transaction.
- Notes (`add_note`): first public note stamps `first_response_at = COALESCE(first_response_at, NOW())`; `send_email` with `note_type=public` emails the ticket contact (plain text) and records `is_email_sent`. Edit rule: who is the tenant setting `tickets/note_editing` in {`off`, `author_or_admin` (default), `author_or_manager`}; unauthorised -> 403. Row state blocks edit with 409: customer-authored note, emailed public note, time_entry note. Audit row keeps old content. See [note editing invariant](invariants/contacts.md#note-editing-pms-974).
- Contact portal ticket and note creation attribute `created_by_id` to the tenant's oldest active user with role super_admin, admin or manager; none -> configuration error.
- `compute_sla_status` (in `mokosh-types`): `not_applicable` when closed_at, resolved_at, a closed status, or no `sla_due_date`; `breached` when now > due; `warning` when within the at-risk lead before due; else `on_track`. Lead is 20% of (due - created_at), clamped to 5 minutes..24 hours.
- Lookup writes: validated lengths mirror column widths (status/priority name 50, type/queue/category name 100, color 7, sla_multiplier 0..=9.99). Setting `is_default` clears the previous default in the tenant. Delete of a lookup row that tickets reference: handled in `delete_lookup` (`TicketService`); exact response unverified.
- Attachments: size cap `ATTACHMENT_MAX_BYTES` (default 25 MiB, 413 on exceed); inline images cap = min(configured cap, 5 MiB), image-only, SVG refused (`utils::inline_image`); per-route `DefaultBodyLimit` matches the cap. Portal JSON upload rejects empty/invalid base64 with 400.
- Automation engine (`AutomationEngine`, `automation.rs`): runs rules of the trigger from `ticket_automation_rules` ordered by priority. Condition fields: status (name), priority (name), company_id, assigned_to_id, source, is_billable; operators equals, not_equals, contains, starts_with, ends_with, is_null, is_not_null; all conditions AND, empty list always matches. Actions: set_status, set_priority, assign_to, set_queue, add_note (DB actions, one transaction), then after commit send_notification and webhook. Webhook: 10 s timeout, max 5 redirects, each hop SSRF-screened ([outbound URL invariant](invariants/config-providers.md#outbound-urls-pms-805-pms-809)). Only `on_create` and `on_update` are invoked from code; no HTTP route or code path inserts into `ticket_automation_rules` (unverified: any other writer, e.g. seed).
- Saved views: name 1-100 chars and not blank; ownership scoped on (tenant_id, user_id).

**Background jobs.** none in this module (SLA alerts are in `sla`).

**Config.** `ATTACHMENT_MAX_BYTES` (registry, optional, default 25 MiB, `src/config/registry.rs`); `STORAGE_ROOT` via storage seam; tenant settings `tickets/note_editing`, `scheduling/default_due_business_days`.

### ticket_templates

**Purpose.** Admin-managed pre-fill templates for new tickets. Source: `src/modules/ticket_templates/`.

**Data model** (`migrations/083_ticket_templates.sql`). `ticket_templates`: name VARCHAR(200), description, `subject` VARCHAR(500) (seeds title), `body` (seeds description), category_id / priority_id / type_id (FKs, ON DELETE SET NULL), `is_active` default true, created_by_id NOT NULL; partial index on active rows; RLS forced (`095`).

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/ticket-templates` | RequireAdminUser | List; `?active_only=true` narrows to active |
| POST | `/ticket-templates` | RequireAdminUser | Create |
| GET | `/ticket-templates/{id}` | RequireAdminUser | Fetch |
| PATCH | `/ticket-templates/{id}` | RequireAdminUser | Partial update; category/priority/type/description/body are double-option (null clears) |
| DELETE | `/ticket-templates/{id}` | RequireAdminUser | Delete, returns `{"deleted": true}` |

**Behaviour.** name 1-200, subject 1-500. The server never applies a template to a ticket: nothing in `tickets` reads `ticket_templates`; the client copies fields. The service does not validate that category/priority/type ids belong to the tenant (unverified whether RLS plus FK alone is relied on). Missing id -> 404 `Ticket template`.

**Background jobs.** none. **Config.** none.

### workflows

**Purpose.** Tenant-defined rules that mutate a ticket when it is created or when its status or priority changes. Source: `src/modules/workflows/` (`executor.rs`, `service.rs`, `routes.rs`).

**Data model** (`migrations/071_workflow_rules.sql`, `072_workflow_rule_max_depth.sql`). `workflow_rules`: `trigger_event` VARCHAR(50), name VARCHAR(200), `conditions` JSONB (object), `actions` JSONB (object), `priority` INT default 100 (lower runs first, ties by created_at), `is_active`, created_by_id. `workflow_rule_runs`: rule_id (cascade), entity_type, entity_id, `applied_actions` JSONB, `error` TEXT null on success, ran_at. Tenant setting `workflows/rule_max_depth` (JSON integer, clamped to 1..=10, default 3 when unset).

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/workflow-rules` | RequireAdminUser | List rules |
| POST | `/workflow-rules` | RequireAdminUser | Create |
| GET | `/workflow-rules/{id}` | RequireAdminUser | Fetch |
| PATCH | `/workflow-rules/{id}` | RequireAdminUser | Partial update (trigger_event not updatable) |
| DELETE | `/workflow-rules/{id}` | RequireAdminUser | Delete |
| GET | `/tickets/{id}/workflow-runs` | RequireAdminUser | Rule-run timeline for a ticket |

**Behaviour.**
- Recognised triggers (`RECOGNISED_TRIGGERS`): `ticket.created`, `ticket.status_changed`, `ticket.priority_changed`; any other value on create -> 400.
- Conditions: object, AND across keys, each key is an array (IN). Keys for created: priority_id, queue_id, company_id, type_id, source. For status_changed: from_status_id, to_status_id, priority_id, queue_id, company_id, type_id. For priority_changed: from_priority_id, to_priority_id, status_id, queue_id, company_id, type_id. Empty object matches all; a non-object matches nothing; an unknown key does not match.
- Actions (object, keys): assign_to_user_id, assign_to_team_id, set_priority_id, set_status_id, add_tag (idempotent append), add_internal_note. On `ticket.created`, set_priority/set_status apply without cascade. On transition triggers, set_priority_id / set_status_id are applied last and re-fire the matching transition trigger at depth+1; a matching rule at depth >= `rule_max_depth` is not applied and a run row is written with error `cycle cap reached at depth N`.
- Execution is inside the ticket transaction; a failing action is recorded in `workflow_rule_runs.error` and does not abort the ticket write. A run row is always written for a matched rule.
- Rule conditions and actions are not schema-validated at write time (validated at run time).

**Background jobs.** none. **Config.** tenant setting `workflows/rule_max_depth`.

### sla

**Purpose.** SLA policies with per-priority targets, business hours, holiday calendars, a due-date evaluator, and an alert sweep. Source: `src/modules/sla/` (`service.rs`, `clock.rs`, `worker.rs`, `models.rs`, `routes.rs`). Storage decision: [JSONB vs normalized](dev-docs/sla-jsonb-vs-normalized.md); tenant-day rule: [time invariants](invariants/time.md#tenant-day-pms-1030).

**Data model** (`005_tickets.sql`, `027_sla_notify.sql`).
- `sla_policies`: name VARCHAR(100), description, business_hours_id, `is_default` (service clears prior default on create/update).
- `sla_targets`: sla_policy_id (cascade), priority_id, `first_response_hours` and `resolution_hours` DECIMAL(10,2), `operational_hours` CHECK in (`business_hours`, `24x7`), UNIQUE(sla_policy_id, priority_id). RLS through the parent policy (migration 041).
- `business_hours`: name, `timezone` VARCHAR(50) default UTC, `schedule` JSONB, `holidays` UUID[] (calendar ids), `is_default`. `holiday_calendars`: name, `holidays` JSONB.
- `sla_notifications`: UNIQUE(ticket_id, kind), kind CHECK in first_response_at_risk, first_response_breached, resolution_at_risk, resolution_breached. Migration 027 seeds default-tenant templates and rules for events `sla.at_risk` and `sla.breached` on channel `in_app`.

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/sla/policies` | RequireAuth | List |
| POST | `/sla/policies` | RequireAdmin | Create |
| GET | `/sla/policies/{id}` | RequireAuth | Fetch |
| PUT | `/sla/policies/{id}` | RequireAdmin | Update |
| DELETE | `/sla/policies/{id}` | RequireAdmin | Delete (targets cascade) |
| GET | `/sla/policies/{id}/targets` | RequireAuth | List targets |
| POST | `/sla/policies/{id}/targets` | RequireAdmin | Upsert target (ON CONFLICT policy+priority) |
| DELETE | `/sla/targets/{id}` | RequireAdmin | Delete target |
| GET, POST | `/sla/business-hours` | GET RequireAuth; POST RequireAdmin | List / create |
| PUT, DELETE | `/sla/business-hours/{id}` | RequireAdmin | Update / delete |
| GET, POST | `/sla/holiday-calendars` | GET RequireAuth; POST RequireAdmin | List / create |
| PUT, DELETE | `/sla/holiday-calendars/{id}` | RequireAdmin | Update / delete |
| POST | `/sla/tickets/{id}/evaluate` | RequireAdmin | Recompute and persist the ticket's three due timestamps |

**Behaviour.**
- Target validation: hours > 0, at most 2 decimal places, below the DECIMAL(10,2) limit; `first_response_hours <= resolution_hours` when both set. The request default for `operational_hours` is `24x7` (the column default is `business_hours`).
- Schedule JSON: object keyed by weekday (`"0"`-`"6"` with 0 = Sunday, or `mon`-`sun`), value null, a `{start,end}` window, or an array of windows; times `HH:MM`, end after start. Holidays: array of `YYYY-MM-DD` strings or `{date, name}` objects.
- `evaluate_for_ticket`: policy = ticket `sla_id` else tenant default; no policy or no target for the priority -> no-op returning OK; `clock::due_at(created_at, hours, schedule, holidays, operational)` where `24x7` is wall-clock and `business_hours` consumes only minutes inside windows (skipping closed days and holidays); a policy with no business hours or no windows degrades to 24x7.
- Sweep milestones: for first response (skipped once `first_response_at` is set) and resolution, `*_breached` when now >= due, else `*_at_risk` when now >= due - lead (20% of window, clamped 5 min..24 h). Open ticket = not resolved, not closed, status not closed. Each (ticket, kind) is dispatched once (ledger). Recipient is the ticket assignee via `context.recipient_user_id`; unassigned tickets are skipped.

**Background jobs.** `sla_sweep` (`SlaSweepWorker`, `src/modules/sla/worker.rs`), scheduler interval 60 s (`src/main.rs`); cross-tenant scan on the migrator pool, dispatches `sla.at_risk` / `sla.breached` through notifications.

**Config.** none beyond notifications / SMTP.

### approvals

**Purpose.** Sign-off requests against a ticket, change request, quote or time entry, addressed to a user, a role, or a portal contact. Source: `src/modules/approvals/`.

**Data model** (`066_ticket_approvals.sql`, `077`, `143`, `181`, `197`, `232`). Table `ticket_approvals`: `target` CHECK in (ticket, change_request, quote, time_entry) default ticket; `entity_id` NOT NULL (parent id); legacy `ticket_id` (nullable; set only when target = ticket); requester `requested_by_id` or `requested_by_contact_id` (at most one set; both NULL = deleted contact); approver `approver_user_id`, `approver_role` VARCHAR(50), `approver_contact_id` (at most one set; all NULL = deleted contact); `status` CHECK in (pending, approved, rejected, cancelled); notes, decision_notes; `decided_by_id`, `decided_by_contact_id`; requested_at, decided_at. Partial indexes for pending by user, role, contact and by (target, entity). RLS forced (`095`).

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET, POST | `/tickets/{ticket_id}/approvals` | RequireAuth | List / create for a ticket |
| GET, POST | `/time-entries/{entity_id}/approvals` | RequireAuth + RequireTimesheets | List / create for a time entry |
| GET, POST | `/change-requests/{entity_id}/approvals` | RequireAuth | List / create |
| GET, POST | `/quotes/{entity_id}/approvals` | RequireAuth | List / create |
| GET | `/approvals/pending` | RequireCallerContext (contact needs `approvals:decide`) | Caller's pending queue (staff: by user id or role; contact: by approver_contact_id) |
| GET | `/approvals/pending/count` | RequireCallerContext (contact `approvals:decide`) | `{count}` |
| POST | `/approvals/{id}/decision` | RequireCallerContext (contact `approvals:decide`) | Body `{decision: "approve"|"reject", decision_notes?}` |
| DELETE | `/approvals/{id}` | RequireAuth | Cancel (row kept with status `cancelled`) |
| POST | `/tickets/{ticket_id}/approvals/request` | see tickets | Dual-plane request shortcut |

**Behaviour.**
- Create: exactly one of `approver_user_id`, `approver_role`, `approver_contact_id` else 400; a contact approver must be a portal user (`is_portal_user`) of the tenant; parent existence is checked per target (404 `Time entry` / `Change request` / `Quote` / `Ticket`); notes max 4000. Contact-filed requests insert approver_role `admin`, `requested_by_contact_id` set.
- Decide (staff): row locked `FOR UPDATE`; must be `pending` (else 400 `Approval is already <status>`); caller must equal approver_user_id or have a role equal to approver_role (else 403). Contact decide: row must have `approver_contact_id` = caller (else 404), writes `decided_by_contact_id` and a `portal.approval_<status>` audit row (a failed audit write is logged at warn). Decision text outside approve/reject -> 400.
- Cancel: only the requester (`requested_by_id`) while pending; other callers 403; non-pending 400.
- The decision changes only the approval row; it does not gate or change the target entity.

**Background jobs.** none. **Config.** none.

### email_intake

**Purpose.** Inbound email to ticket: a mail gateway POSTs parsed messages; creates tickets, threads replies as public notes, stores attachments. Source: `src/modules/email_intake/`.

**Data model.** `tenant_intake_tokens` (`067`): kind VARCHAR(50), `token_hash` CHAR(64) UNIQUE (SHA-256 hex), label VARCHAR(200), last_used_at, revoked_at. `email_intake_log` (`073`): message_id VARCHAR(255), ticket_id (ON DELETE SET NULL), raw_headers JSONB, raw_body_text, raw_body_html, received_at, error. Dedup key `tickets(tenant_id, email_message_id)` unique partial index (`067`). Tenant setting `email_intake/default_company_id`.

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| POST | `/email-intake` | Bearer intake token (header parsed in handler, SHA-256 compared; not RequireAuth; revoked or wrong-kind -> 401) | Process one inbound message |
| GET | `/intake-tokens` | RequireAdminUser | List tokens (active and revoked) |
| POST | `/intake-tokens` | RequireAdminUser | Mint token; plaintext returned once |
| DELETE | `/intake-tokens/{id}` | RequireAdminUser | Revoke (sets `revoked_at`) |
| GET | `/email-intake-log/{id}` | RequireAdminUser | Read one intake audit row |

**Behaviour.**
- Request: message_id 1-255, from_email valid and <= 254, subject 1-500, optional from_name (<= 200), body_text, body_html (not stored on the ticket), `references` list, raw_headers object, attachments `[{file_name 1-255, mime_type?, content_base64}]`.
- Token: only kind `email_intake` is accepted on create (else 400); 32 random bytes URL-safe base64; only the hash is stored; `last_used_at` bumped on use.
- Flow (`EmailIntakeService::intake`): write log row first, run, then finalise the row with ticket_id or error. (1) Dedup on message_id -> existing ticket, `deduplicated=true`. (2) Threading: any `references` entry matching a ticket's `email_message_id` -> append body as a `public` note attributed to the sender contact, store attachments on that note, `threaded=true`, `comment_added` true only if a contact resolved and the note insert succeeded; failures in that arm return `comment_added=false` (the error is not returned). (3) Contact lookup by `lower(email)`; if none and `email_intake/default_company_id` is set, a contact is created under it (first/last name derived); if neither -> 400 naming the sender. (4) Creator = oldest active admin/manager (none -> configuration error). (5) `create_ticket` with `source=email`, `is_billable=false`, description prologue with sender; unique-violation race re-resolves to dedup.
- Attachments are best-effort: a part that fails to decode or exceeds the cap is skipped (logged at warn) and `attachments_stored` counts only stored ones.
- Contact creation follows [company mirror invariant](invariants/contacts.md#company-mirror-pms-1069).

**Background jobs.** none. **Config.** tenant setting `email_intake/default_company_id`; `ATTACHMENT_MAX_BYTES`. Unverified: per-token rate limiting on `POST /email-intake` (none found in the module).

### forms

**Purpose.** Admin-defined request forms; a tokenised public link lets an external client submit one, which creates a ticket (one child ticket per person for bulk links). Source: `src/modules/forms/` (`service.rs`, `request_links.rs`, `validation.rs`, `drafts.rs`, `routes.rs`, `public_routes.rs`), DTOs in `crates/mokosh-types/src/forms.rs`.

**Data model** (`100`, `101`, `102`, `105`, `141`, `151`, `240`; RLS forced on all).
- `form_definitions`: name VARCHAR(200), slug VARCHAR(100) UNIQUE per tenant, description, `contact_info` VARCHAR(200), `kb_article_id` (SET NULL), `rules` JSONB, `is_active`, `portal_visible` default false.
- `form_fields`: name (unique per definition), label, help_text, `field_type` CHECK in (text, textarea, email, date, select, boolean, file), is_required, min_length / max_length (>=0, >0, min <= max), `options` TEXT[] (select needs >= 1), `date_not_in_past`, sort_order. The Rust `FieldType` enum has no `file` variant (it deserialises to `Unknown`); the DB check allows `file` since `151`.
- `form_submissions`: payload JSONB, submitted_by_contact_id, ticket_id, `request_token_id`; definition FK ON DELETE RESTRICT.
- `form_request_tokens`: company_id, contact_id, recipient_email, `token_hash` (password hash of the secret), expires_at, used_at, submission_id, `uses_allowed` 1-50, `uses_remaining`, `parent_ticket_id`.
- `form_definition_drafts`: per (tenant, user, definition-or-new) autosave snapshot.

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/forms` | RequireAuth | List definitions (`?active_only=true`) |
| POST | `/forms` | RequireAdminUser | Create |
| GET | `/forms/{id}` | RequireAuth | Fetch |
| PATCH | `/forms/{id}` | RequireAdminUser | Update (fields list replaces the field set) |
| GET | `/forms/{id}/submissions` | RequireAuth | List submissions |
| GET | `/forms/drafts` | RequireAdminUser | List caller's drafts |
| PUT | `/forms/drafts` | RequireAdminUser | Upsert draft (body `{form_definition_id?, payload}`) |
| DELETE | `/forms/drafts/{id}` | RequireAdminUser | Delete draft, 204 |
| GET | `/form-request-links` | RequireAuth | List issued links (`?company_id=`) |
| POST | `/form-request-links` | RequireAuth (per-user mail limiter, 20/hour) | Issue a link and email it |
| GET | `/public/request-forms/{token}` | none (token); per-IP 30/min | Render the form for a link |
| POST | `/public/request-forms/{token}` | none (token); per-IP 30/min | Submit; 201 with ticket number and `submissions_remaining` |

DELETE `/forms/{id}` and POST `/forms/{id}/submissions` are intentionally unmounted (a test asserts 405).

**Behaviour.**
- Definition write: slug unique per tenant (409); field names `[a-z][a-z0-9_]*`, no trailing or doubled underscore, unique; at least one field; select needs options; min_length <= max_length. Rule kind `required_if {field, when_field, equals}` is validated at write (boolean `equals` must be true/false; unknown kind rejected on write, ignored on read).
- Submission validation (`validate_submission`): payload must be an object; unknown keys rejected; blank strings and null count as absent; required = `is_required` or a matching rule; types: boolean must be a JSON boolean; text/textarea/email honour length (counted in characters); email syntax; date `YYYY-MM-DD` and optional not-in-past (caller's today); select must equal an option; `Unknown` type accepts a string. Errors are returned per field.
- Request link: TTL 7 days; `people` 1-50 (default 1); a link with people > 1 first creates a parent ticket; recipient from `contact_id` email or `recipient_email`; secret is stored hashed; link is `<SPA base>/request-forms/<token_id>.<secret>`; email queued with template event `forms.request_link`.
- Submit (`submit_via_request_link`) is four transactions: store submission; guarded claim `uses_remaining > 0` (loser gets 410); `create_ticket` (company and contact from the token, `source=portal`, `created_by_id` = issuing user, title `<form name>: <first text answer or "client request">`, description a markdown list of labelled answers, `procedure_kb_article_id` = definition kb article, `parent_ticket_id` from the token); stamp the submission with ticket and token ids. A failure after the claim leaves the use spent and an orphan submission without ticket.
- Token errors: malformed, unknown, bad secret or expired -> 400 `Invalid or expired request link`; no uses left or inactive definition -> 410.
- Draft payload limit 256 KiB, rejected rather than truncated.
- `FormsService::list_portal_forms` (active and `portal_visible`) exists; unverified: no route outside the forms module calls it.

**Background jobs.** none.

**Config.** `SPA_BASE_URL` (link base), `PUBLIC_API_BASE_URL` (logo URL in email), `ABUSE_CONTACT_EMAIL` (optional report-abuse line), trusted proxy CIDR (client IP extraction for the public limiter, `src/utils/client_ip.rs`), SMTP keys via notifications.

### teams

**Purpose.** Tenant teams and membership, used for ticket routing and filtering. Compiled only with feature `multi-tenant` (a default feature) and `server`. Source: `src/modules/teams/`; role model: [teams role model](dev-docs/teams.md).

**Data model** (`003_auth.sql`, `155`, `156`, `187`, `211`). `teams`: name VARCHAR(100), description, `manager_id` (users), color VARCHAR(7), `is_active`, timestamps; partial unique `(tenant_id, LOWER(name)) WHERE is_active`. `team_members`: UNIQUE(team_id, user_id), `role` CHECK in (leader, member), created_at (exposed as `joined_at`). `tickets.team_id` has no cascade (soft delete only).

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/teams` | RequireAuth | List; `?active=` true (default) / false / all, `?manager_id=` |
| POST | `/teams` | RequireAdmin | Create (201) |
| GET | `/teams/{team_id}` | RequireAuth | Fetch; `?include=members` adds members |
| PUT | `/teams/{team_id}` | RequireAuth + admin or the team's `manager_id` | Update |
| DELETE | `/teams/{team_id}` | RequireAuth + admin or team manager | Soft delete (`is_active=false`), 204 |
| GET | `/teams/{team_id}/members` | RequireAuth | List members (excludes soft-deleted users) |
| POST | `/teams/{team_id}/members` | RequireAuth + admin or team manager | Add member (201) |
| PUT | `/teams/{team_id}/members/{user_id}` | RequireAuth + admin or team manager | Change member role |
| DELETE | `/teams/{team_id}/members/{user_id}` | RequireAuth + admin or team manager | Remove member, 204 |
| GET | `/me/teams` | RequireAuth | Caller's teams |

**Behaviour.** Color must match `#RRGGBB`; `manager_id` and member `user_id` must be users of the same tenant; active team name unique case-insensitively (409); role must be `leader` or `member` (400 field error); a duplicate membership is 409; `leader` grants no extra authorization. Every write writes an audit row in the same transaction. `CreateTeamRequest.name` allows up to 255 chars while the column is VARCHAR(100) and no later ALTER widens it; behaviour for a 101-255 char name is unverified.

**Background jobs.** none. **Config.** none (compile feature `multi-tenant`).

### notifications

**Purpose.** Event-driven messaging: channels, templates, rules, per-user preferences, an in-app inbox, a dispatcher that queues rows and a worker that delivers them. Source: `src/modules/notifications/` (`service.rs`, `worker.rs`, `routes.rs`).

**Data model** (`013`, `020`, `097`, `111`, `142`, `149`, `150`).
- `notification_channels`: channel_type CHECK in (email, sms, slack, teams, discord, google_chat, mattermost, in_app), name, `config_encrypted` (encrypted with the 32-byte `ENCRYPTION_KEY`), `is_active`, `is_default`.
- `notification_templates`: name, event_type, channel_type, subject VARCHAR(255), body_text, body_html, is_active.
- `notification_rules`: name, event_type, `conditions` JSONB, `channels` VARCHAR(20)[], `recipients` JSONB (keys `user_ids`, `emails`, `contacts`), template_id, is_active.
- `user_notification_preferences` UNIQUE(user_id, event_type); `contact_notification_preferences` UNIQUE(contact_id, event_type): is_enabled, channel_types[].
- `notifications` (the queue and inbox): user_id, `contact_id`, channel_type, template_id, recipient, subject, body, body_html, `status` CHECK in (pending, sending, sent, delivered, failed), error_message, `attempt_count`, `next_attempt_at`, sent_at, read_at, `entity_type`, `entity_id`.

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET, POST | `/notification-channels` | RequireAdmin | List / create (config returned decrypted) |
| PUT, DELETE | `/notification-channels/{id}` | RequireAdmin | Update / delete |
| GET | `/notification-templates` | RequireAuth | List |
| POST | `/notification-templates` | RequireAdmin | Create |
| PUT, DELETE | `/notification-templates/{id}` | RequireAdmin | Update / delete |
| GET | `/notification-rules` | RequireAuth | List |
| POST | `/notification-rules` | RequireAdmin | Create (`template_id` required) |
| PUT, DELETE | `/notification-rules/{id}` | RequireAdmin | Update / delete |
| GET, PUT | `/me/notification-preferences` | RequireAuth | List / upsert caller's preference per event type |
| GET | `/notifications` | RequireCallerContext (contact needs `notifications:read`) | Paginated inbox |
| POST | `/notifications/{id}/read` | RequireCallerContext (contact `notifications:read`) | Mark read |
| POST | `/notifications/preview` | RequireAuth | Render what an event would send; queues nothing, returns unresolved placeholders |
| POST | `/notifications/dispatch` | RequireAdmin | Manually dispatch an event, returns `{"fanout": N}` |

**Behaviour.**
- `dispatch(tenant, event_type, context)`: one tenant transaction. For each active rule of the event whose `conditions` match the context (every key must equal the context value; an array value is an IN check; a missing key fails; `{}` matches): skip with warn if the template is missing, inactive, or `template_id` is null; recipients = rule `user_ids`, `emails`, `contacts` plus context `recipient_user_id`, `recipient_email`, `recipient_contact_id`, deduplicated (an email resolving to an already-listed user is dropped); for each channel, user/contact preferences apply (no row = send; `is_enabled=false` or channel absent from `channel_types` = skip); renders `{{key}}` placeholders (flat replacer, unresolved keys kept and logged at warn on dispatch) with subject, text and HTML; inserts `pending` rows in batched `UNNEST` statements (atomic as a set).
- Context enrichment: tenant branding keys `msp_name` (default "Mokosh Platform"), `msp_logo_url` (absolute or empty), `msp_primary_color` (default `#111827`), `msp_support_email`, `msp_footer_line`, `msp_footer_line_html`; `app_name` always overwritten from deployment config; caller-supplied keys win except `app_name`.
- Event types found by grep in code: `appointment.reminder`, `auth.login_link`, `auth.mokosh_grant_invite`, `auth.password_reset`, `auth.portal_grant`, `auth.portal_welcome`, `auth.welcome`, `contact_sync.failing`, `forms.request_link`, `invitations.created`, `portal.access_requested`, `quote.sent`, `ticket.note_added`, plus `sla.at_risk` and `sla.breached` (from the SLA worker). Completeness of this list is unverified.
- Delivery (`DispatcherWorker`): channel `in_app` is delivered by flipping status to `sent`; `email` goes through the `Mailer` (multipart when `body_html` is present); any other channel type fails permanently with `no transport registered for channel '<x>'`. Missing user email or missing recipient fails permanently; transient SMTP errors retry with backoff 60 s, 300 s, 1800 s, 7200 s, 21600 s; after the ladder the row is `failed` with the last error.
- Channel/template/rule payloads: channel name 1-100; template body_text min 1; rule name 1-100. No application-level whitelist of `event_type` or `channel_type` values on templates (only the channel table CHECK); unverified for rules.

**Background jobs.** `notifications_dispatcher` (`DispatcherWorker`), scheduler interval 5 s. Each tick: claim up to 25 due rows (`pending` due now, or `sending` whose claim expired) by setting `status=sending`, bumping `attempt_count`, `next_attempt_at = now + 600 s` using `FOR UPDATE SKIP LOCKED`; deliver with no open transaction; settle outcomes in batched updates.

**Config.** `ENCRYPTION_KEY` (channel config), SMTP keys (`SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TLS`) and mail provider selection ([email backend](invariants/config-providers.md#email-backend)), `PUBLIC_API_BASE_URL` (absolute logo URL). Mail-audience rule: [mail audiences](invariants/contacts.md#mail-audiences-pms-1140).

### search

**Purpose.** One tenant-scoped substring search across tickets, contacts, companies, assets and projects. Source: `src/modules/search/`.

**Data model.** No tables of its own. Reads `tickets` (title, ticket_number, description), `contacts` (first_name, last_name, email), `companies` (name), `assets` (name, serial_number, asset_tag), `projects` (name). Trigram GIN indexes back each `ILIKE` column (`005`, `004`, `107_search_trigram_indexes.sql`).

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/search?q=` | RequireAuth | Grouped hits `{tickets, contacts, companies, assets, projects, counts}` |

**Behaviour.** `q` is truncated to 200 characters in the route, trimmed; empty -> empty response. `%`, `_` and `\` are escaped so they match literally. Pattern is `%q%` with `ILIKE`. Each section returns at most 5 hits (`SECTION_LIMIT`) and a true match count. Ordering: tickets and projects by `updated_at DESC`; contacts by last, first name; companies, assets by name. All ten statements run in one tenant transaction. Hit shape: `{id, label, secondary}`.

**Background jobs.** none. **Config.** none.

### dashboards

**Purpose.** Per-user saved dashboard layouts (opaque JSON owned by the SPA) with optional scheduled email snapshots. Source: `src/modules/dashboards/`.

**Data model** (`064_saved_dashboards.sql`, `076_scheduled_dashboards.sql`). `saved_dashboards`: user_id, name VARCHAR(200), `layout` JSONB default `{}`, `is_default`; partial unique `(tenant_id, user_id) WHERE is_default`. `scheduled_dashboards`: dashboard_id (cascade), user_id, `cron_expr` VARCHAR(100), `channel` CHECK = `email`, recipient_email, `is_active`, last_run_at, `next_run_at`, last_error. RLS forced (`095`).

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET, POST | `/dashboards` | RequireAuth (own rows) | List / create |
| GET | `/dashboards/default` | RequireAuth | Caller's default or null |
| GET, PATCH, DELETE | `/dashboards/{id}` | RequireAuth (own rows) | Fetch / update / delete |
| GET, POST | `/dashboards/{id}/schedules` | RequireAuth | List / create schedules |
| GET, PATCH, DELETE | `/dashboards/schedules/{schedule_id}` | RequireAuth | Fetch / update / delete a schedule |

**Behaviour.** Name 1-200. Setting `is_default=true` clears the previous default in the same transaction. Dashboard of another user -> 404. `cron_expr` 1-100 chars parsed by the `cron` crate (`utils::validation::validate_cron`); `next_run_at` computed from the expression; invalid -> 400. Recipient defaults to the owner's `users.email`.

**Background jobs.** `scheduled_dashboards` (`ScheduledDashboardsWorker`, `src/modules/dashboards/worker.rs`), interval 60 s: selects up to 10 active rows with `next_run_at <= NOW()` (`FOR UPDATE SKIP LOCKED`, migrator pool), renders a text summary (dashboard name plus widget keys from the layout) and inserts an `email` row into `notifications`; always advances `next_run_at`; on failure stores `last_error`; if the cron cannot advance the schedule is disabled (`is_active=false`, `last_error` = `Disabled: ...`).

**Config.** none (email goes through the notifications worker and SMTP keys).

### saved_reports

**Purpose.** Stored report definitions over tickets, executed on demand or delivered as CSV on a cron schedule. Source: `src/modules/saved_reports/` (`compiler.rs`, `service.rs`, `worker.rs`).

**Data model** (`070_saved_reports.sql`, `075_scheduled_reports.sql`). `saved_reports`: created_by_id, name VARCHAR(200), description, `entity_type` VARCHAR(50), `filters` JSONB object, `columns` JSONB array, `group_by` JSONB array, `sort` JSONB array, `is_shared`. `scheduled_reports`: saved_report_id (cascade), user_id, cron_expr, `channel` CHECK = `email`, `format` CHECK = `csv`, recipient_email, is_active, last_run_at, next_run_at, last_error. RLS forced (`095`).

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/reports/saved` | RequireAuth | List; `?scope=mine|shared|any` (default any), `?entity_type=` |
| POST | `/reports/saved` | RequireAuth | Create |
| GET | `/reports/saved/{id}` | RequireAuth (owner or `is_shared`) | Fetch |
| PATCH | `/reports/saved/{id}` | RequireAuth (owner only; others 404) | Update |
| DELETE | `/reports/saved/{id}` | RequireAuth (owner only; others 404) | Delete |
| POST | `/reports/saved/{id}/execute` | RequireAuth (owner or shared) | Run; `?page=1&per_page=100` |
| GET, POST | `/reports/saved/{id}/schedules` | RequireAuth | List / create schedules (report must be visible) |
| GET, PATCH, DELETE | `/reports/schedules/{schedule_id}` | RequireAuth | Fetch / update / delete a schedule |

**Behaviour.**
- Execute: `per_page` clamped to 1..=10,000; `page` 1-based; returns rows keyed by display header, plus total. Only `entity_type = "tickets"` compiles (any other value -> 400 at execute time; create accepts any 1-50 char value).
- Compiler (hand-rolled, parameterised): column whitelist of 26 keys: ticket_number, title, description, source, is_billable, billing_status, created_at, updated_at, closed_at, status_id, priority_id, queue_id, type_id, company_id, contact_id, assigned_to_id, status_name, priority_name, queue_name, type_name, category_name, company_name, contact_name, assigned_to_name, asset_name, created_by_name. Columns entries are strings or `{field, header}` (header <= 100 chars, no double quote); empty list -> 8 default columns. Filters: key must be a whitelisted column; scalar = equality, array = `= ANY` (empty array -> 400). Sort: array of `{field, dir asc|desc}`, default `updated_at DESC`. Unknown column, filter or sort field -> 400 naming it. `group_by` is stored but not used by the compiler. Tenant id is always bound first.
- Visibility: a schedule runs with the owner's visibility; the worker re-runs `get` as the owner so a report no longer visible fails that run.

**Background jobs.** `scheduled_reports` (`ScheduledReportsWorker`, `src/modules/saved_reports/worker.rs`), interval 60 s: up to 10 due active rows per tick (`FOR UPDATE SKIP LOCKED`, migrator pool), executes the report at 10,000 rows, renders CSV inline in the email body, inserts a `pending` `email` notification; always advances `next_run_at`; failure stored in `last_error`; unadvanceable cron disables the schedule.

**Config.** none (delivery uses notifications and SMTP keys).

### reports

**Purpose.** Built-in operational and financial reports with CSV or PDF export, plus a catalog-based custom report builder. Source: `src/modules/reports/` (`routes.rs`, `service.rs`, `custom.rs`).

**Data model.** No tables of its own; `FROM` clauses in `service.rs` read tickets, ticket_statuses, time_entries, invoices, projects, tasks, companies, assets, contracts and form_definitions (joined lookup tables not enumerated; unverified: payment source for `paid`).

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/reports` | RequireReports | Registry of reports with parameter specs |
| GET | `/reports/dashboard` | RequireReports | Open tickets by priority, `sla_warnings`, `sla_breached`, 30-day ticket trend; `?team_id=` |
| GET | `/reports/tickets` | RequireReports | Opened by status, closed total, opened by assignee; `?from&to` (dates; default last 30 days ending on the caller's today) |
| GET | `/reports/time` | RequireReports | Minutes by user and by work type; `?from&to` |
| GET | `/reports/request-types` | RequireReports | Measured duration per client-request type; `?from&to` |
| GET | `/reports/billing` | RequireReports + RequireFinance | Invoiced / paid / outstanding and A/R aging; `?company_id=` |
| GET | `/reports/projects` | RequireReports | Projects by status, budget vs actual, task completion, overdue |
| GET | `/reports/clients` | RequireReports + RequireFinance | Company, asset, warranty, contract counts |
| GET | `/reports/custom/schema` | RequireReports | Catalog of sources, dimensions, measures, filters |
| POST | `/reports/custom` | RequireReports | Run a custom spec; `"format": "csv"` returns `text/csv` |
| GET | `/reports/{report}/export` | RequireReports (billing and clients also need billing-manager role, else 403) | `?format=csv|pdf` (default csv, other -> query error); `custom` returns 400 |

Saved-report routes live under the same `/reports/` prefix; see saved_reports.

**Behaviour.**
- The registry `REPORTS` is the single list read by `GET /reports` and the export route (unknown key -> 404 `Report <key>`); `ReportKind` is matched exhaustively.
- Dashboard `sla_warnings` counts open tickets with `sla_due_date` within the next 2 hours (and in the future); `sla_breached` counts open tickets with `sla_due_date` in the past; "open" = not resolved, not closed, status not closed (`SLA_CLOCK_RUNNING`). This 2-hour window differs from the 20%-of-window lead used by the ticket badge and the SLA worker.
- Custom builder: sources `tickets`, `time_entries`, `assets` (identifiers are server constants; user values are bound; `tenant_id` always injected). Dimensions: tickets: status, priority, assignee, created_date, created_month; time_entries: user, work_type, date, month, billable, project, contract; assets: type, status, company, manufacturer. Measures include count (all sources), and for time_entries minutes, hours, worked_minutes, billable_minutes, realization, amount. Equality filters per source, optional inclusive `from`/`to` on the source date column. At least one measure required; unknown source, dimension or measure -> 400. `limit` default 100, clamped 1..=1000; GROUP BY / ORDER BY the dimension ordinals. Response `{columns, rows, totals}`.

**Background jobs.** none. **Config.** tenant module toggle `reports` in `module_config` ([feature toggles](feature-toggles.md) describes the separate feature registry); PDF rendering via `crate::pdf` ([document invariants](invariants/documents.md)).

## 6. Billing and delivery modules

Gate legend (from `src/modules/auth/middleware.rs`): `RequireBilling`, `RequireContracts`, `RequireProjects`, `RequireCalendar`, `RequireTimeTracking`, `RequireTimesheets` are per-tenant module gates (`module_config` rows; a disabled module answers 404). `RequireFinance` = role `super_admin | admin | finance`. `RequireAdmin` = `super_admin | admin`. `RequireManager` = `super_admin | admin | manager`. "Dual-plane" means the handler takes `RequireCallerContext` and serves a staff session or a contact Bearer on the same path (the contact branch checks a `contact_portal::capabilities` capability and scopes to the caller's company; a foreign row answers 404). All paths below are under `/api/v1` unless stated; routers are merged in `src/api/router.rs`. Related docs: [invoice lifecycle](invoice-lifecycle.md), [billing invariants](invariants/billing.md), [document invariants](invariants/documents.md), [time invariants](invariants/time.md), [feature toggles](feature-toggles.md).

### billing

**Purpose.** Customer invoicing (invoices, lines, payments, refunds, credit notes, statements, products, tax rates, payment terms), online payment through Stripe or PayPal accounts the tenant connects, and optional delegation of invoice issuing and vendor bills to Xero or QuickBooks. Source: `src/modules/billing/`.

**Data model** (final state after migrations `010`, `050`, `051`, `098`, `122`, `123`, `127`, `133`, `134`, `185`, `189`, `192`, `193`, `213`, `216`, `218`, `233`, `242`, `243`, `253`, `256`-`257`, `263`, `278`, `282`-`291`):

- `invoices`: `id`, `tenant_id`, `invoice_number` (unique per tenant), `company_id` (NOT NULL), `billing_contact_id`, `contract_id`, `status` CHECK `draft | pending | sent | paid | partially_paid | void | written_off`, `invoice_date`, `due_date`, `payment_terms` (text), `payment_term_id` -> `payment_terms`, `subtotal`, `tax_amount`, `discount_amount`, `total`, `amount_paid`, `amount_credited`, `balance_due` (all DECIMAL(12,2)), `currency` (default `USD`), `notes`, `internal_notes`, `po_number`, `sent_at`, `paid_at`, `emailed_at`, `emailed_to`, `issuer_snapshot` JSONB (frozen at first send), `tax_rate_id` + `tax_rate` DECIMAL(7,4) (frozen), write-off columns (`written_off_at`, `written_off_by_id`, `write_off_reason`, `write_off_amount`), void columns (`voided_at`, `voided_by_id`, `void_reason`), `number_scheme` CHECK `tenant_sequence | company_prefix` (NULL = pre-column), `amends_invoice_id` -> `invoices` (ON DELETE SET NULL), `delivery_method` CHECK `email | postal | other`, `delivery_note`, `delivered_by_id` (CHECK: `other` requires a non-blank note), `external_provider`, `external_invoice_id`, `external_number` (set when a provider issued it).
- `invoice_lines`: `line_type` CHECK `service | product | time_entry | mileage | adjustment | tax | discount`, `description`, `quantity` DECIMAL(10,2), `unit_price`, `total`, `time_entry_ids` UUID[], `ticket_id`, `project_id`, `product_id`, `is_taxable` (default true), `sort_order`. `quantity` and `unit_price` are signed by design (discount lines).
- `invoice_sequences` (per-tenant counter, default prefix `INV-`), `invoice_company_sequences` (per-company counter), `companies.invoice_prefix` (4 chars from `ABCDEFGHJKMNPQRSTUVWXYZ23456789`, unique per tenant).
- `payments`: `invoice_id` (nullable: unapplied payment), `company_id`, `payment_date`, `amount` (CHECK positive), `payment_method` CHECK `check | credit_card | ach | wire | cash | paypal | other`, `reference_number`, `gateway_transaction_id` (unique per tenant when set), `gateway_response` JSONB, `currency`, `notes`. `payment_refunds`: `payment_id`, `invoice_id`, `amount` > 0, `provider`, `provider_reference` (unique per tenant), `gateway_response`.
- `credit_notes`: `credit_note_number` (unique per tenant, prefix `CN-`), `company_id`, `invoice_id` (NOT NULL), `status` CHECK `issued | void`, `issue_date`, `reason` (NOT NULL), `subtotal`, `tax_amount`, `total` (CHECK `total > 0`), `currency`, `voided_at`, `voided_by_id`, `external_provider`, `external_credit_note_id`, `external_number`. `credit_note_lines` (same line types as invoice lines, plus `product_id`). `credit_note_sequences`.
- `tax_rates` (`name`, `rate` DECIMAL(7,4) as a percent, `is_default`, `is_active`), `payment_terms` (`name` unique per tenant, `net_days` 0-3650 or NULL, `is_default`, `is_active`, `sort_order`), `products` (`sku` unique per tenant when set, `name` unique case-insensitively per tenant, `unit_price`, `unit` default `each`, `is_taxable`, `is_active`).
- `payment_gateway_configs` (`provider` CHECK `stripe | authorize_net | paypal`, `is_active`, `is_test_mode`, `config_encrypted` nullable once the credential lives in the secret provider, `client_display_name` max 64, `min_partial_amount` NUMERIC(10,2); unique per tenant and provider). `payment_webhook_deliveries` (`outcome` CHECK `accepted | refused | ignored | failed | unreconciled`). `contact_payment_methods` (per contact, one default, `provider` `stripe | paypal`). `invoice_reminders` (unique `tenant_id, invoice_id, offset_days`, the once-per-step guard). `contract_invoice_runs` (unique `tenant_id, contract_id, period_start`, the recurring-invoicing ledger).
- Delegation: `integrations` (unique `tenant_id, provider`; `provider` CHECK `stripe | paypal | quickbooks | xero | google | microsoft`; `status` CHECK `not_connected | connected | error | disconnected`; `enabled_capabilities` TEXT[]; `external_organisation_id` (unique per provider when set); `external_payment_account_id`), `invoice_issuer_company_mappings`, `invoice_issuer_product_mappings`, `invoice_issuer_vendor_mappings`, `invoice_issuer_expense_account_mappings`, `invoice_issuer_user_mappings` (each unique per tenant, provider and local id; provider CHECK `xero | quickbooks`), `invoice_issuer_oauth_states` (hashed single-use state, PKCE `code_verifier`, `expires_at`, `consumed_at`). OAuth tokens live in the secret provider under `SecretKind::Integration`, not in a table (`src/modules/billing/invoice_issuer_credentials.rs`).

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/invoices` | dual-plane: staff `RequireBilling`+`RequireFinance`; contact `invoices:read` | List; filters `company_id`, `status`, `contract_id`, `q` (max 200), `overdue`; contact is forced to its company and never sees drafts |
| POST | `/invoices` | `RequireBilling`+`RequireFinance` | Create draft (or `sent` when issued by a provider) |
| GET | `/invoices/summary` | dual-plane, same as list | `{count, total}` aggregate with the list filters |
| POST | `/invoices/from-time-entries` | `RequireBilling`+`RequireFinance` | Build a draft from a company's `ready_to_bill` time and mileage |
| GET | `/invoices/{invoice_id}` | dual-plane (`invoices:read`) | Detail incl. lines, `is_overdue`, `days_overdue`, `amended_by` |
| PUT | `/invoices/{invoice_id}` | `RequireBilling`+`RequireFinance` | Edit draft/pending; the `draft|pending -> sent` transition (the send) |
| POST | `/invoices/{invoice_id}/write-off` | `RequireBilling`+`RequireFinance` | Write off a `sent`/`partially_paid` invoice |
| POST | `/invoices/{invoice_id}/void` | `RequireBilling`+`RequireFinance` | Void a `draft`/`pending` invoice |
| POST | `/invoices/{invoice_id}/amend` | `RequireBilling`+`RequireFinance` | Create a replacement draft for a sent invoice |
| GET | `/invoices/{invoice_id}/pdf` | dual-plane (`invoices:download_pdf`) | Stored bytes when frozen, live render when draft; `?template=` is staff-only |
| GET | `/invoices/{invoice_id}/delivery-options` | `RequireBilling`+`RequireFinance` | Per-method availability and recipient for the Send dialog |
| POST | `/invoices/{invoice_id}/pay` | dual-plane (`invoices:pay`; `invoices:pay_partial` when `amount` is set) | Mint a hosted checkout session; rate limited 20/min per caller and 10/min per invoice |
| GET | `/invoices/{invoice_id}/payments` | dual-plane (`invoices:read`) | Payments and refunds for one invoice |
| GET | `/invoices/{invoice_id}/payment-readiness` | dual-plane (`invoices:read`) | Whether and how Pay Now can render (providers, partial-payment floor) |
| GET, POST | `/products` | `RequireBilling`+`RequireFinance` | List (filters `is_active`, `q`) / create |
| GET, PUT, DELETE | `/products/{product_id}` | `RequireBilling`+`RequireFinance` | Read / update / delete (409 if sold; retire with `is_active=false`) |
| GET | `/statements` | `RequireBilling`+`RequireFinance` | Company account over `period_start..period_end` (read model, stores nothing) |
| GET | `/statements/pdf` | `RequireBilling`+`RequireFinance` | Same, rendered from current branding |
| GET, POST | `/credit-notes` | `RequireBilling`+`RequireFinance` | List / issue |
| GET | `/credit-notes/{credit_note_id}` | `RequireBilling`+`RequireFinance` | Read |
| GET | `/credit-notes/{credit_note_id}/pdf` | `RequireBilling`+`RequireFinance` | Stored bytes from issue |
| POST | `/credit-notes/{credit_note_id}/void` | `RequireBilling`+`RequireFinance` | Void (stops counting against the invoice) |
| GET, POST | `/payments` | `RequireBilling`+`RequireFinance` | List (filters incl. `invoice_id`) / record manual payment |
| DELETE | `/payments/{payment_id}` | `RequireBilling`+`RequireFinance` | Hard delete; recomputes the invoice balance |
| GET, PUT | `/payment-gateways` | `RequireBilling`+`RequireFinance` | List / upsert a gateway (credential is write-only) |
| GET | `/payment-gateways/webhook-endpoints` | `RequireBilling`+`RequireFinance` | Webhook URL the admin configures at the provider |
| GET | `/payment-gateways/webhook-deliveries` | `RequireBilling`+`RequireFinance` | Recent deliveries (`provider`, `limit`) |
| POST | `/payment-gateways/{provider}/check` | `RequireBilling`+`RequireFinance` | Call the provider to test the stored credential; writes nothing |
| DELETE | `/payment-gateways/{provider}` | `RequireBilling`+`RequireFinance` | Remove a gateway |
| GET, POST | `/tax-rates` | `RequireBilling`+`RequireFinance` | List / create |
| PUT, DELETE | `/tax-rates/{id}` | `RequireBilling`+`RequireFinance` | Update / delete |
| GET | `/tax-rates/lookup` | `RequireBilling`+`RequireFinance` | Rate by jurisdiction key |
| GET, POST | `/payment-terms` | `RequireBilling`+`RequireFinance` | List / create |
| PUT, DELETE | `/payment-terms/{id}` | `RequireBilling`+`RequireFinance` | Update / delete (409 if an invoice references it) |
| GET | `/invoice-issuer-mappings/companies`, `/products`, `/vendors`, `/expense-accounts`, `/people` | `RequireBilling`+`RequireFinance`+`RequireAdmin` | List provider mappings; companies and products 404 unless the `delegated_invoice_issuer` feature is on, vendors, expense accounts and people 404 unless `delegated_bills` is on |
| PUT | `/invoice-issuer-mappings/companies/{provider}/{company_id}` | same | Set external customer id (1-100 chars) |
| PUT | `/invoice-issuer-mappings/products/{provider}/{product_id}` | same | Set external item id (1-100 chars) |
| PUT | `/invoice-issuer-mappings/vendors/{provider}/{vendor_id}` | same | Set external vendor id |
| PUT | `/invoice-issuer-mappings/expense-accounts/{provider}/{category_id}` | same | Set ledger account per expense category |
| PUT | `/invoice-issuer-mappings/people/{provider}/{user_id}` | same | Set external contact for a reimbursed person |
| GET | `/integrations/invoice-issuer/{provider}` | `RequireAdmin`+`RequireAuth` | Connection overview (`provider` is `xero` or `quickbooks`, else 404) |
| POST | `/integrations/invoice-issuer/{provider}/authorize` | `RequireAdmin` | Start OAuth (PKCE S256); returns `authorize_url` |
| POST | `/integrations/invoice-issuer/{provider}/disconnect` | `RequireAdmin` | Disconnect |
| PUT | `/integrations/invoice-issuer/{provider}/bills` | `RequireAdmin` | Toggle bills delegation |
| PUT | `/integrations/invoice-issuer/{provider}/payment-account` | `RequireAdmin` | Set the provider account reimbursements and bill payments are paid from |
| GET | `/public/invoice-issuer/{provider}/callback` | public (single-use state is the identity) | OAuth redirect target; always redirects back to the SPA |
| POST | `/stripe/webhooks/{tenant_id}` (full path `/api/v1/stripe/...`) | public, Stripe HMAC | Payment and refund events |
| POST | `/paypal/webhooks/{tenant_id}` (full path `/api/v1/paypal/...`) | public, PayPal transmission headers verified back with PayPal | Payment and refund events |
| POST | `/webhooks/xero`, `/webhooks/quickbooks` (full path `/api/v1/webhooks/...`) | public, HMAC (`x-xero-signature` / `intuit-signature`) | Invoice paid/voided and delegated bill payment events; one URL per provider, tenant resolved from `integrations.external_organisation_id` |

Sources: `src/modules/billing/routes.rs`, `invoice_issuer_mapping_routes.rs`, `invoice_issuer_connect.rs`, `webhook.rs`, `webhook_invoice_issuer.rs`, `src/api/router.rs`. The source guard `every_billing_handler_also_takes_the_finance_gate` in `routes.rs` enforces the gate pairing.

**Behaviour.**

- Invoice statuses: `draft`, `pending`, `sent`, `paid`, `partially_paid`, `void`, `written_off`. Editable: `draft`, `pending`. Frozen (`is_frozen`): `sent`, `paid`, `partially_paid`, `void`, `written_off`; edits return 409. `PUT` refuses `status = void | written_off` (owned by the void and write-off endpoints). Transitions: send = `draft|pending -> sent` via `PUT`; collection `sent -> partially_paid -> paid` derived by `recompute_invoice_balance`; void `draft|pending -> void`; write-off `sent|partially_paid -> written_off` (reason required, 1-2000 chars; freezes `write_off_amount`; no reversal); amendment send voids the replaced invoice. Full rules: [invoice lifecycle](invoice-lifecycle.md).
- Balance: `recompute_invoice_balance` is the single writer of `amount_paid`, `amount_credited`, `balance_due`, `status`, `paid_at`, from SQL sums over `payments` minus `payment_refunds` and issued `credit_notes`, under the invoice row lock. Status CASE order: draft/pending unchanged, `written_off_at` -> `written_off`, `voided_at` -> `void`, balance <= 0 -> `paid`, paid > 0 -> `partially_paid`, else `sent`.
- Tax (`apply_tax`): rate = request `tax_rate_id` (must be active in tenant, else 400), else the tenant's active default, else none. `tax_amount = round(sum(taxable line totals) * rate / 100, 2)`, half away from zero. A supplied `tax_amount` is stored as given and records no rate. `total = subtotal + tax - discount_amount`. Rate is frozen on the invoice. Product lines copy `products.is_taxable`.
- Create: at least one line; `due_date` must be >= `invoice_date`; omitted `due_date` = invoice date + `net_days` of the named or default payment term, else 30 days; currency = request, else `billing_prefs/currency`, else `USD`; recipient falls back to the company's `default_billing_contact_id`; `billing_contact_id`, `payment_term_id`, `tax_rate_id` and `product_id` are validated against the tenant (400). Product on a retired product is refused.
- Numbering: `billing_prefs/invoice_numbering` is `tenant_sequence` (default, `INV-000042`) or `company_prefix` (`A7QF-000001`); counters are table rows so a rollback leaves no gap; switching renumbers nothing.
- Send (`delivery` block, default `email`): `email` requires a resolvable recipient with an address (409 otherwise), freezes `issuer_snapshot`, stores the PDF, and mails it inside the transaction (relay refusal rolls the send back and writes an `invoice.send_failed` audit row in a new transaction); `postal` and `other` record the delivery without mail (`other` needs a non-blank `note`, else 422). The removed `skip_email` key is refused with 422.
- Payments: manual payment requires the invoice to have been sent (409), amount positive with at most 2 decimals, not above `total - paid - credited` (400), and `company_id` must match the invoice's company (400). Delete is a hard delete followed by recompute. Gateway payments (`record_gateway_payment`) are idempotent on `gateway_transaction_id`; refunds feed `payment_refunds`.
- Credit notes: only against a frozen invoice that is not `void` or `written_off` (400); each line needs positive quantity and unit price; `total` must be > 0 and <= `invoice.total - amount_credited`; issued immediately, never edited, voided not deleted. A credit taking the balance to zero lands the invoice on `paid`, not `void`.
- Amend: allowed only when nothing is paid, no credit note exists, the invoice is not `draft|pending|void`, and no draft amendment is open; checked at create and again when the amendment is sent. Sending the amendment voids the original with `void_reason` naming the replacement.
- Overdue is derived, not stored: `status IN (sent, partially_paid) AND balance_due > 0 AND due_date < today` in the tenant's day.
- From time entries: bills only `billing_status = ready_to_bill` client time and mileage; prepaid entries are skipped; overage entries bill the overage hours at the stored overage rate (see time_tracking, contracts).
- Recurring contract invoicing: for each `active` contract with `billing_cycle` not `one_time` and `start_date <= tenant today`, find the current billing period; skip when the period starts after `end_date`; build a draft from `contract_items` with `billing_rule = every_period` or (`once` and `billed_at IS NULL`); no items = no ledger row; the `contract_invoice_runs` unique key makes a period invoiced at most once; tax is zero and discount zero on this path.
- Statement: dated-row read model with opening balance, invoices, payments, refunds, credits, write-offs (`total_written_off`), closing balance; excludes `void` invoices.
- Pay Now: a tenant connects its own Stripe or PayPal account. `SUPPORTED` providers are `stripe` and `paypal`; activating another is refused. With two active providers the request must name one (`provider`), otherwise it is refused. Partial `amount` is checked against `[min_partial_amount, balance_due]`. A written-off or voided invoice cannot be paid online. Webhook verification is per tenant; every delivery is recorded in `payment_webhook_deliveries`.
- Delegated issuing (`delegated_invoice_issuer` feature on AND tenant `integrations` row for `xero` or `quickbooks` has the `invoicing` capability AND status `connected` or `error`): `create_invoice` calls the provider before its transaction (company and product mappings required, else refusal) and stores the row as `sent` with `external_*` set; sending an amendment voids the provider copy in the same transaction; a credit note raises and applies the provider credit document (a refused creation rolls back, a refused application is logged and the credit note stands); a write-off does not touch the provider. Inbound webhooks apply provider `paid` (through `record_gateway_payment`) and `voided` (`void_delegated_invoice`). Delegated bills, claims and bill payments are described under expenses. Detail: [billing invariants](invariants/billing.md).
- Credential handling: gateway credentials are write-only (omitted on update keeps the stored one), stored in the secret provider (legacy rows in `config_encrypted`); the Xero and QuickBooks client pairs are application-tier secrets, the OAuth consent state lives 10 minutes.
- Documents (invoice, credit note, statement PDFs, issuer snapshot, templates `classic | modern | compact`): see [document invariants](invariants/documents.md); unread by this fragment.

**Background jobs.**

| Job | Cadence | What it does |
|---|---|---|
| `recurring_invoicing` (`RecurringInvoicingWorker`) | 3600 s | Generates one draft per due contract period for every tenant; a per-tenant failure is logged and skipped |
| `invoice_reminders` (`InvoiceReminderWorker`) | 3600 s | Per tenant with `billing_reminders/enabled`: at the tenant-local `send_hour` (default 8) mails each overdue invoice whose `days_overdue` equals a `schedule` offset (e.g. 3, 7, 14, 30); `invoice_reminders` claim prevents repeats |
| Gateway credential move | once per process start (`spawn_once`) | Moves legacy `config_encrypted` credentials into the secret provider (`src/modules/billing/credential_move.rs`) |

**Config.** `ENCRYPTION_KEY` (bootstrap; 32 bytes), `SPA_BASE_URL` (pay links in mail), `PUBLIC_API_BASE_URL` (optional; webhook URLs and logo URLs), `STRIPE_API_BASE`, `PAYPAL_API_BASE` (optional overrides), `XERO_CLIENT_ID`, `XERO_CLIENT_SECRET`, `XERO_WEBHOOK_KEY`, `QUICKBOOKS_CLIENT_ID`, `QUICKBOOKS_CLIENT_SECRET`, `QUICKBOOKS_VERIFIER_TOKEN` (application secrets via `APP_SECRET_BACKEND`; half a client pair refuses boot). Feature toggles (`feature_toggles` table, admin-set): `delegated_invoice_issuer`, `delegated_bills`. Tenant settings: `billing_prefs/currency`, `billing_prefs/invoice_numbering`, `billing_reminders/{enabled,schedule,send_hour}`, `tenants.branding.invoice_template`. Registry: `src/config/registry.rs`, `src/config/variables.toml`.

### quotes

**Purpose.** The sales document that precedes a project: a priced proposal to a company, sent to the customer, accepted or declined by a contact, then converted to a project. Source: `src/modules/quotes/`.

**Data model** (migrations `078`, `092`, `190`, `263`):
- `quotes`: `quote_number` (unique per tenant, prefix `QUO-` via `quote_sequences`), `title` (max 255), `summary`, `description`, `company_id` (NOT NULL), `billing_contact_id`, `status` CHECK `draft | submitted | approved | rejected | sent | accepted | declined | expired | converted | cancelled`, `valid_until`, `sent_at`, `decided_at`, `decided_by_contact_id`, `decision_notes`, `converted_project_id` (unique), `subtotal`, `tax_amount`, `total` (DECIMAL(12,2)), `tax_rate_id`, `tax_rate`, `currency`, `requested_by_id`, `delivery_method`, `delivery_note`, `delivered_by_id`, `emailed_to`, `emailed_at`. `total_cents` is a retained legacy column.
- `quote_lines`: `line_type` CHECK `service | product | labour | expense | adjustment | discount`, `description`, `quantity`, `unit_price`, `total`, `is_taxable`, `sort_order`.

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET, POST | `/quotes` | GET dual-plane (staff `RequireBilling`+`RequireFinance`; contact `quotes:read`, own company, client-visible statuses only); POST `RequireBilling`+`RequireFinance` | List / create |
| GET | `/quotes/{quote_id}` | dual-plane (`quotes:read`) | Detail with lines |
| PUT | `/quotes/{quote_id}` | `RequireBilling`+`RequireFinance` | Edit header (409 once frozen) |
| DELETE | `/quotes/{quote_id}` | `RequireBilling`+`RequireFinance` | Cancel (sets `cancelled`) |
| POST | `/quotes/{quote_id}/send` | `RequireBilling`+`RequireFinance` | Send an `approved` quote |
| GET | `/quotes/{quote_id}/delivery-options` | `RequireBilling`+`RequireFinance` | Per-method availability |
| POST | `/quotes/{quote_id}/convert` | `RequireBilling`+`RequireFinance` | Accepted quote -> project |
| POST | `/quotes/{quote_id}/accept`, `/quotes/{quote_id}/decline` | dual-plane (`quotes:accept`) | Client decision, optional `{notes}` |
| GET | `/quotes/{quote_id}/pdf` | dual-plane (`quotes:download_pdf`) | Answers 501 Not Implemented |
| POST | `/quotes/{quote_id}/lines` | `RequireBilling`+`RequireFinance` | Add line |
| PUT, DELETE | `/quotes/{quote_id}/lines/{line_id}` | `RequireBilling`+`RequireFinance` | Update / delete line |

Approval records for quotes hang off `/quotes/{entity_id}/approvals` in the approvals module (`src/modules/approvals/routes.rs`), outside this module.

**Behaviour.**
- Created as `draft`. Totals are computed server-side from lines (`recompute_totals` after every line change); a client total is never read. Tax follows the invoice rule: a given `tax_amount` clears the rate, a named `tax_rate_id` sets it, only create falls back to the tenant default; rate frozen on the quote.
- Frozen statuses (`is_frozen`): `sent`, `accepted`, `declined`, `expired`, `converted`, `cancelled`; header/line edits and cancel return 409.
- `send` is allowed only from `approved` (409 otherwise). Delivery `{method, note}` defaults to `email`; `email` needs a resolvable billing contact with an address (409), mails a portal link through the `quote.sent` notification inside the transaction (a relay refusal rolls back and writes a `quote.send_failed` audit row); `postal` and `other` attest a delivery; `other` needs a non-blank note (422).
- Client-visible statuses: `sent`, `accepted`, `declined`, `expired`, `converted`. Expiry is read-time: a `sent` quote whose `valid_until` is before the reader's today reads as `expired`; no job writes it. A contact decision is allowed only while the effective status is `sent` (409 otherwise), moves it to `accepted` or `declined`, records `decided_at`, `decided_by_contact_id`, `decision_notes`.
- `convert` locks the row, requires `accepted` (409 otherwise), inserts a project (`status planning`, `project_type client`, budget_amount = quote total, `billing_method` default `fixed_price`, optional manager and dates from the request), sets `converted_project_id` and status `converted`; converting an already converted quote returns it unchanged.
- unverified: no code under `src/` writes `submitted`, `approved` or `rejected` onto `quotes.status` (only `src/modules/quotes/service.rs` updates the table, and it writes `cancelled`, `sent`, `accepted`/`declined`, `converted`); how a quote reaches `approved` was not found.

**Background jobs.** None.

**Config.** None (tenant default tax rate and `billing_prefs/currency` are read through billing).

### contracts

**Purpose.** Service agreements per company: items, prepaid hour balances, billing cycle for recurring invoices, and rate cards for labour pricing. Source: `src/modules/contracts/`.

**Data model** (migrations `009`, `025`, `061`, `123`, `124`, `051`):
- `contracts`: `contract_number`, `name`, `company_id`, `contract_type` CHECK `managed_services | block_hours | time_and_materials | fixed_price | warranty`, `status` CHECK `draft | active | expired | cancelled | renewed` (default `draft`), `start_date`, `end_date`, `auto_renew`, `renewal_terms` JSONB (optional `term_months`), `billing_cycle` CHECK `monthly | quarterly | annually | one_time | weekly | bi_weekly` (default `monthly`), `billing_amount`, `sla_id`, `signed_date`, `signed_by_contact_id`, `notes`, `internal_notes`, `custom_fields`.
- `contract_items`: `item_type` CHECK `recurring_service | block_hours | retainer | product | one_time`, `quantity`, `unit_price`, `total_price`, `billing_frequency`, `work_type_id`, `included_hours`, `overage_rate`, `rollover_enabled`, `max_rollover_hours`, `product_id`, `billing_rule` CHECK `every_period | once | manual` (default `manual`; backfilled `every_period` for `recurring_service` and `retainer`), `billed_at`.
- `contract_hour_balances`: per item and period (`period_start`, `period_end`, `hours_included`, `hours_used`, `hours_remaining`, `rollover_hours`), unique per period (migration `025`).
- `rate_cards` (`name`, `is_default`, `default_per_mile_rate` DECIMAL(8,4)), `rate_card_items` (`work_type_id`, `hourly_rate`, `after_hours_rate`, `emergency_rate`; unique per card and work type), `contract_invoice_runs` (see billing).

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/contracts` | dual-plane (staff `RequireContracts`+`RequireFinance`; contact `contracts:read`, own company) | List |
| POST | `/contracts` | `RequireContracts`+`RequireFinance` | Create |
| GET | `/contracts/{id}` | dual-plane (`contracts:read`) | Read |
| PUT, DELETE | `/contracts/{id}` | `RequireContracts`+`RequireFinance` | Update / delete |
| GET, POST | `/contracts/{id}/items` | `RequireContracts`+`RequireFinance` | List / add item |
| PUT, DELETE | `/contract-items/{id}` | `RequireContracts`+`RequireFinance` | Update / delete item |
| GET | `/contracts/{id}/hour-balance` | `RequireContracts`+`RequireFinance` | Current period balance |
| GET, POST | `/rate-cards` | `RequireContracts`+`RequireFinance` | List / create |
| GET, PUT, DELETE | `/rate-cards/{id}` | `RequireContracts`+`RequireFinance` | Read / update / delete |
| GET, POST | `/rate-cards/{id}/items` | `RequireContracts`+`RequireFinance` | List / upsert item |
| DELETE | `/rate-card-items/{id}` | `RequireContracts`+`RequireFinance` | Delete item |

**Behaviour.**
- Validation: `name` 1-255; `contract_type`, `status` and `billing_cycle` validated against the closed sets above; `end_date` may not precede `start_date`.
- Lifecycle sweep (`expire_due_contracts`): for each `active` contract whose `end_date` is before the tenant's today: with `auto_renew` true, set `status = renewed` and advance `start_date` to the day after `end_date` and `end_date` by `renewal_terms.term_months`, else the whole-month span of the closing term (minimum 1 month); otherwise set `status = expired`. Each change writes an audit row. unverified: whether a `renewed` contract returns to `active`; recurring invoicing selects `status = 'active'` only.
- Prepaid block hours: `consume_hours` draws `hours_remaining` for the period found from the contract start and cycle; hours beyond the allotment are overage (`overage_hours`, `overage_rate` stored on the time entry). A draw is idempotent via `time_entries.hours_consumed IS NULL`; `release_hours` returns exactly the applied hours to the named balance row. `roll_to_next_period` (rollover, capped by `max_rollover_hours`) is defined in `service.rs` and has no caller elsewhere in `src/` (grep). `resolve_rate` picks a labour rate from rate cards.
- Items billed by recurring invoicing per `billing_rule`: `every_period` each period, `once` until `billed_at` is set, `manual` never automatically. Billing rules and prepaid rules: [billing invariants](invariants/billing.md).

**Background jobs.** `contract_lifecycle` (`ContractLifecycleWorker`), 3600 s, runs `expire_due_contracts` across all tenants in per-tenant batches on the migrator pool; recurring invoices are generated by billing's `recurring_invoicing`.

**Config.** None.

### expenses

**Purpose.** The payables plane: vendors, expense categories, vendor bills with payments, and employee expense claims with an approval and reimbursement flow, with optional push to Xero or QuickBooks. Source: `src/modules/expenses/`.

**Data model** (migrations `279`, `285`, `286`, `287`, `289`, `293`):
- `vendors` (`name`, `account_number`, `default_currency`, `notes`), `expense_categories` (`name` unique case-insensitively per tenant, `is_active`).
- `bills`: `vendor_id` (RESTRICT), `bill_number`, `issue_date`, `due_date`, `currency`, `subtotal_minor`, `tax_minor`, `total_minor`, `paid_minor` (bigint minor units), `status` CHECK `draft | approved | paid | void`, `external_provider`, `external_bill_id`. `bill_lines` (`category_id`, `description`, `quantity_hundredths`, `unit_price_minor`, `tax_minor`, `total_minor`, `position`).
- `bill_payments`: `paid_on`, `amount_minor` (CHECK > 0), `payment_method` CHECK `check | credit_card | ach | wire | cash | other`, `reference`, `notes`.
- `expenses`: `user_id` (RESTRICT), `incurred_on`, `currency`, `subtotal_minor`, `tax_minor`, `total_minor`, `status` CHECK `draft | submitted | approved | reimbursed | rejected`, `approver_id`, `approved_at`, `reimbursed_at`, `external_provider`, `external_expense_id`. `expense_lines` (`category_id`, `description`, `amount_minor`, `tax_minor`, `position`).
- Mapping tables are listed under billing.

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET, POST | `/vendors` | `RequireBilling`+`RequireFinance` | List / create |
| GET, PUT, DELETE | `/vendors/{id}` | `RequireBilling`+`RequireFinance` | Read / update / delete |
| GET, POST | `/expense-categories` | `RequireBilling`+`RequireFinance` | List / create |
| PUT | `/expense-categories/{id}` | `RequireBilling`+`RequireFinance` | Update (no DELETE route) |
| GET, POST | `/bills` | `RequireBilling`+`RequireFinance` | List (`status`, `q`) / create (raises the provider bill first when delegated) |
| GET | `/bills/{id}` | `RequireBilling`+`RequireFinance` | Read with lines |
| POST | `/bills/{id}/approve` | `RequireBilling`+`RequireFinance` | `draft -> approved` |
| POST | `/bills/{id}/void` | `RequireBilling`+`RequireFinance` | `draft|approved -> void` |
| GET, POST | `/bills/{id}/payments` | `RequireBilling`+`RequireFinance` | List / record a payment (pushes to the provider first when delegated) |
| GET, POST | `/expenses` | `RequireBilling` only; list is own claims unless the caller is a finance-capable role | List (`status`, `q`) / create for the caller |
| GET | `/expenses/{id}` | `RequireBilling`; owner or finance-capable role | Read with lines |
| POST | `/expenses/{id}/submit` | `RequireBilling`; owner or finance-capable role | `draft -> submitted` |
| POST | `/expenses/{id}/approve` | `RequireBilling`+`RequireFinance` | `submitted -> approved`, records approver |
| POST | `/expenses/{id}/reject` | `RequireBilling`+`RequireFinance` | `submitted -> rejected` |
| POST | `/expenses/{id}/reimburse` | `RequireBilling`+`RequireFinance` | `approved -> reimbursed` |

"Finance-capable role" is `user.role.can_manage_billing()`. Source: `src/modules/expenses/routes.rs`.

**Behaviour.**
- Bill statuses: `draft -> approved` (approve), `draft|approved -> void`, `approved -> paid` only through payment recording. A draft bill cannot be paid, a void bill cannot be paid, amount must be > 0 and <= remaining (`total_minor - paid_minor`); all four refusals are 409/400 with a reason. `recompute_bill_payment_state` is the single writer of `paid_minor` (SQL sum over `bill_payments`, bill row locked `FOR UPDATE`); a part-paid bill stays `approved`.
- Expense statuses: `draft -> submitted -> approved -> reimbursed`, and `submitted -> rejected`. Any other transition is 409; `reimbursed` is terminal. Transitions lock the row `FOR UPDATE`.
- Validation: `currency` 3 letters (uppercased), at least one line for a bill or an expense (field error), `status` and `q` filters max 20 and 200.
- Delegated bills (`delegated_bills` feature on AND tenant delegates `BillsAndExpenses`): `create_bill` pushes to the provider before the local write, a refusal leaves nothing; vendor mapping (and, for QuickBooks, expense-account mapping per line) required, else 409 naming the route that sets it. `pay_bill` pushes the payment to the provider before the local write; `record_bill_payment` is the inner writer that pushes nothing. Inbound provider payment webhooks reconcile `paid_minor` to the provider's running total (idempotent by difference) through `record_bill_payment`; a provider-voided bill is left for an operator.
- Delegated claims: only `reimburse` pushes (Xero `SPEND` bank transaction, QuickBooks purchase), before the write transaction, needing `integrations.external_payment_account_id`, the expense-account mapping and (Xero) the user mapping; a refusal leaves the claim `approved`.
- Detail: [billing invariants](invariants/billing.md#single-writer), [delegated issuing](invariants/billing.md#delegated-issuing).

**Background jobs.** None.

**Config.** Feature toggle `delegated_bills`; Xero and QuickBooks keys as listed under billing.

### time_tracking

**Purpose.** Time entries, running timers, weekly timesheet submission and approval, rounding rules, work types, and a per-person work-day clock. Source: `src/modules/time_tracking/`, DTOs in `crates/mokosh-types/src/time_tracking.rs`.

**Data model** (migrations `006`, `033`, `055`, `081`, `119`, `120`, `121`, `125`, `188`, `191`):
- `work_types` (`name`, `default_billable`, `default_rate`, `is_active`, `sort_order`), `time_rounding_rules` (`increment_minutes` default 15, `rounding_method` CHECK `up | down | nearest`, `minimum_minutes`, `is_default`).
- `time_entries`: `user_id`, `date`, `start_time`, `end_time`, `duration_minutes` (NOT NULL), `worked_minutes`, `billable_minutes`, `work_type_id` (NOT NULL), `ticket_id`, `project_id`, `task_id`, `company_id` (nullable), `contract_id`, `entry_kind` CHECK `client | employee` (CHECKs: client needs a company; employee carries no ticket/project/task/contract), `work_category` CHECK `ticketed | project | general`, `is_billable`, `billing_status` CHECK `not_billed | ready_to_bill | billed | prepaid`, `invoice_id`, `hourly_rate`, `total_amount`, `approval_status` CHECK `draft | pending | approved | rejected` (default `draft`), `approved_by_id`, `approved_at`, `rejection_reason`, `hours_consumed`, `hours_balance_id`, `overage_hours`, `overage_rate`.
- `active_timers` (unique `user_id`: one timer per person), `work_day_segments` (`kind` CHECK `work | break`, `started_at`, `ended_at`, `date`; partial unique index allows one open segment per user).
- A timesheet is not a table: it is aggregated per user and Monday-anchored week from `time_entries`.

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET, POST | `/work-types` | `RequireTimeTracking`; POST also `RequireAdmin` | List / create |
| PUT, DELETE | `/work-types/{id}` | `RequireTimeTracking`+`RequireAdmin` | Update / delete |
| GET, POST | `/time-entries` | `RequireTimeTracking` | List / create (non-admin is forced to log for self) |
| GET | `/time-entries/summary` | `RequireTimeTracking` | Minute sums |
| GET, PUT, DELETE | `/time-entries/{id}` | `RequireTimeTracking`; PUT and DELETE owner or admin (403 otherwise) | Read / edit / delete |
| GET | `/timesheets` | `RequireTimeTracking`+`RequireTimesheets` | Weekly summaries; `status` `pending|approved|rejected|all`; range capped at 26 weeks |
| POST | `/timesheets/{user_id}/{week_start}/submit` | `RequireTimeTracking`+`RequireTimesheets`; owner or admin | Entries -> `pending` |
| POST | `/timesheets/{user_id}/{week_start}/withdraw` | same | `pending` -> `draft` |
| POST | `/timesheets/{user_id}/{week_start}/approve` | `RequireTimeTracking`+`RequireTimesheets`+`RequireManager` | `pending` -> `approved` |
| POST | `/timesheets/{user_id}/{week_start}/reject` | same | `pending` -> `rejected` with `reason` |
| GET | `/timers/active` | `RequireTimeTracking` | Active timers |
| POST | `/timers/start` | `RequireTimeTracking` | Start caller's timer |
| POST | `/timers/{id}/stop` | `RequireTimeTracking` | Stop and create the entry |
| GET | `/workday` | `RequireTimeTracking`+`RequireTimesheets` | Day view derived from segments and entries |
| POST | `/workday/clock-in`, `/workday/clock-out` | same | Open / close the caller's segment |
| POST | `/workday/break/start`, `/workday/break/end` | same; 404 when `timesheets/track_breaks` is off | Break segments |
| PUT, DELETE | `/workday/segments/{id}` | same plus policy `timesheets/segment_editing` (`off | owner_or_admin | owner_or_manager`, default `owner_or_admin`) | Correct or remove a segment |
| GET, POST | `/time-rounding-rules` | `RequireTimeTracking`; POST also `RequireAdmin` | List / create |
| PUT, DELETE | `/time-rounding-rules/{id}` | `RequireTimeTracking`+`RequireAdmin` | Update / delete |

**Behaviour.**
- Entry validation: `duration_minutes` and `worked_minutes` 1-1440, `billable_minutes` 0-1440. Referenced work type, ticket, company, project, task are checked to belong to the tenant (400). Per-day cap: worked minutes per user and date may not exceed `time_tracking/max_hours_per_day` (default 24 hours), enforced inside the insert/update transaction.
- Kind: derived as `client` when a ticket, project, task or contract is named, else `employee` when no company or the tenant's own company, else `client`; an explicit `entry_kind` is validated. Employee time is never billable and bills nobody. `work_category` derived (`ticketed` with ticket, `project`, else `general`); `ticketed` requires a `ticket_id`.
- Rounding: billable minutes derive from the default rounding rule: floor at `minimum_minutes`, then round to `increment_minutes` by `up`, `down` or `nearest` (exact midpoint rounds up); worked minutes are stored unrounded; `total_amount` is priced on billable minutes.
- Billing status is armed at creation: billable client entry -> `ready_to_bill`, else `not_billed`; `billed` is never re-armed; `prepaid` is set by the block-hours draw and is not sticky. Contract is derived from the company's covering block-hours contract and the draw happens at create (re-draw on update, release on delete), not on approval.
- Timesheet statuses are the entries' `approval_status`: `draft` -> `pending` (submit; approved entries untouched) -> `approved` or `rejected` (manager); withdraw is refused with 409 once any entry in the week is approved; approve and reject are idempotent per pending entry.
- Timer: one active timer per user (409 on a second start); stop creates a time entry dated in the timer owner's zone. unverified: the stop route passes only the timer id (no caller id) and no ownership check was seen in the route or in `stop_timer`.
- Work day: no day row; clock-in opens a `work` segment (409 when one is open), clock-out closes the open segment, break start/end swap `work` and `break` segments in one transaction. Detail: [time invariants](invariants/time.md).

**Background jobs.** None.

**Config.** Tenant settings `time_tracking/max_hours_per_day`, `timesheets/track_breaks`, `timesheets/segment_editing`; module gates `time_tracking` and `timesheets` (the latter defaults on for `org` tenants and off for `personal` tenants).

### mileage_tracking

**Purpose.** Distance-based entries logged from the Log Time form, invoiced as `mileage` lines. Source: `src/modules/mileage_tracking/`, DTOs in `crates/mokosh-types/src/mileage_tracking.rs`.

**Data model** (migration `051`): `mileage_entries`: `user_id`, `date`, `distance_miles` NUMERIC(8,2) CHECK > 0, `start_address`, `end_address`, `ticket_id`, `project_id`, `task_id`, `company_id` (NOT NULL), `contract_id`, `is_billable` (default true), `rate_per_mile` NUMERIC(8,4), `total_amount`, `billing_status` CHECK `not_billed | ready_to_bill | billed`, `invoice_id`, `approval_status` CHECK `draft | pending | approved | rejected`, `approved_by_id`, `approved_at`, `rejection_reason`. Also `rate_cards.default_per_mile_rate`.

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET, POST | `/mileage-entries` | `RequireTimeTracking` | List / create |
| GET, PUT, DELETE | `/mileage-entries/{id}` | `RequireTimeTracking`; PUT and DELETE owner or admin (403 otherwise) | Read / edit / delete |

**Behaviour.** `distance_miles` must be positive with at most 2 decimals (422 field error; service also returns 400 for <= 0); `rate_per_mile` is non-negative with at most 4 decimals. Rate precedence: request rate, else the tenant default rate card's `default_per_mile_rate`, else none (unpriced); `total_amount = rate * distance` only for billable entries with a rate. A billable entry is `ready_to_bill` on creation. Foreign ids are validated against the tenant. Invoiced by billing's from-time-entries builder.

**Background jobs.** None.

**Config.** None; gated by the `time_tracking` module.

### projects

**Purpose.** Client and internal projects with phases, tasks, task statuses, dependencies and project types. Source: `src/modules/projects/`.

**Data model** (migrations `007`, `048`, `059`):
- `projects`: `name` (1-80 on request), `description`, `project_number`, `company_id` (nullable: house projects), `contract_id`, `project_type` (text), `project_type_id` -> `project_types`, `status` CHECK `planning | active | on_hold | completed | cancelled`, `project_manager_id`, `start_date`, `target_end_date`, `actual_end_date`, `budget_hours`, `budget_amount`, `billing_method` CHECK `fixed_price | time_and_materials | not_billable`, `hourly_rate`, `is_billable`, `default_due_business_days` (0-365), `custom_fields`, `tags`.
- `project_phases` (`status` CHECK `not_started | in_progress | completed`, `sort_order`, dates), `task_statuses` (`name`, `color` max 7, `is_completed`), `tasks` (`project_id`, `phase_id`, `parent_task_id`, `title` max 255, `status_id` NOT NULL, `priority` CHECK `low | medium | high | critical`, `assigned_to_id`, `estimated_hours`, `actual_hours`, `start_date`, `due_date`, `completed_at`, `checklist` JSONB, `tags`), `task_dependencies` (`dependency_type` CHECK `finish_to_start | start_to_start | finish_to_finish`; unique per pair), `project_types` (`name` unique per tenant, `is_default`, `is_active`, `is_system`; seeded `client` and `internal`).

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/projects` | dual-plane (staff `RequireProjects`; contact `projects:read`, own company, plus house projects with NULL company per the handler note) | List |
| POST | `/projects` | `RequireProjects` | Create |
| GET | `/projects/summary` | `RequireProjects` | Counts by status |
| GET | `/projects/{id}` | dual-plane (`projects:read`) | Read |
| PUT | `/projects/{id}` | `RequireProjects` | Update |
| DELETE | `/projects/{id}` | `RequireProjects`+`RequireAdmin` | Delete |
| GET, POST | `/projects/{id}/phases` | `RequireProjects` | List / create phase |
| PUT, DELETE | `/phases/{phase_id}` | `RequireProjects` | Update / delete phase |
| GET, POST | `/task-statuses` | `RequireProjects`; POST also `RequireAdmin` | List / create |
| PUT, DELETE | `/task-statuses/{id}` | `RequireProjects`+`RequireAdmin` | Update / delete |
| GET, POST | `/project-types` | `RequireProjects`; POST also `RequireAdmin` | List / create |
| PUT, DELETE | `/project-types/{id}` | `RequireProjects`+`RequireAdmin` | Update / delete |
| GET, POST | `/projects/{id}/tasks` | `RequireProjects` | List / create task |
| GET, PUT, DELETE | `/tasks/{id}` | `RequireProjects` | Read / update / delete task |
| POST, DELETE | `/tasks/{id}/depends-on/{other}` | `RequireProjects` | Add / remove dependency |

**Behaviour.** No new phase or task may be added to a `cancelled` project (409). A task cannot depend on itself (400), and an edge that would close a cycle is refused (409). Task `start_date` must not follow `due_date` (400, evaluated against stored dates on partial updates). Moving a task to a status with `is_completed` stamps `completed_at`; moving off clears it. System project types cannot be deleted and a type referenced by a project cannot be deleted (409). Project and task `actual_hours` and `actual_amount` are aggregates counting time entries with `approval_status <> 'rejected'`. Budget hours, budget amount and rate are range-validated. Quote conversion creates projects (see quotes).

**Background jobs.** None.

**Config.** None; gated by the `projects` module.

### opportunities

**Purpose.** CRM pipeline: leads tracked against a company through stages to won or lost, with an optional link to the quote raised from them. Source: `src/modules/opportunities/`.

**Data model** (migration `249`): `opportunities`: `company_id` (NOT NULL), `contact_id`, `title` (1-255), `value_amount` NUMERIC(14,2) CHECK >= 0, `currency` (default `USD`), `stage` CHECK `lead | qualified | proposal | negotiation | won | lost`, `expected_close_date`, `outcome` CHECK `won | lost`, `quote_id`, `notes`, `created_by_id`, `closed_at`, `deleted_at` (soft delete). Table CHECK: a closed stage (`won`, `lost`) must carry an outcome and an open stage must not.

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET, POST | `/crm/opportunities` | `RequireAuth` (no module gate) | List (filters `company_id`, `stage`, `closed`) / create |
| GET, PUT | `/crm/opportunities/{id}` | `RequireAuth` | Read / update |
| DELETE | `/crm/opportunities/{id}` | `RequireManager`+`RequireAuth` | Soft delete |
| POST | `/crm/opportunities/{id}/close` | `RequireAuth` | Close with `outcome` (`won | lost`) and optional `quote_id` |

**Behaviour.** Created open (default stage `lead`; a closed stage on create or update is a 422 pointing at the close endpoint). Company, contact and quote must exist in the tenant (422 field error). Currency must be a 3-letter code. A closed opportunity is immutable (400 on update or a second close). Close writes stage, outcome and `closed_at` in one statement, and for `won` links a given `quote_id` (else keeps the existing link). Reads exclude soft-deleted rows.

**Background jobs.** None.

**Config.** None.

### calendar

**Purpose.** Appointments with recurrence, per-user availability, time off with approval, on-call rotations, scheduling templates and the aggregated dispatch board. Source: `src/modules/calendar/`.

**Data model** (migrations `008`, `028`, `056`, `187`):
- `appointments`: `title`, `appointment_type` CHECK `ticket | project | meeting | other`, `ticket_id`, `project_id`, `task_id`, `company_id`, `contact_id`, `site_id`, `team_id`, `assigned_to_id` (NOT NULL), `start_time`, `end_time`, `all_day`, `timezone`, `status` CHECK `scheduled | in_progress | completed | cancelled`, `location`, `recurrence_rule` (RFC 5545 RRULE text), `recurrence_parent_id`, `reminder_minutes` INTEGER[].
- `user_availability` (`day_of_week` 0-6, `start_time`, `end_time`, `is_available`), `time_off` (`type` CHECK `vacation | sick | personal | holiday | other`, `status` CHECK `pending | approved | rejected`, `approved_by_id`), `on_call_schedules` (`rotation_type` CHECK `weekly | daily | custom`, `rotation_config` JSONB, `team_id`, `is_active`), `scheduling_templates` (`kind` CHECK `dispatch | calendar`, `duration_minutes` > 0, `travel_before_minutes`, `travel_after_minutes` >= 0), `appointment_reminders` (unique `appointment_id, occurrence_start, reminder_minutes`).

**API.** All handlers carry `RequireCalendar` unless noted.

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET, POST | `/appointments` | `RequireCalendar` | List with bounded range, recurrence expanded in memory / create |
| GET | `/calendar/appointments` | `RequireCalendar` | Alias of the list |
| GET, PUT, DELETE | `/appointments/{id}` | `RequireCalendar` | Read / update / delete |
| GET, PUT | `/users/{user_id}/availability` | `RequireCalendar` | Read / replace weekly windows |
| GET, POST | `/time-off` | `RequireCalendar` | List / request |
| GET, DELETE | `/time-off/{id}` | `RequireCalendar` | Read / delete |
| POST | `/time-off/{id}/approval` | `RequireCalendar`+`RequireManager` | Body `{status: approved | rejected}` |
| GET | `/on-call-schedules` | `RequireCalendar` | List |
| POST | `/on-call-schedules` | `RequireCalendar`+`RequireManager` | Create |
| PUT, DELETE | `/on-call-schedules/{id}` | `RequireCalendar`+`RequireManager` | Update / delete |
| GET | `/on-call/now` | `RequireCalendar` | Who is on call now |
| GET, POST | `/scheduling-templates` | `RequireCalendar` | List / create |
| GET, PUT, DELETE | `/scheduling-templates/{id}` | `RequireCalendar` | Read / update / delete |
| GET | `/dispatch` | `RequireCalendar` | Board for `from`, `to`, optional `assigned_to_id`: appointments (expanded), availability, time off, on-call |

**Behaviour.** `end_time` must be after `start_time` (400); every availability window must also end after it starts; time off needs `end_date >= start_date` (400). A non-blank `recurrence_rule` must parse as RFC 5545 against the start time (422 field error); expansion is capped at 1000 occurrences per series. Every foreign id in a body must belong to the tenant (400 `Referenced <table> not found in this tenant`). Time off is created `pending`; only a manager role decides it. Reminders: an appointment with `reminder_minutes` produces a reminder at each offset before each occurrence start, once per (appointment, occurrence, offset) via `appointment_reminders`, dispatched as the `appointment.reminder` notification to the assignee; a failed dispatch is logged with a warning and the ledger row stays stamped.

**Background jobs.** `CalendarReminderWorker`, every 60 s: enumerates due reminders across tenants on the migrator pool (cross-tenant read), then claims and dispatches per tenant.

**Config.** None.

## 7. Assets, integrations, knowledge base and platform-feature modules


Conventions used below. `RequireKB` is shorthand for the `RequireKnowledgeBase` extractor. All paths are under `/api/v1` unless stated. "Module gate" means the tenant's `module_config` row for that module name is enabled; a missing row reads as disabled and the gated extractor answers 404 (`src/modules/auth/middleware.rs`, `SettingsService::is_module_enabled` in `src/modules/settings/service.rs`; see [E2E notes](e2e.md)). `RequireAdmin` admits `admin`/`super_admin`; `RequireManager` admits `super_admin`/`admin`/`manager` (`ManagerRoles`). Queries run through `Database::begin_with_tenant` and every table below carries `tenant_id`; RLS policies are stated per table only where the migration read this session enables them (unverified: RLS state of tables created in migrations 011, 012, 014, which were not checked for a later policy). Mounting is in `src/api/router.rs`.

### assets

**Purpose.** CMDB for client assets: asset types, assets, relationships with impact-graph traversal, encrypted configuration items, an encrypted credential vault with audited reveal, and a per-asset audit log. Files: `src/modules/assets/{routes,service,models}.rs`.

**Data model** (migrations `011_assets.sql`, `044`, `063`, `065`, `080`, `248`, `270`, `271`, `275`):
- `asset_types`: `name` (1-100), `icon`, `parent_type_id` (self FK), `custom_fields_schema` JSONB, `is_active`, `itil_category` VARCHAR(50) free text (065). Migration 248 seeds a `Website` type per tenant (and the default tenant that new tenants copy from) and backfills one asset per company with a non-blank `companies.website`; `companies.website` stays as a deprecated column.
- `assets`: `asset_tag` (system generated, see Behaviour), `name` (1-255), `asset_type_id` NOT NULL, `company_id` NOT NULL, `site_id`, `contact_id`, `status` CHECK in (`active`,`inactive`,`retired`,`in_repair`,`in_stock`,`in_transit`), `manufacturer`, `model`, `serial_number`, `purchase_date`, `purchase_price` DECIMAL(12,2), `warranty_expiry`, `end_of_life`, `rmm_device_id`, `last_sync_at`, `custom_fields` JSONB, `tags` TEXT[], `notes`, plus (063) `assigned_user_id`, `ip_address` INET, `hostname`, `mac_address`, `installed_date`, `department`, `in_transit_ticket_id` (FK tickets, SET NULL); (065) `itil_lifecycle_stage`; (080) `license_vendor`, `license_seat_count` (CHECK >= 0), `license_expiry`; (271) `asset_model_id` (FK `asset_models`, SET NULL); (270) `search_haystack` STORED generated lowercase concat of name, asset_tag, serial_number, hostname, host(ip_address), mac_address, manufacturer, model, department, notes, with a pg_trgm GIN index; GIN on `tags`; btree partials on `warranty_expiry` and `end_of_life`. Unique index `uq_assets_tenant_asset_tag_ci` on `(tenant_id, lower(asset_tag))` where tag is not null (275).
- `asset_tag_counters` (275): PK `tenant_id`, `next_number` BIGINT; RLS enabled and forced.
- `asset_relationships`: `parent_asset_id`, `child_asset_id` (both FK assets, CASCADE), `relationship_type` CHECK in (`contains`,`connected_to`,`depends_on`,`hosts`), UNIQUE `(parent_asset_id, child_asset_id, relationship_type)`.
- `configuration_items`: `asset_id` (CASCADE), `name` (1-100), `category`, `value_encrypted` NOT NULL, `notes`.
- `credential_vault`: `name`, `company_id`, `asset_id`, `credential_type` CHECK in (`local_admin`,`domain`,`ssh`,`api`,`other`), `username_encrypted`, `password_encrypted`, `notes_encrypted`, `url` VARCHAR(500), `last_rotated`. Secrets are AES-256-GCM under `ENCRYPTION_KEY` (`utils::crypto`). Table comment (migration 250) records the stance: secrets stay local, reads go through the audited reveal.
- `asset_audit_log`: `asset_id` NOT NULL with no FK (dropped in 044 so rows outlive the asset), `action` CHECK in (`created`,`updated`,`synced`,`status_changed`,`deleted`), `changes` JSONB, `performed_by_id`, `performed_at`.
- Setting `ci/impact_max_depth` in `tenant_settings` (074), default 5 (see settings).
- Migration 045 is a guard that raises if any `credential_vault` or `configuration_items` row exists at migrate time (rows written under the former all-zero key).

**API.** Router `assets_routes` (`src/modules/assets/routes.rs`), merged at the `/api/v1` root. `RequireAssets` = authenticated staff plus the `assets` module gate.

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/asset-types` | RequireAssets | Paginated list |
| POST | `/asset-types` | RequireAssets + RequireAdmin | Create (audited) |
| PUT | `/asset-types/{id}` | RequireAssets + RequireAdmin | Update |
| DELETE | `/asset-types/{id}` | RequireAssets + RequireAdmin | Delete (404 if absent) |
| GET | `/assets` | RequireCallerContext (staff, or contact with `assets:read`) | Filtered paginated list; contact arm forces `company_id` to the session company and returns `ContactAssetResponse` |
| POST | `/assets` | RequireAssets | Create; audited |
| POST | `/assets/search` | RequireAssets + toggle `assets_search_v2` | Structured filter search |
| POST | `/assets/search/facets` | RequireAssets + toggle `assets_search_v2` | Facet counts for the same filter |
| POST | `/assets/bulk-create` | RequireAssets + toggle `assets_catalog` | Fan-out create from a catalog model |
| POST | `/assets/exists` | RequireAssets | Which serials already exist for a company |
| GET | `/assets/{id}` | RequireCallerContext (contact needs `assets:read` and same company, else 404) | Get |
| PUT | `/assets/{id}` | RequireAssets | Full update |
| PATCH | `/assets/{id}` | RequireAssets | Partial update (only sent keys) |
| DELETE | `/assets/{id}` | RequireAssets + RequireAdmin | Delete |
| GET | `/assets/{id}/relationships` | RequireAssets | Paginated list |
| POST | `/assets/{id}/relationships` | RequireAssets | Create (id is the parent) |
| DELETE | `/asset-relationships/{id}` | RequireAssets | Delete |
| GET | `/assets/{id}/impact` | RequireAssets | Upstream/downstream traversal |
| POST | `/assets/{id}/report-issue` | RequireCallerContext (contact needs `assets:report_issue` and same company) | Create a ticket linked to the asset |
| GET | `/assets/{id}/configuration-items` | RequireAssets | List without values |
| POST | `/assets/{id}/configuration-items` | RequireAssets | Upsert one item (value encrypted) |
| GET | `/configuration-items/{id}` | RequireAssets | Reveal decrypted value (audit row) |
| DELETE | `/configuration-items/{id}` | RequireAssets | Delete |
| GET | `/assets/{id}/credentials` | RequireAssets | List summaries (no secrets) |
| POST | `/assets/{id}/credentials` | RequireAssets | Create (username, password, notes encrypted; audited) |
| GET | `/credentials/{id}` | RequireAssets | Reveal decrypted credential (audit row) |
| DELETE | `/credentials/{id}` | RequireAssets | Delete (audited, secrets omitted from the snapshot) |
| GET | `/assets/{id}/audit-log` | RequireAssets + RequireAdmin | Paginated asset audit log |

**Behaviour.**
- Asset tag: `create_asset` rejects a caller-supplied `asset_tag` (422 on field `asset_tag`); `PATCH` rejects it too ("read-only; delete and recreate"). The server issues `AST-` plus a number zero-padded to width 3 via `reserve_asset_tags`, an atomic `INSERT ... ON CONFLICT DO UPDATE` on `asset_tag_counters`; the first call seeds the counter from the highest existing `AST-<n>` tag. `bulk-create` also refuses a per-serial `asset_tag`. Assets created by the RMM sync worker leave `asset_tag` NULL (its INSERT lists no tag column).
- Validation (`models.rs`): `ip_address` via `validate_ip_address` (max 45), `mac_address` via `validate_mac_address` (max 50), `hostname` max 255, `license_seat_count` >= 0; list filter `q` max 200, `warranty_within_days` 0-36500.
- Audit: create writes `asset_audit_log` `created`; a status change writes `status_changed`; delete writes `deleted` in the same transaction before the DELETE; credential reveal and configuration-item reveal each write an `asset_audit_log` row with action `synced` and `changes` `{"event":"credential_read"}` / `{"event":"config_item_revealed"}`. Generic `audit_write` rows are also written for type, asset, relationship, credential mutations.
- Impact graph: `direction` = `upstream|downstream|both` (default `both`, other value 400), `depth` default 10, effective depth = `clamp(requested, 1, 10).min(tenant ci/impact_max_depth)`; recursive CTEs (`DOWNSTREAM_CTE`, `UPSTREAM_CTE`) return nodes tagged with direction and depth; 404 if the root asset is missing.
- Structured search (`validate_search_request`): `tags` accepts only `ContainsTag`; `IsNull/IsNotNull` need empty values; `Within` only on warranty_expiry, end_of_life, purchase_date, installed_date and needs `values[0].days` integer; `Before/After` only on those date fields with one value; `Eq` needs one value; `In/NotIn` need non-empty values. A violation is a 422 on `filters[i]`. When the toggle is off the routes answer 404 "not enabled on this deployment".
- Bulk create (toggle `assets_catalog` else 404): 1-500 `serials` (each serial 1-100, optional name 1-255, hostname max 255, mac/ip validated); `template_id` takes precedence over `asset_model_id` and the template's company, site, assigned user, department override the request's; model, company, site, user are checked up front with 422 naming the field; one transaction, all-or-nothing; default name `"{manufacturer} {model} #{serial}"`; warranty and end-of-life dates derive from the model's months; model `uses_count` and template `uses_count` are bumped; returns 201 `{created, count}`.
- `POST /assets/exists`: `company_id` plus 1-500 serials, case-insensitive match, returns the subset that exists.
- `report-issue`: staff path creates an `Internal`-source ticket with `asset_id`; contact path creates a portal ticket for the asset's company then stamps `tickets.asset_id`; default title `"Reported issue: {asset name}"`.
- Asset type delete and asset delete with dependent rows: unverified how a foreign-key refusal maps to an HTTP status.

**Background jobs.** None in this module (asset rows are also written by the RMM sync worker, see rmm).

**Config.** `ENCRYPTION_KEY` (32 bytes, via `AssetsService::with_encryption_key`). Feature toggles `assets_search_v2`, `assets_catalog` ([feature toggles](feature-toggles.md)). Tenant setting `ci/impact_max_depth`.

### asset_catalog

**Purpose.** Per-tenant catalog of device models and saved bulk-order templates that feed `POST /assets/bulk-create`, plus a hot-pattern detector that suggests new catalog entries. Files: `src/modules/asset_catalog/{routes,service,models,job}.rs`.

**Data model** (`271_asset_catalog.sql`, `272_asset_signature_candidates_mv.sql`, `273_asset_catalog_seed.sql`):
- `asset_models`: `manufacturer` (<=100), `model` (<=100), `asset_type_id` (FK `asset_types`, NO ACTION), `warranty_months`, `end_of_life_months` (0-600 validated), `default_department`, `default_license_vendor`, `default_tags` TEXT[], `specs` JSONB, `image_url`, `source` CHECK in (`seeded`,`tenant_authored`,`auto_derived`), `uses_count`. Unique `(tenant_id, lower(manufacturer), lower(model), asset_type_id)`; trigram GIN on `lower(manufacturer || ' ' || model)`. RLS enabled and forced.
- `asset_templates`: `name` (1-150, unique per tenant case-insensitive), `asset_model_id` (CASCADE), optional `company_id`, `site_id`, `default_assigned_user_id`, `department`, `tags`, `notes`, `license_seat_count` (0-100000 validated), `created_by`, `uses_count`. RLS enabled and forced.
- Materialized view `asset_signature_candidates_mv`: assets created in the last 7 days with manufacturer and model set, grouped by tenant, lower(manufacturer), lower(model), asset_type_id, `HAVING COUNT(*) >= 5`; unique index so it can refresh concurrently.
- Migration 273 seeds `source = 'seeded'` models for the default tenant, re-copied into new tenants by `TenantService` (re-linked by asset type name).

**API.** Merged at the `/api/v1` root. Every handler first requires toggle `assets_catalog` (404 otherwise).

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/asset-models` | RequireAssets | Typeahead; `q` (<=200) substring on `lower(manufacturer || ' ' || model)`, `limit` default 10 clamped 1-50, ordered by `uses_count DESC` |
| POST | `/asset-models` | RequireAssets + RequireAdmin | Create; duplicate shape is 409 |
| GET | `/asset-models/signature-detector` | RequireAssets | Top un-catalogued (or `auto_derived`) hot pattern, or `{signature: null}`; window 7 days |
| GET | `/asset-models/{id}` | RequireAssets | Get |
| PUT | `/asset-models/{id}` | RequireAssets + RequireAdmin | Update; duplicate shape 409 |
| DELETE | `/asset-models/{id}` | RequireAssets + RequireAdmin | Delete (templates cascade, assets keep NULL model) |
| GET | `/asset-templates` | RequireAssets | List, joined to model, ordered `updated_at DESC` |
| POST | `/asset-templates` | RequireAssets + RequireAdmin | Create; duplicate name 409 |
| GET | `/asset-templates/{id}` | RequireAssets | Get |
| PUT | `/asset-templates/{id}` | RequireAssets + RequireAdmin | Update |
| DELETE | `/asset-templates/{id}` | RequireAssets + RequireAdmin | Delete |

**Behaviour.** `asset_type_id` on a model must exist in the tenant (422 on `asset_type_id`). The static route `/asset-models/signature-detector` is registered before `/asset-models/{id}`. Detector result carries `manufacturer`, `model`, `asset_type_id`, `recent_count`, `window_days: 7`, `existing_model_id`, and `template_suggestion.name_hint` = `"{manufacturer} {model}"`.

**Background jobs.** `asset_signature_detector_refresh`, every 60 s (`src/main.rs`, `job.rs`): `REFRESH MATERIALIZED VIEW CONCURRENTLY asset_signature_candidates_mv`. Runs once at scheduler start as well.

**Config.** Toggle `assets_catalog`. No env vars.

### rmm

**Purpose.** Stores RMM connections, maps RMM devices to assets and companies, syncs devices on a schedule, and turns signed inbound alerts into tickets by rule. Files: `src/modules/rmm/{routes,service,provider,worker,models}.rs`.

**Data model** (`014_rmm.sql`, `022_rmm_mesh_central_provider.sql`):
- `rmm_connections`: `name` (1-100), `provider` CHECK in (`tactical_rmm`,`mesh_central`,`datto`,`connectwise`,`ninja_rmm`), `api_url` (VARCHAR 500, validated as URL), `api_key_encrypted` NOT NULL, `api_secret_encrypted`, `is_active` default FALSE, `sync_interval_minutes` default 60, `last_sync_at`, `sync_status` CHECK in (`never`,`success`,`failed`,`in_progress`), `last_error`.
- `rmm_device_mappings`: `rmm_connection_id` (CASCADE), `rmm_device_id` (<=255), `asset_id` (SET NULL), `company_id` (SET NULL since 113), `device_name`, `device_info` JSONB, `last_seen`, `sync_status` CHECK in (`pending`,`synced`,`error`), UNIQUE `(rmm_connection_id, rmm_device_id)`.
- `rmm_alert_rules`: `rmm_connection_id` (CASCADE), `name`, `alert_type` (NULL matches any), `severity_mapping` JSONB, `auto_create_ticket` default TRUE, `ticket_template` JSONB, `assign_to_id`, `queue_id`, `is_active`, `suppression_rules` JSONB.
- `rmm_connections` is deliberately not an `integrations` provider (`252_integrations.sql` comment).

**API.** Merged at the `/api/v1` root. `RequireRmm` = staff plus module gate `rmm_integration`.

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/rmm/connections` | RequireRmm + RequireAdmin | Paginated list (secrets never returned) |
| POST | `/rmm/connections` | RequireRmm + RequireAdmin | Create; key and secret encrypted |
| GET | `/rmm/connections/{id}` | RequireRmm + RequireAdmin | Get |
| PUT | `/rmm/connections/{id}` | RequireRmm + RequireAdmin | Update; key/secret re-encrypted only when sent |
| DELETE | `/rmm/connections/{id}` | RequireRmm + RequireAdmin | Delete |
| POST | `/rmm/connections/{id}/test` | RequireRmm + RequireAdmin | Reachability probe |
| GET | `/rmm/device-mappings` | RequireRmm | Paginated list |
| POST | `/rmm/device-mappings` | RequireRmm + RequireAdmin | Create |
| PUT | `/rmm/device-mappings/{id}` | RequireRmm + RequireAdmin | Update |
| DELETE | `/rmm/device-mappings/{id}` | RequireRmm + RequireAdmin | Delete |
| GET | `/rmm/alert-rules` | RequireRmm | Paginated list |
| POST | `/rmm/alert-rules` | RequireRmm + RequireAdmin | Create |
| PUT | `/rmm/alert-rules/{id}` | RequireRmm + RequireAdmin | Update |
| DELETE | `/rmm/alert-rules/{id}` | RequireRmm + RequireAdmin | Delete |
| POST | `/rmm/alerts` | Signed webhook: no session; header `X-Tenant-Id` (UUID) and `X-Signature` = base64 HMAC-SHA256 of the raw body keyed with the connection's decrypted `api_secret` | Ingest one alert; answers `{"tickets_created": n}` |

**Behaviour.**
- Webhook auth (`routes.rs::ingest_alert`): body parsed first (failure is 401, not 400), connection secret looked up for `(X-Tenant-Id, rmm_connection_id)`, HMAC computed over the original bytes and compared in constant time; any missing header, unknown tenant, no secret, or mismatch is 401. The path is in the body sanitizer's raw-body list so bytes are not rewritten.
- Providers (`provider.rs`): the `RmmProvider` trait has `list_devices`, `list_alerts(since)`, `ping`. `build_provider` returns a real client only for `tactical_rmm` (`Authorization: Token <api_key>`; `GET agents/`, `GET alerts/`, `HEAD core/version/` under `api_url`). Every other accepted provider value gets `UnimplementedProvider`, whose calls fail with "RMM provider '<name>' is not implemented yet". Outbound URLs pass `guard_outbound_url` with the private-target allowlist and redirects are refused (a redirect is a `Configuration` error telling the operator to set the final URL).
- `test_connection`: `HEAD` on the guarded `api_url`, 10 s timeout, no redirects; any HTTP status counts as reachable; writes `sync_status` `success` or `failed` and `last_sync_at`; returns `{"reachable": bool, "status"|"error"}`. It decrypts the API key but does not send it.
- Alert ingest (`service.rs::ingest_alert`): loads active rules for the connection where `alert_type` equals the alert's or is NULL; company comes from the device mapping (`company_id`); for each rule with `auto_create_ticket`: skip when no mapped company, skip when `suppression_rules.min_severity` outranks the alert (ranks: `low|info`=1, `medium|warning`=2, `high`=3, `critical`=4; unknown severities rank by the function's fallback), skip when `suppression_rules.dedupe_window_minutes` is set and an open (non-closed status) ticket with `source = 'rmm'`, same company and same title exists within the window; title/description render from `ticket_template` with fallback to the raw alert; ticket created through `TicketService::create_ticket` with source `Rmm`, `is_billable = false`, rule's `queue_id` and `assign_to_id`, created-by the tenant's default creator, audit as system actor. Observation: the no-mapped-company skip and the no-default-creator skip do not log at an error or warn level in the code read (the suppression and dedupe skips log at debug only); the response still reports `tickets_created` as success.
- Sync worker (`worker.rs`): selects connections with `is_active = TRUE`, `sync_status <> 'in_progress'`, and `last_sync_at IS NULL` or older than `sync_interval_minutes`; marks `in_progress`; lists devices; upserts a mapping per device (`sync_status = 'synced'`); only when the mapping already has a `company_id` does it link or create an asset: existing `asset_id` is touched (audit `synced`), else match by `serial_number` then by `assets.name = hostname`, else create an `active` asset using the tenant's oldest asset type (name `hostname` or `rmm:<device id>`, `rmm_device_id`, `last_sync_at`) with audit `created`. Success sets `sync_status = 'success'`; failure sets `failed` plus `last_error` and logs a warning. The worker does not call `list_alerts`.

**Background jobs.** `RmmSyncWorker::run_tick`, every 60 s on the scheduler (`src/main.rs`).

**Config.** `ENCRYPTION_KEY`; module gate `rmm_integration`; per-connection `sync_interval_minutes` (default 60). Outbound private-target allowlist read through `private_target_allowlist` (exact key unverified here; see [configuration reference](configuration.md)).

### integrations

**Purpose.** A per-tenant registry and status page of external providers and the capabilities (payments, invoicing, bills and expenses, contacts) a tenant delegates to each. Files: `src/modules/integrations/{registry,routes,service,models,connection}.rs`, shared enums in `crates/mokosh-types/src/integrations.rs`.

**Data model** (`252_integrations.sql`, `277`, `280`, `282`, `283`, `288`, `290`):
- `integrations`: UNIQUE `(tenant_id, provider)`; `provider` CHECK in (`stripe`,`paypal`,`quickbooks`,`xero`,`google`,`microsoft`,`icloud`); `status` CHECK in (`not_connected`,`connected`,`error`,`disconnected`) default `not_connected`; `config` JSONB object; `enabled_capabilities` TEXT[]; `poll_interval_minutes` CHECK NULL or >= 5; `connected_by_user_id`, `connected_at`, `disconnected_at`, `last_error`; `external_organisation_id` (282: Xero tenant id or QuickBooks realm id); `external_payment_account_id` (288); partial unique index `(provider, external_organisation_id)` where not null (290). RLS enabled and forced. Credentials never live on the row (secrets provider).
- `invoice_issuer_company_mappings` and `invoice_issuer_product_mappings` (282): per tenant, provider in (`xero`,`quickbooks`), company or product to external customer/item id, UNIQUE per `(tenant, provider, company|product)`, RLS enabled and forced. Their routes live in billing, not here.
- Capabilities (`Capability::ALL`): `payments`, `invoicing`, `bills_and_expenses`, `contacts`. Migration 277 stripped a retired `point_of_sale` capability; 283 stripped `invoicing` from Stripe rows.

**Registry** (`registry.rs`, the single source for the list):

| Provider | Capabilities | Credential home | Connection home | Polled |
|---|---|---|---|---|
| stripe | payments | payment gateway page | integrations | no |
| paypal | payments | payment gateway page | integrations | no |
| quickbooks | invoicing, bills_and_expenses | invoice issuer | integrations | yes |
| xero | invoicing, bills_and_expenses | invoice issuer | integrations | yes |
| google | contacts | contact sync | contact_sync_connections | yes |
| microsoft | contacts | contact sync | contact_sync_connections | yes |
| icloud | contacts | contact sync | contact_sync_connections | yes |

Polled providers: default 15 minutes, floor 5.

**API.** Merged at the `/api/v1` root. Every handler is `RequireAuth` plus `RequireAdmin`; there is no module gate by design.

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/integrations` | RequireAdmin | List every registry provider with status, capabilities, setup surface, `configurable_here`, `available` |
| GET | `/integrations/{provider}` | RequireAdmin | One provider |
| PUT | `/integrations/{provider}` | RequireAdmin | Update capabilities, config, poll interval |
| POST | `/integrations/{provider}/connect` | RequireAdmin | Record connection |
| POST | `/integrations/{provider}/disconnect` | RequireAdmin | Record disconnection |

**Behaviour.**
- `parse_provider` 404s an unknown provider and any provider whose `credential_home` is not `Integration` ("is configured under <surface>"). In the registry read this session no provider has `CredentialHome::Integration`, so the four per-provider routes answer 404 for every provider today; only `GET /integrations` serves. The list deliberately includes all providers; changing one is confined to its own settings surface.
- `update`/`connect` reject providers whose connection lives elsewhere (409) and providers not built (409). `connect` additionally refuses a credential in the body for payment gateways (400: credentials are entered under the payment gateway settings), requires an existing `payment_gateway_configs` row holding a credential (ciphertext on the row or a value in the secret provider), and writes status through `connection::set_payment_connection`, the one writer of whether a payment provider is connected (it also mirrors `payment_gateway_configs.is_active` one way).
- Capability validation: unknown key 400, capability not supported by the provider 400, duplicates 400; omitted capabilities on connect means all supported; `config` must be a JSON object; poll interval below the provider floor 400, set on an unpolled provider 400; `poll_interval_minutes` is a double option (explicit null clears to default).

**Background jobs.** None in this module.

**Config.** None of its own; credentials go through the `SecretProvider` ([providers](providers.md), [config and providers invariants](invariants/config-providers.md)). Toggles `integrations_overview` (gates nothing), `delegated_invoice_issuer`, `delegated_bills` are registered in features. Unverified: the Xero and QuickBooks connect/OAuth and webhook routes (mounted from billing in `router.rs`) are outside this module.

### knowledge_base

**Purpose.** Staff knowledge base: categories, articles with monotonic versions, per-user drafts, one-level client-specific variants, template variables, votes, inline images, staff-only threaded comments with mentions and anchors, plus a published read slice for portal contacts. Files: `src/modules/knowledge_base/{routes,service,models,attachments,attachment_move,render,mentions,anchor}.rs`. Rules for versions and comments are in [KB invariants](invariants/kb.md).

**Data model** (`012`, `026`, `032`, `068`, `099`, `114`, `115`, `200`, `201`, `202`, `251`, `292`):
- `kb_categories`: `name` (1-100), `slug` (1-100), `parent_id`, `visibility` CHECK in (`public`,`internal`,`client_specific`) default `internal`, `sort_order`; UNIQUE `(tenant_id, slug)`.
- `kb_articles`: `title` (1-255), `slug` (1-255), `content`, `summary`, `category_id`, `visibility` (same enum, default `internal`), `company_ids` UUID[], `status` CHECK in (`draft`,`published`,`archived`) default `draft`, `author_id`, `updated_by_id` (200, SET NULL), `view_count`, `helpful_count`, `not_helpful_count`, `related_article_ids`, `related_ticket_ids`, `tags` TEXT[], `published_at`, `parent_article_id` (251, self FK, SET NULL), `template_variables` JSONB default `[]` (292); UNIQUE `(tenant_id, slug)`.
- `kb_article_versions`: `version_number`, `title`, `content`, `edited_by_id`, `change_note`, `change_kind` CHECK in (`create`,`edit`,`restore`), `restored_from_version`.
- `kb_article_votes`: one row per `(article_id, user_id)`, `vote` in (`helpful`,`not_helpful`).
- `kb_article_drafts`: UNIQUE `(tenant_id, article_id, user_id)`; RLS.
- `kb_article_attachments`: `file_name`, `mime_type`, `file_size`, `uploaded_by_id`; RLS. Bytes live in the storage seam at `{tenant_id}/kb-articles/{attachment_id}` (legacy flat `kb-articles/{id}` read as a fallback).
- `kb_article_comments`: `parent_id` (self, CASCADE, one level enforced in service), `author_id`, `body` (1-20000), `anchor` JSONB, `anchor_version`, `resolved_at`, `resolved_by_id`, `edited_at`, `deleted_at` (soft delete); RLS.
- `kb_comment_mentions`: PK `(comment_id, user_id)`, `notified_at`; RLS. Migration 202 seeds the `kb.comment.mention` in-app template and rule and copies them to all tenants.
- `tickets.source_kb_article_id` (068) and `tickets.procedure_kb_article_id` (099) reference articles with SET NULL.

**API.** Merged at the `/api/v1` root. `RequireKB` = staff plus module gate `knowledge_base`. Dual-plane = `RequireCallerContext`: staff must pass the module gate; a contact needs capability `kb:read` (loaded from the DB per request) and the module flag is not consulted for contacts.

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/kb/categories` | Dual-plane | List; contacts see non-internal categories |
| POST | `/kb/categories` | RequireKB + RequireManager | Create (unique slug) |
| PUT | `/kb/categories/{id}` | RequireKB + RequireManager | Update |
| DELETE | `/kb/categories/{id}` | RequireKB + RequireManager | Delete |
| GET | `/kb/articles` | Dual-plane | Filtered list; contacts get `ContactKbArticleResponse` |
| POST | `/kb/articles` | RequireKB + RequireManager | Create |
| GET | `/kb/articles/{id}` | Dual-plane | Get; staff read bumps `view_count`, contact read does not |
| PUT | `/kb/articles/{id}` | RequireKB + RequireManager | Update (optional `change_note` <= 500) |
| DELETE | `/kb/articles/{id}` | RequireKB + RequireManager | Delete (audited) |
| GET | `/kb/articles/{id}/draft` | RequireKB + RequireManager | Caller's draft |
| PUT | `/kb/articles/{id}/draft` | RequireKB + RequireManager | Save draft (title 1-255) |
| DELETE | `/kb/articles/{id}/draft` | RequireKB + RequireManager | Discard draft |
| GET | `/kb/articles/{id}/versions` | RequireKB | Paginated versions |
| POST | `/kb/articles/{id}/versions/{version_number}/restore` | RequireKB + RequireManager | Restore as a new version; returns the version |
| POST | `/kb/articles/{id}/render` | Dual-plane | Render Markdown with a `values` map |
| POST | `/kb/articles/{id}/helpful` | RequireKB | Toggle helpful vote |
| POST | `/kb/articles/{id}/not_helpful` | RequireKB | Toggle not-helpful vote |
| GET | `/kb/articles/{id}/vote` | RequireKB | Caller's vote and tallies |
| GET | `/kb/top-ticket-driving-articles` | RequireKB | Articles ranked by linked tickets; `days` default 90 clamped 1-365, `limit` default 20 clamped 1-100 |
| GET | `/kb/articles/{id}/measured-duration` | RequireKB | Measured time from request-form tickets documented by the article; default window trailing 90 days, optional dates |
| GET | `/kb/articles/{id}/tickets` | RequireKB | Tickets referencing the article |
| GET | `/kb/articles/{id}/comments` | RequireKB | Threaded comments |
| POST | `/kb/articles/{id}/comments` | RequireKB | Create (body 1-20000, optional anchor, optional parent) |
| PUT | `/kb/comments/{id}` | RequireKB | Edit own comment (author or admin; 409 if deleted) |
| DELETE | `/kb/comments/{id}` | RequireKB | Soft delete (author or admin) |
| POST | `/kb/comments/{id}/resolve` | RequireKB | Resolve root thread |
| POST | `/kb/comments/{id}/unresolve` | RequireKB | Reopen |
| GET | `/kb/articles/{id}/attachments` | RequireManager (inside module router) | List images |
| POST | `/kb/articles/{id}/attachments` | RequireManager | Upload multipart image |
| DELETE | `/kb/articles/{id}/attachments/{attachment_id}` | RequireManager | Delete (removes tenant path and legacy path) |
| GET | `/public/kb/attachments/{attachment_id}` | Public (no session, by design: `<img>` cannot send a bearer) | Serve image; `Cache-Control: public, max-age=31536000, immutable` |

**Behaviour.**
- Article create: `visibility = client_specific` requires non-empty `company_ids`, each owned by the tenant (400 otherwise); other visibilities ignore the scope. Slug unique per tenant (409 on duplicate). `status = published` at create stamps `published_at`; on update `published_at` is stamped on the first transition to `published` and never cleared. First version is seeded with `change_kind = create`; an update that changes title or content snapshots a new version (`edit`); a metadata-only edit creates none; a save deletes the caller's draft in the same transaction. Restore writes a new monotonic version with `change_kind = restore`.
- Hierarchy: `parent_article_id` must exist in the tenant, cannot be self, cannot itself have a parent, and an article with children cannot be given a parent (422 on `parent_article_id`); one level only.
- Template variables: names non-empty and unique, `default` must be in `allowed_values` when both are set (422 `template_variables.*`). Render uses minijinja (`{{ }}`/`{% %}`, lenient undefined; a bare missing variable renders as `[missing: NAME]`); a template error is a 400 with the engine message, never a 500.
- Contact slice (`list_articles_for_contact`, `get_portal_article`): `status = 'published'` AND (`visibility = 'public'` OR (`visibility = 'client_specific'` AND session company in `company_ids`)); `status`, `visibility`, `company_id` request params are ignored on the contact arm; an invisible article answers 404 like an unknown id.
- Votes: one vote per user, mutually exclusive, same vote again removes it; tallies recomputed in the transaction.
- Attachments: images only; SVG is refused (served unauthenticated from the API origin); cap `KB_ATTACHMENT_MAX_BYTES` default 5 MiB, applied as the route body limit and again in `create`; upload goes through `crate::storage` and the file ledger.
- Comments are staff only, one level deep, `@handle` mentions resolved server-side (`mentions.rs`), anchors shape-checked by `anchor::validate` (W3C TextQuoteSelector, unknown keys refused); detail in the KB invariants doc.
- Observation: `get_article` discards the result of the `view_count` UPDATE (`let _ = sqlx::query(...)`) with a "fire-and-forget" comment and no log line.

**Background jobs.** `KbAttachmentMover` (`attachment_move.rs`), one-shot per process start via `scheduler::one_shot::spawn_once` (`src/main.rs`): moves flat `kb-articles/{id}` files under `{tenant}/kb-articles/{id}` and updates the `files` ledger; reads fall back to the old path until it finishes.

**Config.** `KB_ATTACHMENT_MAX_BYTES` (optional, since v0.14.0, see [configuration](configuration.md)); module gate `knowledge_base`; storage settings per [config and providers invariants](invariants/config-providers.md#storage-seam-pms-910).

### documentation

**Purpose.** One read-only aggregate answering "what do we have for this client": assets, credential references and KB articles for a company, composed from existing services with no store of its own. Files: `src/modules/documentation/{routes,service}.rs`.

**Data model.** None (composition over `assets`, `credential_vault`, `kb_articles`).

**API.** Nested under `/companies` in `router.rs`.

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/companies/{company_id}/documentation` | RequireAssets | `{assets, credentials, articles}` for the company |

**Behaviour.** Three lists fetched concurrently (`tokio::try_join!`): assets and KB articles each capped at the first page of 100 (`PER_LIST_LIMIT`), credentials from `list_credentials_for_company` ordered by name with no limit seen in the query. Credentials are `CredentialSummary` (no secret fields); reveal stays on `GET /credentials/{id}`. The KB articles call is the staff `list_articles` with a `company_id` filter and is gated only by `RequireAssets`, not by the `knowledge_base` module gate (verified: `routes.rs` takes no KB extractor). A company in another tenant yields empty or 404 per the child queries (unverified which).

**Background jobs.** None. **Config.** None.

### status

**Purpose.** Ingests per-device check outcomes (backup, disk, patch, antivirus) from RMM agents into monitored systems and exposes current status plus backup-success and uptime rollups per company. Files: `src/modules/status/{routes,service,models,retention}.rs`.

**Data model** (`247_monitored_systems_and_status_observations.sql`, RLS on both):
- `monitored_systems`: `company_id` (CASCADE), `external_source` TEXT, `external_id` TEXT, `name`, `first_seen_at`, `last_seen_at`, `deleted_at`; UNIQUE `(tenant_id, external_source, external_id)`.
- `status_observations`: append-only; `monitored_system_id` (CASCADE), `check_kind` CHECK in (`backup`,`disk`,`patch`,`antivirus`), `outcome` CHECK in (`success`,`warning`,`failure`,`unknown`), `observed_at`, `payload` JSONB; UNIQUE `(monitored_system_id, check_kind, observed_at)`.

**API.** Merged at the `/api/v1` root. These routes carry `RequireAuth` only, with no module gate.

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| POST | `/rmm/status` | Signed webhook: `X-Tenant-Id` and `X-Signature` (base64 HMAC-SHA256 of raw body, same secret and scheme as `/rmm/alerts`) | Ingest one observation; 204 for both recorded and duplicate |
| GET | `/status/systems/{id}/current` | RequireAuth | Latest observation per check kind for one system (404 if missing or soft-deleted) |
| GET | `/status/companies/{company_id}/backup` | RequireAuth | Current backup outcome for every live system of the company |
| GET | `/reports/status/backup-success-rate` | RequireAuth | Query `company_id`, `from`, `to` (RFC 3339, half-open, `from < to` else 422): `success`, `total`, `rate` over `backup` observations |
| GET | `/reports/status/uptime` | RequireAuth | Same window: `up_observations` (outcome `success` or `warning`) over all observations, `rate` is 1.0 when there are none |

**Behaviour.** Ingest validates `check_kind` and `outcome` against the allowed sets (422 on the field) and `system_name` 1-255, resolves the company from `rmm_device_mappings` for `(rmm_connection_id, rmm_device_id)` (no mapping is a 422 naming the device), upserts the monitored system with `external_source = 'tactical_rmm'` (constant) and `external_id = rmm_device_id`, refreshes `last_seen_at`, clears `deleted_at`, keeps the stored name unless the row was soft-deleted, and inserts the observation `ON CONFLICT DO NOTHING`. Uptime is an observation ratio, not time-in-state. Per the module header, three of these routes have no SPA caller recorded as of that note.

**Background jobs.** `status_retention`, every 6 hours (`src/main.rs`): deletes `status_observations` older than `DEFAULT_RETENTION_DAYS = 395` (constant, not configurable); logs the purged count.

**Config.** None (retention is a code constant).

### features

**Purpose.** Deployment-wide feature switches: a code registry of features plus a table of operator changes; a missing row reads as off. Semantics are in [feature toggles](feature-toggles.md). Files: `src/modules/features/{registry,routes,service,job}.rs`.

**Data model** (`261_feature_toggles.sql`): `feature_toggles(key TEXT PK CHECK key ~ '^[a-z][a-z0-9_]*$', enabled BOOLEAN default FALSE, updated_at, updated_by FK users SET NULL)`. No `tenant_id` (deployment-wide).

**Registered features** (`registry.rs`, `Feature::ALL`): `integrations_overview` (gates nothing), `assets_search_v2`, `assets_catalog`, `delegated_invoice_issuer`, `delegated_bills`.

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/settings/feature-toggles` | DeploymentOperator | Every registered feature with label, help, issue, state, `updated_at`, `updated_by` |
| PUT | `/settings/feature-toggles/{key}` | DeploymentOperator | Body `{enabled}`; 404 naming registered keys if unknown; audited in the same transaction as the upsert; swaps this process's snapshot immediately |
| GET | `/public/config` | Public (no session) | `{"features": {key: bool}}`, keys and booleans only |

`DeploymentOperator` (`src/modules/tenants/routes.rs`) = platform-admin bearer, or an admin of the system tenant (`SYSTEM_TENANT_ID` = UUID 1).

**Behaviour.** Unknown stored keys are ignored with one warning per process and kept. Consumers call `FeatureSnapshot::is_enabled` (assets routes read `assets_search_v2` and `assets_catalog`).

**Background jobs.** `feature_toggle_refresh`, every 60 s (`REFRESH_INTERVAL_SECS`): reloads the table into the snapshot, logs at info when the map changed, and on a failed load the scheduler logs and keeps the previous snapshot.

**Config.** None.

### settings

**Purpose.** Tenant settings (category/key JSON), per-module enable flags, and the deployment-wide operator settings: SMTP relay, product name, Google OAuth client. Files: `src/modules/settings/{routes,service,models,email,app_name,google_client}.rs`.

**Data model.**
- `tenant_settings` (`017_settings.sql`): `category` VARCHAR(50), `key` VARCHAR(100), `value` JSONB, UNIQUE `(tenant_id, category, key)`; fail-closed RLS per `038_rls_fail_closed.sql` (cited by the code comments, not re-read here).
- `module_config` (`017_settings.sql`): `module_name` VARCHAR(50), `is_enabled` default FALSE, `config` JSONB, UNIQUE `(tenant_id, module_name)`. Migration 120 inserts `timesheets` for every tenant, enabled when `tenants.kind = 'org'`.
- System rows on the system tenant (UUID 1): `email/smtp` (password stored AES-256-GCM), `system/app_name`. The Google client pair is not stored in `tenant_settings`; it is two governed application secrets (migration 258 deleted the older per-tenant rows).

**API.** Merged at the `/api/v1` root. Literal routes are registered before `/settings/{category}`.

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/settings` | RequireAuth | Paginated list of the tenant's settings |
| PUT | `/settings` | RequireAuth + RequireAdmin | Upsert by body `{category, key, value}` |
| GET | `/settings/modules` | RequireAuth | Paginated module configs |
| GET | `/settings/modules/{module}` | RequireAuth | One module config |
| PUT | `/settings/modules/{module}` | RequireAuth + RequireAdmin | Body `{is_enabled, config}` |
| GET | `/settings/email` | DeploymentOperator | SMTP settings view (`password_set` boolean, never the password) |
| PUT | `/settings/email` | DeploymentOperator | Update host, port, username, from, tls, password; hot-swaps the live mailer |
| POST | `/settings/email/test-send` | DeploymentOperator | Send a test message `{to}` through the live mailer |
| POST | `/settings/email/verify` | DeploymentOperator | Check the transport without sending (SMTP NOOP, `LogMailer` trivially ok) |
| GET | `/settings/google-contacts-client` | DeploymentOperator | Boolean-style configured status only |
| PUT | `/settings/google-contacts-client` | DeploymentOperator | Write `client_id` and `client_secret` together to the declared app-secret provider |
| GET | `/settings/app-name` | DeploymentOperator | Product name |
| PUT | `/settings/app-name` | DeploymentOperator | Set product name (sanitised, 422 on `app_name`) |
| GET | `/settings/{category}` | RequireAuth | Settings of one category |
| GET | `/settings/{category}/{key}` | RequireAuth | One setting |
| PUT | `/settings/{category}/{key}` | RequireAuth + RequireAdmin | Set value (body `{value}`) |
| DELETE | `/settings/{category}/{key}` | RequireAuth + RequireAdmin | Delete |

(Feature-toggle routes under `/settings/feature-toggles` are listed under features.)

**Behaviour.**
- `validate_setting_value` runs on both write shapes. Validated keys (value rule; default when unset as read by the `read_*` helpers):
  - booleans: `timesheets/track_breaks` (false), `integrations/google_contacts_enabled`, `integrations/icloud_contacts_enabled`, `integrations/microsoft_contacts_enabled` (all default true), `notifications/channel_email_enabled`, `notifications/channel_in_app_enabled`, `billing_reminders/enabled`.
  - enums: `tickets/note_editing` via `NoteEditPolicy::parse` (unset = `author_or_admin` behaviour), `timesheets/segment_editing` via `SegmentEditPolicy::parse`, `billing_prefs/invoice_numbering` in (`tenant_sequence`,`company_prefix`).
  - ranges: `ticketing/auto_close_resolved_after_days` 1-90, `scheduling/default_due_business_days` 0-365 (read default 0), `time_tracking/max_hours_per_day` 1-24 (read default 24, i.e. 1440 minutes), `ci/impact_max_depth` 1-10 (read default 5), `workflows/rule_max_depth` 1-10 (read default 3), `billing_reminders/send_hour` 0-23, `billing_reminders/schedule` array.
  - strings: `notifications/default_locale` non-empty max 10, `billing_prefs/currency` three uppercase letters (read default `USD`), `email_intake/default_company_id` UUID string, `branding/*` via `validate_branding_value`, which also asserts any referenced public tenant or company URL belongs to the caller's tenant (PMS-1371).
  - Any other `(category, key)` is accepted verbatim with a `warn` log naming category, key, type and length; this is a catch-all for unknown keys (logged, not rejected).
- Module config upsert has no module-name validation in the handler (unverified whether the service restricts names); gating extractors look up the literal module names `billing`, `projects`, `calendar`, `contracts`, `assets`, `knowledge_base`, `rmm_integration`, `reports`, `time_tracking`, `timesheets`.
- Email: DB row overrides env per field; env (`SMTP_*`) is the fallback; no row equals env-only behaviour; `From` must parse as an address (400). Google client: both halves required, non-empty, and swap-detected (`client_id` must not start with `GOCSPX-`, `client_secret` must not end with `.apps.googleusercontent.com`); refuses (422) when the declared app-secret provider cannot be written, naming the `*_FILE` variables; never returns either value.
- `read_tenant_zone` returns the default business-hours row's timezone else `UTC`.

**Background jobs.** None.

**Config.** `ENCRYPTION_KEY`; `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`, `SMTP_TLS`, `MAIL_PROVIDER`; `GOOGLE_CONTACTS_CLIENT_ID`, `GOOGLE_CONTACTS_CLIENT_SECRET` (and `_FILE` forms), `APP_SECRET_BACKEND`. See [configuration](configuration.md) and [config and providers invariants](invariants/config-providers.md#email-backend).

### ip_enrich

**Purpose.** Admin-only advisory lookup of ASN, organisation and VPN/proxy likelihood for an IP, using the shared `dunite-ipenrich` crate over an IP2Proxy PX database file. Files: `src/modules/ip_enrich/routes.rs`.

**Data model.** None.

**API.**

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/ip-enrichment?ip=<addr>` | RequireAuth + RequireAdmin | Enrichment for one address |

**Behaviour.** Malformed `ip` is a 422-style query error (`query_error("ip", ...)`). Returns JSON `null` when the service is not configured, the address is private or reserved, or the dataset has no entry. Response fields: `ip`, `asn`, `organization`, `isp`, `category`, `vpn`, `is_anonymizing`, `proxy_type`, `provider`, `threat`, `advisory` (always true). Never a verdict. `main.rs` logs `IP2PROXY_DB_PATH unset; IP enrichment disabled` at info when unset; unverified: handling and log level when the file is set but fails to load. The module header records that no SPA caller exists.

**Background jobs.** None. **Config.** `IP2PROXY_DB_PATH` (optional, since v0.11.0).

### data_transfer

**Purpose.** Admin-only tenant export, wipe-and-replace import, and an explicit demo-data load. File: `src/modules/data_transfer/mod.rs`.

**Data model.** None of its own; reads every `public` table with a `tenant_id` column from `information_schema`.

**API.** Merged at the `/api/v1` root; all handlers are `RequireAuth` plus `RequireAdmin`.

| Method | Path | Auth gate | Purpose |
|---|---|---|---|
| GET | `/data/export` | RequireAdmin | Download one JSON envelope: `schema_version` (1), `tenant_id`, `tenant_name`, `included_tables`, `excluded_tables`, `entities` |
| POST | `/data/import` | RequireAdmin, body limit 25 MiB | Wipe the tenant and load the envelope |
| POST | `/data/seed-demo` | RequireAdmin | Load the built-in demo set into an empty tenant |

**Behaviour.**
- Export: tables excluded outright: `payment_gateway_configs`, `credential_vault`, `api_keys`, `rmm_connections`, `users`, `user_sessions`, `password_reset_tokens`, `portal_setup_tokens`, `tenant_intake_tokens`, `tenant_invitations`, `audit_log`, `asset_audit_log`, `email_intake_log`. Any column whose name contains `encrypted`, `password_hash`, `_secret`, `mfa_secret`, `api_key`, `api_secret` or `private_key` is dropped from every row. Writes an `Export` audit row.
- Import: `schema_version` must equal 1 (400); table names must be safe identifiers and not excluded (400); `confirm` must equal the tenant name after trim (400); one transaction with `SET CONSTRAINTS ALL DEFERRED` (FKs are deferrable per migration 088), deletes the tenant's rows per table, assigns fresh UUIDs for every row `id` and remaps matching UUID fields, forces `tenant_id`; any failure rolls everything back; writes an `import` audit row. A file table not carrying `tenant_id` in the live schema is treated as schema drift (error). Unverified: how `configuration_items` rows (whose `value_encrypted` column is dropped on export) behave on import, since the column is NOT NULL.
- Seed-demo: always 200; `{"seeded": true|false, "message"}`; `false` when the tenant already has companies. Observation: the `seeded: true` message text says "a sample company, two contacts, and three tickets" while the bundle holds two companies, four contacts, two projects, five tickets, one SLA (`src/modules/seed/data.rs` tests).

**Background jobs.** None. **Config.** None.

### seed

**Purpose.** Demo and test dataset seeders: the first-visit demo seed, an admin-triggered load, and operator-only QA, showcase and portal-development seeders. Files: `src/modules/seed/{service,middleware,data,qa,showcase,portal_dev}.rs`, bundle `src/modules/seed/demo_seed.json`.

**Data model.** No tables. Marker state: `tenants.settings->>'demo_seeded'` (claimed with an atomic compare-and-set), `settings->>'is_qa'`, `settings->>'is_showcase'`, `settings->>'environment'`.

**API.** None of its own. `seed_middleware` runs inside the auth middleware; the explicit load is `POST /data/seed-demo` (see data_transfer).

**Behaviour.**
- First-visit auto seed (`seed_middleware` -> `SeedService::ensure_demo_seeded`): for an authenticated request from a tenant not yet in the process-local `seen` set, spawns a detached task so the request is not delayed. Enabled only when `ENVIRONMENT` is `production`, or `MOKOSH_DEMO_SEED` is one of `1`, `true`, `yes`, `on`; the shared landing tenant (`OIDC_DEFAULT_TENANT_ID`) is never auto-seeded; tenants that already have companies are skipped (flag still set). Loads through the real service methods: 2 companies, 4 contacts, 1 SLA attached to a company, 2 projects (one with a phase and a task), 5 tickets. On a transient failure it logs a warning and does not mark the tenant seen, so it retries on the next request.
- `load_demo_data` (explicit): not gated by environment; additive; only into a tenant with no companies; marks seen.
- QA seed (`qa_seed`, `qa_teardown`): run via `mokosh-bootstrap qa-seed|qa-teardown` and `mokosh-server qa-seed|qa-teardown --tenant <id>` (`src/cli/mod.rs`, `src/bin/mokosh-bootstrap.rs`); `confirm_qa_tenant` fails closed unless `settings->>'is_qa'` is true and `environment` is not `production`; data is `QA-` prefixed (8 companies, about 16 contacts, 35 tickets, 2 projects, 8 time entries, contracts, 2 invoices, 1 asset type with 6 assets, 1 KB category with 3 articles).
- Showcase seed (`showcase_seed`, `showcase_refresh`, `showcase_teardown`): `mokosh-server showcase-seed|showcase-refresh|showcase-teardown --tenant <id>`; same fail-closed guard on `settings->>'is_showcase'`; `SHOWCASE-` prefixed data.
- Portal-dev seed (`portal_dev_seed`): refuses unless `ENVIRONMENT` is `development`, `dev` or `test`; creates `acme` (active, branded), `beta` (active), `inact` (inactive) tenants with one portal-enabled contact each sharing `PORTAL_DEV_PASSWORD`; idempotent (`ON CONFLICT (slug) DO NOTHING`).

**Background jobs.** None (the auto seed is request-triggered and detached).

**Config.** `ENVIRONMENT`, `MOKOSH_DEMO_SEED`, `OIDC_DEFAULT_TENANT_ID` (registry keys in `src/config/registry.rs`).

### credential_move.rs (top-level helper, not a feature module)

`src/modules/credential_move.rs` is a small library, not an HTTP module: `verify_readback(readback, expected)` and `move_value_with_readback(value, write, read_back)` implement the write, read-back from the target live, compare invariant used when a secret moves between stores. A missing or different read-back is `AppError::Configuration` with a redacted message (the value is never included). Its doc comment says `billing::credential_move` implements the same shape for payment-gateway credentials; it is consumed by `src/cli/providers.rs` (provider-migrate subcommands) and `src/modules/settings/google_client.rs`. No routes, tables, jobs or config.
