# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Mokosh Server: PSA (Professional Services Automation) REST API for MSPs. Rust + Axum + SQLx + PostgreSQL. Two binaries:

- `mokosh-server`: long-running HTTP API (`src/main.rs`).
- `mokosh-bootstrap`: one-shot CLI for first-run Infisical setup and OIDC client registration (`src/bin/mokosh-bootstrap.rs`).

## Common commands

All driven through `just` (see `justfile`). Required tooling: `just`, Nushell `0.112.2`, Docker + Compose v2, Rust stable, `sqlx-cli` for migrations, `cargo-machete` for the unused-dependency gate (`cargo install --locked cargo-machete`).

```
just                       # list recipes
just check                 # every check.yml step except its cargo test steps (run before pushing)
just check-compile         # cargo check --all-targets
just check-clippy          # cargo clippy --all-targets -- -D warnings (same as check.yml)
just check-fmt             # cargo fmt --all --check
just check-migration-immutability # fail if a migration already on main is modified or deleted
just check-pool-safety     # fail if a serving `.pool()` call lacks its `// SAFETY (PMS-285` note
just check-workspace-deps  # [workspace.dependencies] matches what members inherit
just check-unused-deps     # cargo-machete: fail on a dependency with no call site
just check-env-example     # every var the code reads has a .env.example key and a compose.dev.yml line
just check-doc-recipes     # every `just <recipe>` in README.md / docs/quickstart.md exists in the justfile
just check-doc-links       # every relative Markdown link resolves to a path that exists
just fmt                   # cargo fmt --all
just test                  # cargo test (workspace-wide)
just test-integration      # Postgres-backed tests/*.rs suite (mirrors CI integration.yml)
just install-hooks         # install the git pre-commit hook -> runs `just pre-commit`
just pre-commit            # check.yml's cargo steps only: fmt/clippy/compile/unit/doc, in the dev container
just build                 # cargo build --release --bins
just migrate-run           # sqlx migrate run against $DATABASE_URL
just migrate-create <name> # new migration in migrations/
just check-docker          # validate OCI image builder stage (NOT part of `just check`)
just build-docker          # build production OCI image (oci-build/Dockerfile)
```

`just check` and `just pre-commit` are complements: together they cover every step of `.forgejo/workflows/check.yml`, and neither covers it alone. `docs/dev-docs/local-vs-ci-checks.md` maps the workflow onto the recipes step by step and states why `check-docker`, `test-integration`, `verify-demo` and `test-e2e` stay outside the umbrella recipe (PMS-851). Adding a step to `check.yml` means adding the matching recipe to `just check` (or `just pre-commit`) and the row in that file.

Single test: `cargo test -p <crate> <test_name>` (workspace), e.g. `cargo test -p mokosh-server utils::totp::tests::rfc6238_vector`.

### Dev stack

A single Traefik-routed dev stack (PMS-511 folded the former SSO overlay into `compose.dev.yml`):

```
just dev                   # Traefik-routed stack at https://${USER}-mokosh-api.a8n.run (mokosh-server + Postgres + mailpit)
just dev-infisical         # opt-in: Infisical + its Postgres (compose profile: infisical)
just down                  # stop the dev stack, remove orphans (volumes preserved)
just dev-clean             # stop + wipe volumes + remove .env (keeps .env.infisical)
just infisical-bootstrap   # one-time after `just dev-infisical`, fills INFISICAL_* in .env
```

OIDC client registration recipes (`register-client`, etc.) were removed with mokosh-auth in PMS-295: bunyip is the sole OP and owns its own client registry, so RPs register with bunyip, not mokosh.

`just dev` rewrites `MOKOSH_HOST_BIND_IP` and `USER` in `.env` each run (`USER` names the per-developer containers, volumes, networks and the `${USER}-mokosh-api.a8n.run` route; the LAN IP, discovered from `sys net | where name =~ 'eth0|br0'`, is recorded but no longer consumed by `compose.dev.yml`, since PMS-496 moved the `postgres`/`mailpit` host publishes to loopback and the `server` is ingress-only via Traefik). First run generates `.env` from the committed `.env.example` (via the `ensure-env` recipe, a dependency of `just dev`), minting fresh random values for every self-owned secret (PMS-490: DB passwords, `JWT_SECRET`, `ENCRYPTION_KEY`, the Infisical secrets) and leaving third-party credentials as empty placeholders. It does not copy a file; an existing `.env` is left untouched, so the generation runs once per clone.

`just dev-infisical` rewrites `MOKOSH_SERVER_INFISICAL_ADDRESS` in `.env` to `http://infisical:8080`, which compose passes to the `server` container as `INFISICAL_ADDRESS` (restart `server` to pick it up). It stays empty on a plain `just dev` so the readiness probe reports `checks.infisical == "skipped"` rather than 503ing against the profile-gated service (PMS-707). The separate plain `INFISICAL_BASE_URL` in `.env` is a different key: the host-side `http://localhost:28002` that `just infisical-bootstrap` uses.

`just dev` requires the shared external `network-traefik-public` to already exist. (Before PMS-295 it also needed a local Ed25519 keypair for mokosh-auth's OP signing; that subsystem is gone, so no key material is provisioned now. The bunyip-as-OP Resource-Server path verifies tokens against bunyip's JWKS over the network.)

## Architecture

### Top-level layout

```
src/
  main.rs               mokosh-server entrypoint: AppConfig::from_env, build router
  lib.rs                library crate root
  api/router.rs         create_api_router: builds every /api/v1 nest (see "Routing model"), wires middleware + CORS
  bin/mokosh-bootstrap.rs CLI: bootstrap-infisical, qa-seed/qa-teardown
  db/                   Database wrapper around sqlx::PgPool
  infisical/            Infisical HTTP client + first-run bootstrap
  modules/<name>/       Feature modules (see "Modules" below)
  utils/                error, email (Mailer trait + SmtpMailer/LogMailer), crypto, validation, pagination
  version.rs            VersionInfo (build-time git hash/describe via build.rs)

crates/                 Workspace members: mokosh-types, build-metadata
migrations/             SQLx migrations, embedded at compile time via sqlx::migrate!
oci-build/Dockerfile    Production multi-stage Alpine + musl
Dockerfile              Dev image (debug build, source-mounted)
compose.dev.yml         Traefik-routed dev stack (per-developer *.a8n.run)
.forgejo/workflows/     CI (Forgejo)
docs/                   Contributor/user docs; docs/dev-docs/ = internal notes (codebase-state.md = module/route catalog)
```

### Auth: two independent mechanisms (PMS-295)

bunyip-as-OP is the only OP. PMS-295 removed mokosh-auth (mechanism 2, mokosh's own OIDC OP) entirely; the server now accepts two independent auth paths in parallel, and failing to mount one does NOT disable the other:

1. **Bunyip-as-OP Resource-Server** (`src/modules/auth/oidc_rs.rs`): mokosh verifies bunyip-issued `at+jwt` Bearer tokens against bunyip's JWKS. Configured by `OIDC_ISSUER` + `OIDC_AUDIENCE`. This is the path the mokosh-apps SPA and the E2E suite actually use; tokens come from `api.<tld>` = bunyip. Mokosh holds no signing key and exposes no `/oauth2/*` endpoints.
2. **Legacy HS256 cookie auth** (`src/modules/auth/`): JWT in cookie, Argon2 password hashing, session rows in `user_sessions`. Used by the original PSA endpoints. `AuthMiddleware` decodes the cookie into an `AuthState`. Routes opt in via `RequireAuth` / `RequireRole` / `RequireAdmin` / `RequireManager` / `RequireFinance` extractors. TOTP (RFC 6238) + MFA recovery codes for this path live in `src/utils/totp.rs` + `src/utils/recovery.rs` (relocated from the removed `mokosh-auth-crypto` crate in PMS-295).

Both paths run the same principal gate (PMS-698): `AuthService::ensure_principal_usable` rejects a `users.status != 'active'` row and a tenant whose `status != 'active'`, so deactivating a user or suspending a tenant takes effect on the very next request regardless of which mechanism minted the token. The PMS-681 `iat`-vs-`password_changed_at` cutoff stays legacy-only on purpose: bunyip owns the credential on path 1, so a mokosh-side password change is not a revocation signal there.

**History (PMS-291 / PMS-292 / PMS-289)**: mokosh-auth was a configured-but-unused second IdP (`crates/mokosh-auth*`). PMS-289 made a misconfigured mokosh-auth a fatal boot error, which took staging+prod down (PMS-292 restored service by provisioning keys - interim path B). PMS-295 is the path-A follow-up: tear mokosh-auth out so `MOKOSH_AUTH_*` env, the `crates/mokosh-auth*` workspace members, and the `mokosh-server-secrets` volume all go away. The server boots fine with no `MOKOSH_AUTH_*` env present.

PMS-837 removed the last auth-adjacent workspace crate: `google-oauth-flow` and the `/api/v1/auth/google` + `/api/v1/auth/google/callback` popup routes it served went away with the `GOOGLE_OAUTH_*` and `OAUTH_SUPER_ADMIN_EMAILS` env vars. No client ever called them (three parity audits between 2026-07-30 and 2026-08-14 found the routes unconsumed, and mokosh-apps still has no reference). `google_oauth_routes_stay_unmounted` in `src/modules/auth/routes.rs` is the guard that fails if either mount returns; the `user_oauth_identities` table stays, because migrations are immutable.

### Portal credentials are a third, fully separate plane (PMS-820)

A portal identity is a `contacts` row (`portal_password_hash`, `is_portal_user`); a platform identity is a `users` row. One email address can legitimately hold one platform account and a portal identity in several tenants at once, so the portal owns its whole credential lifecycle: `POST /api/v1/portal/auth/{login,setup-password,forgot-password,reset-password}` resolve the identity from `contacts` inside the tenant named by `tenant_slug` and never read or write `users`. `/api/v1/auth/forgot-password` is the platform path and resolves against `users` only; an address that is portal-only finds no user there and gets the same silent 200 as any unknown address. Do NOT point the portal at the platform reset endpoints: one credential path serving two identity kinds is the PMS-820 defect, where a customer resetting their portal password reset a staff login instead.

Portal reset tokens reuse the PMS-136 `portal_setup_tokens` row and its `{contact_id}.{secret}` shape (Argon2-hashed, single use, 24h), so redeeming a self-service reset link and redeeming an agent-minted setup link share one replay contract: 204, then 410 on replay, 400 on expired/unknown. Both new endpoints are rate limited by `AuthRateLimiter` (10/min per IP, 3/min per account) exactly as PMS-680 did for the platform path; forgot-password keys the account bucket on `(tenant_slug, email)` because `contacts.email` is only unique within a tenant, and reset-password keys it on the contact id in the token. The mail is queued through the existing `auth.password_reset` template (already copied to every new tenant by `TenantService::create`), so no new template is seeded.

Portal sessions are stateless, so revocation is a cutoff, not a delete (MAPPS-532). `PortalAuthService::login` mints an 8-hour HS256 JWT and writes no session row; `PortalJwtClaims` carries no session id, so there is no portal analogue of `user_sessions` for `POST /portal/auth/logout` to delete. It stamps `contacts.portal_tokens_valid_from` instead, and `portal_auth_middleware` rejects any token whose `iat` predates that stamp - the `users.password_changed_at` shape from PMS-681. Two consequences to keep in mind: a portal sign-out ends that contact's sessions on EVERY device, and the check is strictly `<` so a contact who signs straight back in inside the same second keeps the token they just received. The middleware pays nothing extra for it (the contacts row was already being read for the names PII minimisation keeps out of the JWT), but that read is now the revocation check, so a failure to read it is a 401 rather than the empty-names degrade it used to be.

### Routing model

`create_api_router` (`src/api/router.rs`) builds these top-level nests, plus a fallback. Each one states what authenticates a request to it; keep this list in step with the `.nest(...)` calls at the end of `create_api_router`.

- `/api/v1/*` PSA router. Every module exposes either `<name>_routes(service)` (nested under a prefix) or merges directly when it owns multiple top-level prefixes (e.g. `time_tracking_routes`, `projects_routes`, `calendar_routes`, `contracts_routes`, `billing_routes`, etc. all use `.merge`). Authenticated by the session: `auth_middleware` runs globally and populates `AuthState`; route handlers opt in via `RequireAuth` / `RequireRole` / `RequireAdmin` / `RequireManager` / `RequireFinance`.
- `/api/v1/public/*` UNAUTHENTICATED, by design. Nothing authenticates a request to this subtree: no session, no cookie, no bearer, no signature. Everything it serves is listed here. `GET` and `POST /api/v1/public/request-forms/{token}` (`src/modules/forms/public_routes.rs`), where the single-use magic-link token in the URL is the only identity and resolves its own tenant, throttled per client IP by `RequestFormLimiter`. `GET /api/v1/public/tenants/{tenant_id}/logo` (`src/modules/tenants/routes.rs`), which a recipient's mail client fetches straight out of a request-form email and can never authenticate; a tenant with no logo 404s identically to a tenant id that does not exist, and SVG is excluded from the allowed upload types (`src/modules/tenants/logo.rs`). A handler added here answers anyone on the internet: it needs its own throttle and must expose nothing that a tenant id or a leaked token alone should not unlock.
- `/api/v1/portal/*` portal router with its OWN auth middleware (identity = `contacts` row, not `users`). Authenticated by a portal-tagged Bearer JWT that `portal_auth_middleware` decodes; handlers opt in via `RequirePortalAuth`, and the `/portal/auth/{login,setup-password,forgot-password,reset-password}` credential endpoints are reachable without one (they are rate limited by `AuthRateLimiter` instead). `POST /portal/auth/logout` is the exception among the `/auth/*` siblings: it needs the bearer it revokes, so it sits behind `RequirePortalAuth`. Never sees `AuthState`.
- `/api/v1/bunyip/*` bunyip webhook receiver (`POST /webhooks/account-deleted`). Authenticated by the `X-Webhook-Signature` HMAC-SHA256 over the body, keyed by `BUNYIP_WEBHOOK_SECRET` (PMS-591), not by a session.
- `/api/v1/stripe/*` Stripe webhook receiver (`POST /webhooks/{tenant_id}`). Authenticated by the `Stripe-Signature` HMAC over the raw body, keyed by that tenant's stored webhook signing secret (PMS-711), not by a session. The tenant id in the path selects which secret to verify against; it is not itself a credential.
- Fallback for non-API paths: small HTML "not a frontend" page linking back to the SaaS shell. No authentication; it renders the same page for anyone.

`#[cfg(feature = "multi-tenant")]` gates the `/tenants` CRUD routes; default features are `["multi-tenant", "server"]`. The `server` feature gates HTTP-only code so the library crate can be reused without Axum.

### Multi-tenancy

No middleware-level tenant scoping. Every service method takes `tenant_id: Uuid` explicitly. Forgetting to thread `user.tenant_id` becomes a cross-tenant data leak. See `docs/dev-docs/codebase-state.md` cross-cutting issue #8.

### Migrations

Per-feature files under `migrations/` (split from the original `001_initial_schema.sql` monolith in PMS-128). Embedded at compile time via `sqlx::migrate!`; `migrations/` must exist in the build context (both Dockerfiles copy it). On server start with `RUN_MIGRATIONS=true` (default) migrations run automatically.

**Migrations are immutable once committed.** sqlx stores a SHA-384 checksum of each migration in `_sqlx_migrations` when it applies it, and re-verifies on every startup. Editing (or renaming/deleting) a migration that has already been applied to any database makes that database refuse to boot with `migration N was previously applied but has been modified` (this is exactly how v0.4.0 broke nc-01: `023_seed_data.sql` was edited after a build had applied it). To change schema or seed data, add a NEW migration with `just migrate-create <name>` - never edit an existing one. CI enforces this: `scripts/check-migration-immutability.nu` (wired into `.forgejo/workflows/check.yml`, DEV-395) fails any PR that modifies/renames/deletes a migration already on `main`, alongside `check-migration-prefixes.nu` (prefix uniqueness, PMS-198).

### Module status

Most route groups have real handlers. `src/api/router.rs` nests/merges ~30 implemented modules (`auth`, `contacts`, `tenants`, `tickets`, `billing`, `projects`, `calendar`, `contracts`, `quotes`, `assets`, `rmm`, `sla`, `saved_reports`, `workflows`, `time_tracking`, and more); the old `stub_routes()` 501 placeholder mechanism is gone. The report-export route (`src/modules/reports/routes.rs`) implements CSV only and rejects every other `format`, `pdf` included, with 400 and not 501: `format` is an enumerated query parameter, so a value outside the implemented set is an out-of-range request rather than a server-side gap (PMS-854; adding PDF is tracked in PMS-876). The schema is still ahead of the handler layer in places. Before adding a new module, read `docs/dev-docs/codebase-state.md` for the per-module status, open TODOs (`F1..F14`), and known shallow-DTO traps in tickets.

## Conventions specific to this repo

- Branches: `fix/...`, `feat/...`, `chore/...`. Forgejo PRs via `fj pr create` (host `dev.a8n.run`). `gh` is not installed.
- CI runner labels (PMS-719, GOV-43): a job that compiles on the runner requests `RUNS_ON_OPENSUSE_DEV_LATEST` (only that image ships `cc` / `gcc` / `ld` plus glibc and OpenSSL headers); everything else stays on `RUNS_ON_OPENSUSE_BASE_LATEST`. Base plus a compile fails at `linker cc not found` on a cold cache (PMS-705, PMS-706); the fix is the label, never a run-time `zypper install gcc`. `scripts/check-runner-labels.nu` (in `just check` and `check.yml`) enforces this and requires every `runs-on:` to carry a comment justifying its label.
- OCI build cache (PMS-720, GOV-20): `build-oci-image.yml` builds on a `docker-container` buildx driver and caches to the runner's built-in Actions cache server (`cache_from type=gha`, `cache_to type=gha,mode=max,ignore-error=true`), with `crazy-max/ghaction-github-runtime@v3` re-exporting `ACTIONS_CACHE_URL` / `ACTIONS_RUNTIME_TOKEN` so a raw `docker buildx build` can reach it. The retired `type=inline` and `type=registry` `:buildcache` backends are banned. `scripts/check-oci-build-cache.nu` (in `just check` and `check.yml`) enforces this; because `ignore-error=true` makes a dead cache go green silently, read freshness from the build log's `importing cache manifest from gha` line, not the exit code.
- Image publish tags (PMS-733): the publish train comes from the trigger, not `git describe`. A `v*` tag push publishes `:vX.Y.Z` only, a `main` push publishes `:latest` only, and a push to a branch on `BRANCH_ALLOW_LIST` in `oci-build/get-tags.nu` publishes that branch's own tag only (the branch name with `/` replaced by `-`), so staging can run a feature branch without `:latest` moving. A branch off that list publishes nothing: it is filtered out by `on.push.branches`, rejected by the job's ref guard, and would fail loud in `get-tags.nu` rather than fall back to `:latest`. To publish from a new branch, add it to the const AND to both places in `build-oci-image.yml`; `scripts/check-oci-publish-tags.nu` (in `just check` and `check.yml`) fails the build if the three disagree.
- Workspace dependency table (PMS-785): `[workspace.dependencies]` in the root `Cargo.toml` lists only crates a member actually inherits with `<crate> = { workspace = true }`, because that is the only way an entry reaches the build graph. An entry nobody inherits pins a version and a feature set the build never uses (`tower-http` pinned `["cors", "trace"]` there while the root package independently pinned a six-feature superset), and a member that re-pins a crate the table already covers reopens the same ambiguity. `scripts/check-workspace-deps.nu` (in `just check` and `check.yml`) fails on either shape; `cargo machete` cannot, because it only reads each package's own `[dependencies]` / `[dev-dependencies]` / `[build-dependencies]`. To share a new crate, add the workspace entry and the member's `{ workspace = true }` line in the same change.
- Unused dependencies (PMS-780): `cargo machete` runs in `just check` and `check.yml` as a blocking gate, so a crate declared in `Cargo.toml` with no call site fails the PR. `pulldown-cmark` and `minijinja` had been compiled on every cold build for nothing. Response compression is brotli-then-gzip: `CompressionLayer::new()` offers only the algorithms whose `tower-http` cargo features are compiled in, so `compression-br` must stay in the feature list (guarded by the negotiation tests in `src/api/router.rs`).
- Release image layers (PMS-781): `oci-build/Dockerfile` compiles third-party dependencies against stub sources in their own layer, then copies the real `migrations/`, `build.rs`, `crates/` and `src/` and compiles the workspace crates in a second layer, so a source-only change reuses the dependency layer instead of recompiling ~330 crates. A layer is the shape the CI `type=gha,mode=max` cache exports; a `--mount=type=cache,target=/build/target` is not, which is why the registry cache mount stays but no `target/` mount was added. The `MOKOSH_GIT_HASH` / `MOKOSH_BUILD_DATE` `ARG`+`ENV` block sits BELOW the dependency layer on purpose: those values change on every build and an `ENV` above the layer would invalidate it every time. Adding a workspace member means adding its `COPY <member>/Cargo.toml`, its stub `src/lib.rs`, and its `--package` to the `cargo clean` that drops the stub artifacts; the clean is what makes the second compile deterministic, because `COPY` preserves the build context's older mtimes and cargo would otherwise call the stubs fresh.
- Environment-variable parity (PMS-836): `compose.dev.yml` declares the dev `server` service's environment as an explicit per-key map with no `env_file:`, so it ENUMERATES the container's environment. A variable the code reads with no line there cannot be set in dev at all: the operator follows `.env.example`, edits `.env`, gets no error, and the feature stays off. That shipped `SPA_BASE_URL`, `ABUSE_CONTACT_EMAIL`, `PUBLIC_API_BASE_URL`, `TENANT_LOGO_MAX_BYTES`, `ATTACHMENT_DIR`, `IP2LOCATION_DB_PATH`, `IP2PROXY_DB_PATH` and `LOGIN_APPROVAL_ENABLED` unreachable. Adding an `env::var` read therefore means adding a `.env.example` key AND a compose line whose `:-` default reproduces the code's own fallback; `scripts/check-env-example.nu` (in `just check` and `check.yml`) fails on either omission, on a `.env.example` key nothing consumes, and on a stale allowlist entry. The allowlist in that script carries one stated reason per deliberate asymmetry (build-time vars, the host-side bootstrap CLI's `.env.infisical` vars, `INFISICAL_ADDRESS` versus `MOKOSH_SERVER_INFISICAL_ADDRESS`). A forwarded-but-unset key arrives as `""`, so every reader must treat empty as unset. Uploads (`ATTACHMENT_DIR`, which holds ticket attachments and the `tenant-logos/` subdirectory) live on the `dev-mokosh-attachments-${USER}` volume at `/data/attachments` so a logo survives a rebuild.
- Releases: `just create-release <major|minor|hotfix>` bumps `Cargo.toml`, pushes a `release/v<X.Y.Z>` branch, opens the PR. CI tags + publishes on merge.
- Email backend selection: `MailerConfig::from_env().build()` returns `SmtpMailer` if `SMTP_HOST` is set, `LogMailer` otherwise. `SMTP_USERNAME` without `SMTP_PASSWORD` is a hard error at startup (fail-loud, not silent degrade).
- `ENCRYPTION_KEY` must parse as 32 bytes (raw or 64 hex chars) via `utils::crypto::parse_encryption_key`. Used for AES-256-GCM at-rest encryption of per-tenant secrets (e.g. payment-gateway configs).
- `CORS_ORIGIN` is comma-separated; required to be a valid header value or startup panics. Defaults to `[CLIENT_ORIGIN]`.
- `LOGIN_APPROVAL_ENABLED` (PMS-658) turns on the suspicious-login notify-and-approve gate; off by default because it can withhold a login, so it is opt-in per deployment for a staged rollout. When on and a password login clears password/MFA but comes from a new country (needs `IP2LOCATION_DB_PATH`) or a new device (client-supplied `device_id` in the login body), the session/tokens are withheld and a single-use 6-digit code is emailed; the client re-POSTs `/auth/login` with `approval_code` to finish (mirrors the `mfa_required` flow). Off = the PMS-657 alert-only behaviour. Gates password login in v1 (the portal path is a follow-up); tables `login_approvals` + `user_login_devices`.
- Outbound-URL screening (PMS-805, PMS-809): every outbound fetch whose URL comes from a request or from tenant-editable configuration runs through `utils::net::guard_outbound_url`, which resolves the host and refuses any address `is_non_public_ip` rejects, before the first connect and again on every redirect hop. Three callers: the company website probe (`modules/contacts/website_probe.rs`, ports pinned to 80/443), the ticket-automation `webhook` action (`modules/tickets/automation.rs`, refusal logged with the rule id and the blocked address), and `TacticalRmmProvider` (`modules/rmm/provider.rs`, refusal is an `AppError::Configuration` surfaced in `rmm_connections.last_error`; redirects are not followed). Do not copy the predicate or the resolve loop: a second definition of either fails `utils::net`'s `exactly_one_definition_in_the_crate` test. `OUTBOUND_PRIVATE_ALLOWLIST` is the operator escape hatch (comma-separated hostnames, IPs, or CIDRs) for a self-hosted integration that really does live on a private network; unset means no exemption. Fetches whose URL comes from operator env are deliberately NOT screened (`INFISICAL_ADDRESS`, the Stripe API base, the `OIDC_ISSUER` JWKS, the fixed upstream version check).
- Docker resource naming: every service/volume/network is prefixed with the app name; dev resources get an extra `dev-` prefix. Sub-service data stores sort adjacent to their parent (`dev-backup-infisical-postgres`, not `dev-backup-postgres-infisical`).
- Dev stack binds to a private LAN IP (br0/eth0), not 127.0.0.1, so sibling containers on the host can reach the API while the public internet cannot.
