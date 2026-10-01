# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Mokosh Server: PSA (Professional Services Automation) REST API for MSPs. Rust + Axum + SQLx + PostgreSQL. Two binaries:

- `mokosh-server`: long-running HTTP API (`src/main.rs`).
- `mokosh-bootstrap`: one-shot CLI for first-run Infisical setup and OIDC client registration (`src/bin/mokosh-bootstrap.rs`).

## Common commands

All driven through `just` (see `justfile`). Required tooling: `just`, Nushell `0.112.2`, Docker + Compose v2, Rust `1.98.1` (the exact patch `rust-toolchain.toml` pins, so rustfmt and clippy match CI), `sqlx-cli` for migrations, `cargo-machete` for the unused-dependency gate (`cargo install --locked cargo-machete`).

```
just                       # list recipes
just check                 # every check.yml step except its cargo test steps (run before pushing)
just check-compile         # cargo check --all-targets
just check-clippy          # cargo clippy --all-targets -- -D warnings (same as check.yml)
just check-fmt             # cargo fmt --all --check
just check-migration-immutability # fail if a migration already on main is modified or deleted
just check-pool-safety     # fail if a serving `.pool()` call lacks its `// SAFETY (PMS-285` note
just check-validate-parity # fail if a Create*Request and its Update*Request validate a field differently
just check-workspace-deps  # [workspace.dependencies] matches what members inherit
just check-unused-deps     # cargo-machete: fail on a dependency with no call site
just check-env-example     # every var the code reads has a .env.example key and a compose.dev.yml line
just check-doc-recipes     # every `just <recipe>` in a doc listed in scripts/check-doc-recipes.nu exists in the justfile
just check-config-doc-paths # every docs/ path named in .env.example / compose.dev.yml / justfile exists
just check-doc-links       # every relative Markdown link resolves to a path that exists
just check-claude-md       # CLAUDE.md stays under 20,000 bytes and its docs/ links resolve (PMS-1437)
just check-single-build    # fail if a compiling workflow builds the same tree twice (DEV-612)
just fmt                   # cargo fmt --all
just test                  # cargo test (workspace-wide)
just test-integration      # Postgres-backed tests/*.rs suite (mirrors CI integration.yml)
just install-hooks         # install the git pre-commit hook -> runs `just pre-commit` (from common)
just pre-commit            # check.yml's cargo steps except doc tests: fmt/clippy/compile/unit, in the dev container
just build                 # cargo build --release --bins
just migrate-run           # sqlx migrate run against $DATABASE_URL
just migrate-create <name> # new migration in migrations/
just check-docker          # validate OCI image builder stage (NOT part of `just check`)
just build-docker          # build production OCI image (oci-build/Dockerfile)
```

`just check` and `just pre-commit` are complements: together they cover `check.yml` except its doc tests. `pre-commit`, `install-hooks` and `create-release` come from the `common` submodule, so a fresh clone runs `git submodule update --init` first. Details: [local vs CI checks](docs/dev-docs/local-vs-ci-checks.md#how-the-two-recipes-relate).

Adding a step to `check.yml` means adding the matching recipe to `just check` (or `just pre-commit`), the row in that file, and its line in `docs/recipes.md`.

Single test: `cargo test -p <crate> <test_name>` (workspace), e.g. `cargo test -p mokosh-server utils::totp::tests::rfc6238_vector`.

### Dev stack

A single Traefik-routed dev stack (PMS-511 folded the former SSO overlay into `compose.dev.yml`):

```
just dev                   # Traefik-routed stack at https://${USER}-mokosh-api.a8n.run (mokosh-server + Postgres + mailpit)
just dev-infisical         # opt-in: Infisical + its Postgres (compose profile: infisical)
just dev-s3                # opt-in: MinIO, and fills the blank STORAGE_S3_* keys in .env (compose profile: s3)
just down                  # stop the dev stack, remove orphans (volumes preserved)
just dev-clean             # stop + wipe volumes + remove .env (keeps .env.infisical)
just infisical-bootstrap   # one-time after `just dev-infisical`, fills INFISICAL_* in .env
```

OIDC client registration recipes (`register-client`, etc.) were removed with mokosh-auth in PMS-295: bunyip is the sole OP and owns its own client registry, so RPs register with bunyip, not mokosh.

`just dev` rewrites `USER` in `.env` on each run, generates `.env` from `.env.example` once per clone (PMS-490), needs the external `network-traefik-public`, and runs as compose project `dev-mokosh-${USER}` (PMS-1281). Details: [dev stack notes](docs/quickstart.md#12-dev-stack-notes).

## Architecture

### Top-level layout

```
src/
  main.rs               mokosh-server entrypoint: AppConfig::from_env, build router
  lib.rs                library crate root
  api/router.rs         create_api_router: builds every /api/v1 nest (see "Routing model"), wires middleware + CORS
  app_secrets/          AppSecretProviderKind: application-tier secrets (database, file, env, Infisical), chosen by SECRET_BACKEND (PMS-988)
  bin/mokosh-bootstrap.rs CLI: bootstrap-infisical, qa-seed/qa-teardown, normalize-company-industries
  cli/                  Operator subcommands mokosh-server dispatches before binding a port (PMS-494); providers.rs and verify.rs add the four provider subcommands (PMS-1012/1013)
  config/               ConfigProvider: the declared key registry and the one configuration read path (PMS-982)
  db/                   Database wrapper around sqlx::PgPool
  infisical/            Infisical HTTP client + first-run bootstrap
  modules/<name>/       Feature modules (see "Modules" below)
  pdf/                  Document model, and the one place it becomes PDF bytes (PMS-876)
  providers/status/     ProviderStatusReport: collects and renders which provider each capability kind is using; itself selected by no env var (PMS-989)
  scheduler/            Registry for the interval background jobs (PMS-135); `one_shot` for work that runs once per process start (PMS-1320)
  secrets/              SecretProvider: database (default) or Infisical, chosen by SECRET_BACKEND (PMS-967)
  storage/              File storage seam; the provider of record for STORAGE_ROOT (PMS-910); branding/ also reads it through the config seam for local-path assets
  utils/                error, email (Mailer trait + SmtpMailer/LogMailer), crypto, validation, pagination
  version.rs            VersionInfo (build-time git hash/describe via build.rs)
  version_check.rs      Opt-in self-hosted update check against MOKOSH_UPDATE_CHECK_URL (PMS-238)

crates/                 Workspace members: mokosh-types, build-metadata
migrations/             SQLx migrations, embedded at compile time via sqlx::migrate!
oci-build/Dockerfile    Production multi-stage Alpine + musl
Dockerfile              Dev image (debug build, source-mounted)
compose.dev.yml         Traefik-routed dev stack (per-developer *.a8n.run)
.forgejo/workflows/     CI (Forgejo)
docs/                   Contributor/user docs; docs/dev-docs/ = internal notes (codebase-state.md = frozen 2026-05-06 route catalog)
```

### Auth: two independent mechanisms (PMS-295)

Two parallel paths: bunyip `at+jwt` Bearers checked against bunyip's JWKS, and legacy HS256 Bearers on `user_sessions`. Both run the PMS-698 principal gate; a caller's own tenant comes from membership state, never a claim (PMS-244). [Full text](docs/architecture.md#auth-two-independent-mechanisms-pms-295).

### The contact plane is a third, fully separate identity plane

A contact (`contacts` row) owns its credential lifecycle on `/api/v1/contact/*` and never touches `users`: rotation-family sessions (PMS-1062), MFA on both login paths (PMS-1063), MSP-issued resets (PMS-1343). [Full text](docs/architecture.md#the-contact-plane-is-a-third-fully-separate-identity-plane).

### Providers (PMS-1009)

`docs/providers.md` is the contract for every selectable-implementation seam: the provider kinds, the three tiers (bootstrap / application / tenant, separated by bootstrap order rather than by sensitivity), where each is configured, priority, the four boot classifications, refresh, and the migrate-verify-purge
workflow. Read it before adding a seam or a second implementation of one, because the parts that are easy to get wrong (a silent fallback to the default, a purge that deletes a value not verified elsewhere, an unreachable provider reported as absent) are exactly the parts it fixes. `src/config/`, `src/secrets/`
and `src/storage/` are the three seams that already follow it; application secrets, authentication and email do not yet, and `docs/ROADMAP.md` carries the sequencing with each phase linked to its issue.

Two rules from that document bind any change here. Provider enablement is bootstrap configuration, never served by a provider, because configuration that locates configuration cannot live inside what it locates. And a key read outside its provider is the defect the model exists to prevent: Bunyip had
a working Infisical client and still served secrets from the database, because nothing forced the read through the seam.

### Routing model

`create_api_router` nests `/api/v1/*` (session), `/api/v1/public/*` (no auth, by design), `/api/v1/contact/*` (contact Bearer) and the signed Bunyip, Stripe and PayPal receivers; JSON bodies pass `sanitize_json_body` (PMS-924). Keep the [full list](docs/architecture.md#routing-model) in step with the `.nest(...)` calls.

### Multi-tenancy

No middleware-level tenant scoping: every service method takes the scope explicitly. Since PMS-139 that scope is a `TenantId` newtype (`src/modules/auth/tenant.rs`) whose in-crate constructor is `pub(crate)` and is reached only through `CurrentUser::tenant()`, so a handler that forgets to thread the
caller's tenant no longer compiles instead of leaking across tenants. The deliberate escape hatch is `TenantId::from_trusted`, for the paths where the scope genuinely is not a `CurrentUser` claim: the Stripe and RMM webhook receivers, super-admin `tenants` handlers addressing a path tenant, portal contact
sessions, the seeders, and the cross-tenant workers (`calendar/worker.rs`, `sla/worker.rs`, the billing sweep). Cross-cutting issue #8 in `docs/dev-docs/codebase-state.md` records the rollout.

### Migrations

Embedded via `sqlx::migrate!` and run at startup. Committed migrations are immutable; guarded content UPDATEs assert row counts (PMS-1117); a GRANTed role must exist in tests (PMS-988); a new table is granted to `mokosh_app` (PMS-1265). [Full text](docs/architecture.md#migration-rules).

### Module status

Most route groups have real handlers. `src/api/router.rs` nests/merges ~30 implemented modules (`auth`, `contacts`, `tenants`, `tickets`, `billing`, `projects`, `calendar`, `contracts`, `quotes`, `assets`, `rmm`, `sla`, `saved_reports`, `workflows`, `time_tracking`, and more); the old `stub_routes()`
501 placeholder mechanism is gone. The report-export route (`src/modules/reports/routes.rs`) serves `csv` and `pdf` (PMS-876) and rejects every other `format` with 400 and not 501: `format` is an enumerated query parameter, so a value outside the implemented set is an out-of-range request rather than
a server-side gap (PMS-854). The schema is still ahead of the handler layer in places. `docs/dev-docs/codebase-state.md` is a frozen 2026-05-06 snapshot (PMS-849), not a current per-module status: read it for the `F1..F14` fix ids, the numbered cross-cutting issues that source comments cite, and the
shallow-DTO traps in tickets, and read `src/api/router.rs` plus the "Routing model" section above for what is actually mounted. Do not append to it; a new route group is recorded in the "Routing model" list.
That list is in [`docs/architecture.md`](docs/architecture.md#routing-model).

## Conventions specific to this repo

One line per rule, linking its full text. A new convention adds its text under `docs/invariants/` and one line here (PMS-1437).

### Billing

- Billable time is armed at creation, not approval ([PMS-944](docs/invariants/billing.md#billable-time-pms-944))
- A quote's tax follows the invoice rule ([PMS-1038](docs/invariants/billing.md#quote-tax-pms-1038))
- `apply_tax` derives tax from the tenant rate ([PMS-1029](docs/invariants/billing.md#invoice-tax-pms-1029))
- An invoice's balance has one writer ([PMS-953](docs/invariants/billing.md#balance-pms-953))
- A sent invoice is replaced, and the replacement voids it ([PMS-1334](docs/invariants/billing.md#amendment-pms-1334))
- Overdue is derived; reminders are a worker ([PMS-1037](docs/invariants/billing.md#overdue-pms-1037))
- A write-off is not a credit ([PMS-1036](docs/invariants/billing.md#write-off-pms-1036))
- Sending emails the invoice; `sent` means it went ([PMS-991, PMS-992](docs/invariants/billing.md#sending-pms-991-pms-992))
- `net_days` derives the default due date ([PMS-990](docs/invariants/billing.md#net-terms-pms-990))
- Lines copy prices; `billing_rule` decides billing ([PMS-955](docs/invariants/billing.md#products-pms-955))
- Prepaid blocks draw down when time is logged ([PMS-951](docs/invariants/billing.md#prepaid-draw-pms-951))
- Prepaid hours never re-invoice; overage bills at its rate ([PMS-1035](docs/invariants/billing.md#overage-pms-1035))
- An invoice uses the tenant's currency ([PMS-1028](docs/invariants/billing.md#currency-pms-1028))
- Billing handlers take `RequireBilling` and `RequireFinance` ([PMS-962](docs/invariants/billing.md#read-gates-pms-962))
- Dual-plane invoice handlers gate in the body ([PMS-1041](docs/invariants/billing.md#dual-plane-gates-pms-1041))

### Documents and PDF

- An invoice freezes the MSP's identity at first send ([PMS-911](docs/invariants/documents.md#issuer-pms-911))
- An issued document is kept, not reproduced ([PMS-959](docs/invariants/documents.md#issued-bytes-pms-959))
- A line names the work; a document addresses the customer ([PMS-1004](docs/invariants/documents.md#bill-to-pms-1004))
- A document names the person it was sent to ([PMS-1001](docs/invariants/documents.md#recipient-pms-1001))
- PDFs embed Noto Sans ([PMS-1007](docs/invariants/documents.md#fonts-pms-1007))
- A PDF embeds only the glyphs it drew ([PMS-1008](docs/invariants/documents.md#subsetting-pms-1008))
- The document template is a tenant setting ([PMS-1006](docs/invariants/documents.md#templates-pms-1006))

### Time and work days

- `entry_kind` splits client work from the MSP's own time ([PMS-942](docs/invariants/time.md#entry-kind-pms-942))
- Timesheets are a gated module ([PMS-943](docs/invariants/time.md#timesheets-gate-pms-943))
- A work day is derived from its segments ([PMS-950](docs/invariants/time.md#work-day-pms-950))
- "Today" is the person's zone, never UTC ([PMS-1027](docs/invariants/time.md#today-pms-1027))
- A tenant-level job takes the tenant's day ([PMS-1030](docs/invariants/time.md#tenant-day-pms-1030))
- A work-day segment can be corrected ([PMS-1145](docs/invariants/time.md#segment-edits-pms-1145))

### Identity and auth

- `ENCRYPTION_KEY` must parse as 32 bytes ([details](docs/invariants/identity-auth.md#encryption_key))
- `CORS_ORIGIN` must be a valid header value ([details](docs/invariants/identity-auth.md#cors_origin))
- `LOGIN_APPROVAL_ENABLED` gates suspicious logins ([PMS-658](docs/invariants/identity-auth.md#login-approval-pms-658))
- `users` mirrors to `identities` one way ([PMS-1120](docs/invariants/identity-auth.md#identity-mirror-pms-1120))
- A TOTP secret is sealed on both planes ([PMS-1055](docs/invariants/identity-auth.md#totp-secret-pms-1055))

### Configuration and providers

- Stored files go through one seam, `crate::storage` ([PMS-910](docs/invariants/config-providers.md#storage-seam-pms-910))
- The storage provider is chosen once per process ([PMS-958](docs/invariants/config-providers.md#storage-provider-pms-958))
- Config has one read path over a declared registry ([PMS-982](docs/invariants/config-providers.md#config-registry-pms-982))
- A selectable implementation is a provider ([PMS-1010](docs/invariants/config-providers.md#provider-naming-pms-1010))
- The deployment mode supplies default providers ([PMS-1011](docs/invariants/config-providers.md#deployment-mode-pms-1011))
- The hosted deployments declare the database secret provider ([PMS-1440](docs/providers.md#what-the-hosted-deployments-actually-declare-pms-1440))
- SMTP when `SMTP_HOST` is set, else `LogMailer` ([details](docs/invariants/config-providers.md#email-backend))
- Untrusted outbound URLs pass `guard_outbound_url` ([PMS-805, PMS-809](docs/invariants/config-providers.md#outbound-urls-pms-805-pms-809))
- `integrations.status` has one writer ([PMS-1312](docs/invariants/config-providers.md#payment-status-pms-1312))
- The Google OAuth client is the host's ([PMS-1430](docs/invariants/config-providers.md#google-client-pms-1340))
- A one-time correction runs once per boot ([PMS-1320](docs/invariants/config-providers.md#one-shots-pms-1320))
- Every stored object puts its tenant first ([PMS-1318](docs/invariants/config-providers.md#tenant-first-pms-1318))
- Storage settings are `STORAGE_`-prefixed ([PMS-1317](docs/invariants/config-providers.md#storage-names-pms-1317))

### CI, release and repo hygiene

- Branches are `fix/`, `feat/`, `chore/`; no `gh` ([details](docs/invariants/ci-release.md#branches))
- A compiling CI job uses the dev runner label ([PMS-719, GOV-43](docs/invariants/ci-release.md#runner-labels-pms-719-gov-43))
- OCI builds cache through `type=gha` only ([PMS-720, GOV-20](docs/invariants/ci-release.md#oci-cache-pms-720-gov-20))
- The trigger alone picks the image tag ([PMS-733](docs/invariants/ci-release.md#publish-tags-pms-733))
- Compile on `pull_request`, never again on `push: main` ([DEV-612](docs/invariants/ci-release.md#single-build-dev-612))
- `[workspace.dependencies]` lists only inherited crates ([PMS-785](docs/invariants/ci-release.md#workspace-deps-pms-785))
- `cargo machete` fails an unused dependency ([PMS-780](docs/invariants/ci-release.md#unused-deps-pms-780))
- Release image caches dependencies in their own layer ([PMS-781](docs/invariants/ci-release.md#image-layers-pms-781))
- A config read needs registry, `.env.example` and compose entries ([PMS-836](docs/invariants/ci-release.md#env-parity-pms-836))
- Two migrations cannot share a version ([PMS-965](docs/invariants/ci-release.md#migration-versions-pms-965))
- A red integration run blocks the merge ([PMS-1426](docs/invariants/ci-release.md#integration-required-pms-1426))
- `just create-release` opens the release PR ([details](docs/invariants/ci-release.md#releases))
- A database test is `#[mokosh_test]` ([PMS-1254](docs/invariants/ci-release.md#test-databases-pms-1254))
- The SPA repository is `mokosh-apps` ([PMS-856](docs/invariants/ci-release.md#client-repo-pms-856))
- Docker resources carry the app prefix ([details](docs/invariants/ci-release.md#docker-naming))
- Dev stack binds to a private LAN IP ([details](docs/invariants/ci-release.md#lan-bind))

### Knowledge base

- A KB version records who, what kind and why ([PMS-1126](docs/invariants/kb.md#versions-pms-1126))
- KB comments are staff-only ([PMS-1128, PMS-1129, PMS-1130](docs/invariants/kb.md#comments-pms-1128-pms-1129-pms-1130))

### Contacts and mail

- A contact's company mirror is written with its link ([PMS-1069](docs/invariants/contacts.md#company-mirror-pms-1069))
- Ticket-note editing is a tenant policy ([PMS-974](docs/invariants/contacts.md#note-editing-pms-974))
- A second mail audience is a second event ([PMS-1140](docs/invariants/contacts.md#mail-audiences-pms-1140))
- The label selection is the import filter ([PSA-70 E, PMS-1358](docs/invariants/contacts.md#sync-labels-psa-70-e-pms-1358))
