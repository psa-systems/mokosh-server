# Mokosh E2E suite (Playwright)

End-to-end tests that run against a **deployed** mokosh-server instance (staging
by default), not a CI-built artifact. Phase 1 (PMS-140): stand up the harness,
shake out flakiness. The CI run is **post-merge and informational**, not a merge
gate (that is PMS-141).

## What it covers

| Area | File | How |
| --- | --- | --- |
| Auth login / session / logout | `tests/auth.spec.ts` | real browser drives the SPA login form (TOTP-aware), opens the avatar menu, clicks Logout, asserts URL returns to the hub's `/login` (**quarantined - `test.fixme`**; PMS-148: after the PMS-142 v2 un-fixme merged, post-merge CI exposed a separate failure mode where the auth-ui project's login deterministically stalls when run after `setup` finishes - form submit click no-op's, URL stays on the hub `/login`. Bunyip's `/logout` fix from BUNYIP-53 IS deployed; this is a different problem) |
| OIDC token flow | `tests/oidc.spec.ts` | request context with replayed OP session cookies (from `e2e/.auth/op-state.json`, written by setup): `/oauth2/authorize` -> code -> `/oauth2/token` -> `/oauth2/userinfo` -> refresh (PKCE). Asserts the full OP contract; mokosh-server's RS path is exercised indirectly by every other api test (**quarantined - `test.fixme`**; PMS-435: the PMS-434 diagnostic run #2098 proved `bunyip_op_session` is captured, persisted on the right domain, and replayed by the fixture, yet `/oauth2/authorize` still 302s to `/login` with no `state`. Root cause is bunyip's COOKIE_DOMAIN / `bunyip_op_session` scoping (BUNYIP-146), not an e2e forwarding defect; un-fixme when BUNYIP-146 ships) |
| Form validation (PMS-518 / AC7) | `tests/form-validation.spec.ts` | real browser drives the SPA create forms (new-ticket, new-contact): an empty submit must flag EVERY missing required field at once (per-field inline errors; company in the form-level banner) and not navigate, and correcting a field clears only its error. DOM-only, like `auth.spec.ts` (the FormGuard validation is client-side and never reaches an API). `form-ui` project (**quarantined - `test.fixme`**; un-fixme once the target's mokosh-apps SPA includes the PMS-518 `FormGuard` migration AND the browser-login path is green - it shares `loginViaSpa`, currently blocked by the PMS-148 stall) |
| Tickets CRUD | `tests/tickets.spec.ts` | request context against `/api/v1/tickets` |
| Contacts + tenants + cross-tenant canary | `tests/contacts.spec.ts` | request context, tenant-scoped smoke + leak check |
| Time-tracking CRUD | `tests/time-tracking.spec.ts` | work types + time entries + rounding rules (PMS-155); enables the `time_tracking` module first |
| Projects CRUD | `tests/projects.spec.ts` | project + phase + task + task-status (PMS-155); enables the `projects` module first |
| Billing CRUD | `tests/billing.spec.ts` | tax-rate + payment full lifecycle, invoices read-only (no DELETE route) (PMS-155); enables the `billing` module first |
| Contracts CRUD | `tests/contracts.spec.ts` | contract + item + rate card + hour-balance (PMS-155); enables the `contracts` module first |
| Calendar CRUD | `tests/calendar.spec.ts` | appointment + time-off + on-call schedule (PMS-155); enables the `calendar` module first |
| SLA CRUD | `tests/sla.spec.ts` | policy + business hours + holiday calendar (PMS-155); SLA is not module-gated, writes are admin-only |
| Assets CRUD | `tests/assets.spec.ts` | asset type + asset + encrypted configuration item (PMS-155); enables the `assets` module first |
| Knowledge-base CRUD | `tests/knowledge-base.spec.ts` | category + article + version history (PMS-155); enables the `knowledge_base` module first |
| Notifications CRUD | `tests/notifications.spec.ts` | template + channel create/list/delete (PMS-155); not module-gated, writes admin-only |
| Settings CRUD | `tests/settings.spec.ts` | tenant setting upsert/read/update/delete keyed by category+key (PMS-155); throwaway `e2e` category |
| Audit log | `tests/audit.spec.ts` | read-only; creates a company and asserts the audit log surfaces its `create` entry (PMS-155) |
| Reports read smoke | `tests/reports.spec.ts` | dashboard/tickets/time/billing + CSV export return 200 (PMS-155); enables the `reports` module first |
| RMM CRUD | `tests/rmm.spec.ts` | connection (fake credentials) + alert rule + device mapping (PMS-155); enables the `rmm_integration` module first |
| Dispatch board | `tests/dispatch.spec.ts` | aggregated board read smoke for a date range (PMS-155); enables the `calendar` module first, requires `from`+`to` |

**Module gating.** Most feature modules (time_tracking, projects, billing, contracts, calendar, assets, knowledge_base, reports, rmm_integration) are tenant-gated and default to DISABLED (`is_module_enabled` treats a missing `module_config` row as `false`). Each spec for a gated module enables it up front via `PUT /api/v1/settings/modules/{module}` (admin-only, idempotent) so it runs regardless of the staging tenant's current config; see `lib/factories.ts::enableModule`. The enable persists on the E2E tenant - this is configuration, not swept residue. SLA is NOT gated; its writes are simply admin-only.

**Invoices.** Billing has no `DELETE /api/v1/invoices/{id}` route, so an invoice created by the suite would be permanent residue (the leak PMS-149/PMS-155 set out to avoid). The billing spec therefore smoke-reads the invoice list only; a follow-up should add a delete/void-and-purge route and the matching invoice lifecycle.

**Harness shape.** Two independent auth paths because the mokosh-clients SPA
keeps its bearer token in WASM memory (`mokosh-clients/src/hooks/fetch.rs`),
which Playwright's `storageState` cannot replay; and direct
`POST /api/v1/auth/login` does not work either (the OP advertises only
`authorization_code` + `refresh_token`, and SPA-signed-up accounts do not
exist in mokosh's local `users` table):

- **`setup` project** (`tests/global.setup.ts`) drives the SPA login in a
  real browser (TOTP-aware), then writes two artifacts: (a) the
  bunyip-issued bearer to `e2e/.auth/token.txt`, captured from the first
  outbound `Authorization: Bearer` header (any host - the SPA's first
  authenticated call lands on the bunyip hub's `/v1/auth/memberships`,
  and the same bearer authenticates mokosh's RS-verified `/api/v1/*`);
  and (b) the OP session cookies to `e2e/.auth/op-state.json`, filtered
  to the OP host and its parent domain. The `api` project consumes both:
  `lib/fixtures.ts` exports a default `test` (injects the bearer header
  for PSA-API specs like `tickets`, `contacts`) and an `oidcTest`
  (replays the OP cookies via `storageState`, no bearer header, used by
  `tests/oidc.spec.ts`). Teardown reads `token.txt` only.
- **`auth-ui` project** (`tests/auth.spec.ts`) drives the SPA login form in
  a real browser and asserts on URL transitions (login leaves `/login`,
  logout returns to it). DOM-only, no API probe - the SPA's in-memory token
  cannot be exfiltrated for an external request context to use. Captures a
  URL trail + request log via `lib/page-diagnostics.ts` and folds them into
  the thrown error on failure. Currently `test.fixme` pending PMS-148 (see
  "What it covers" above).

## Required configuration

Set via `e2e/.env` locally (copy from `.env.example`) or Forgejo Actions secrets
in CI. Required unless noted.

**Local vs CI naming (PMS-271).** Locally these are the plain `E2E_*` names
below, holding one environment at a time. In CI the Forgejo Actions secrets hold
both environments at once, and `.forgejo/workflows/e2e.yml` selects per var and
exposes the result on the plain `E2E_*` names per run, so `env.ts` and the gate
scripts only ever read the plain names and stay environment-agnostic. The CI
secret names follow the **deployment's own variable names** where one exists
(verified against the mokosh infra repo, `server/{c-01 staging, nc-01
production}`):

| `E2E_*` var | CI secret(s) | Deployment source |
| --- | --- | --- |
| `E2E_OIDC_CLIENT_ID` | `MOKOSH_OIDC_CLIENT_ID` (single, shared) | the mokosh-apps public PKCE client, seeded by `bunyip-api` with the **same id in both envs**, read by the SPA as `MOKOSH_OIDC_CLIENT_ID` |
| `E2E_OIDC_REDIRECT_URI` | `MOKOSH_APPS_REDIRECT_URIS_STAGING` / `_PRODUCTION` | `bunyip-api` `MOKOSH_APPS_REDIRECT_URIS` (per env: `https://msp.a8n.systems/auth/callback` vs `https://msp.psa.systems/auth/callback`) |
| `E2E_OP_BASE_URL` | `OIDC_ISSUER_STAGING` / `OIDC_ISSUER_PRODUCTION` | `mokosh-server` `OIDC_ISSUER` (the bunyip OP apex: `https://api.a8n.systems` vs `https://api.psa.systems`) |
| everything else (`BASE_URL`, `EMAIL`, `PASSWORD`, `TENANT_ID`, `TOTP_SECRET`, `FOREIGN_COMPANY_ID`) | `E2E_STAGING_<NAME>` / `E2E_PRODUCTION_<NAME>` | test-only; no deployment variable to match |

Forgejo must hold both env values at once, so per-env secrets keep a
`_STAGING`/`_PRODUCTION` suffix on the deployment base name; the shared client id
needs no suffix. Automatic runs (push, PR) always resolve to staging; production
is manual-dispatch only (see [CI](#ci)).

| Var | Purpose |
| --- | --- |
| `E2E_BASE_URL` | **required** - SPA host the auth-ui project navigates to. No default; set per environment (staging `https://msp.a8n.systems`, prod `https://msp.psa.systems`) |
| `E2E_API_BASE_URL` | *optional* - API host for `/api/v1`. Defaults to prepending `api.` to `E2E_BASE_URL` (e.g. `msp.a8n.systems` -> `api.msp.a8n.systems`). Set when the deployment uses a different naming scheme |
| `E2E_OP_BASE_URL` | *optional* - OIDC OP host for `/oauth2/*` + `/.well-known/openid-configuration`. Defaults to `E2E_API_BASE_URL`. On bunyip-as-OP deploys the OP runs on the apex `api.<tld>`, NOT the mokosh API host, so set this explicitly (e.g. `https://api.a8n.systems`) |
| `E2E_EMAIL` | dedicated E2E account login |
| `E2E_PASSWORD` | E2E account password |
| `E2E_TENANT_ID` | UUID of the dedicated E2E tenant |
| `E2E_OIDC_CLIENT_ID` | public OIDC client id for the token-flow test |
| `E2E_OIDC_REDIRECT_URI` | redirect_uri registered for that client (no default; must match exactly or the OP returns `invalid_redirect_uri`). Only the `code` is captured, the URL is never loaded |
| `E2E_TOTP_SECRET` | base32 TOTP secret for the E2E account. Setup generates the second-factor code at runtime; same string you pasted into your authenticator when enrolling 2FA on the account |
| `E2E_FOREIGN_COMPANY_ID` | *optional* - a company id in **another** tenant. The cross-tenant company canary always runs; setting this strengthens it (an existing, foreign-owned company must still 403/404). When unset, `global.setup.ts` falls back to a random, well-formed UUID the E2E tenant cannot own |

## One-time staging provisioning (manual)

Done once by a human before the suite can pass against a deployment:

1. **E2E tenant** - create a dedicated tenant for E2E. Record its UUID as
   `E2E_TENANT_ID`. All test records live here and are swept after each run.
2. **E2E account** - create a user in that tenant with the **`admin`** role
   (or `super_admin`). Admin is REQUIRED, not optional: the suite enables
   tenant-gated modules via the admin-only `PUT /api/v1/settings/modules/{module}`
   route, and many writes are gated by `RequireAdmin` / `RequireManager` /
   `RequireFinance` (admin satisfies all three). A non-admin account passes only
   the tickets / contacts / OIDC specs and 403s on everything else. Record
   `E2E_EMAIL` / `E2E_PASSWORD`. Enable 2FA on the account and save the base32
   secret (the string under the QR code at enrollment) as `E2E_TOTP_SECRET` -
   the setup test
   computes the second factor at runtime.

   **Where the role lives, and how to set it.** The E2E account signs in
   through the bunyip SSO, so it reaches mokosh on the bunyip Resource-Server
   path (`ensure_user_from_bunyip`, `src/modules/auth/middleware.rs`). That path
   resolves the request's role from the mokosh `users` table row
   (`get_user_by_id(...).role`), NOT from the access token - the bunyip token
   only carries `sub` + email. On first login the row is auto-created by
   `upsert_user_from_oidc(...)` with the schema default `role = 'technician'`
   (`migrations/003_auth.sql`), which is non-admin. So "make the account admin"
   means flipping that row's `role` to `admin`. Valid values:
   `super_admin, admin, manager, technician, dispatcher, sales, finance`.

   The role is re-read from the row on every request, so the change takes effect
   on the next call (no re-login needed). Two ways to set it:

   - **Direct DB on the staging mokosh Postgres** (simplest, avoids the
     chicken-and-egg below):

     ```sql
     -- confirm the row first
     SELECT id, email, role, tenant_id FROM users WHERE email = '<E2E_EMAIL>';
     -- elevate
     UPDATE users SET role = 'admin' WHERE email = '<E2E_EMAIL>';
     ```

   - **Admin API**, if an admin/super_admin already exists: as that admin,
     `PUT /api/v1/users/{e2e_user_id}` with body `{"role":"admin"}`
     (`update_user`; rejects non-admin callers). `e2e_user_id` is the bunyip
     `sub` UUID, which is the mokosh `users.id`; list it via
     `GET /api/v1/users` as the admin.

   **Bootstrapping the first admin.** If no admin exists yet, an account whose
   email is in the `OAUTH_SUPER_ADMIN_EMAILS` env and that signs in via the
   **Google** path is auto-provisioned as `super_admin`
   (`provision_user_from_google`). That account can then elevate others via the
   Admin API above. This allowlist only applies to the Google login path, not
   the bunyip SSO path the E2E account uses, so it cannot elevate the E2E
   account directly - use the DB update for that.
3. **OIDC client** - reuse the staging SPA public client (PKCE) or register a
   dedicated E2E client. Record `E2E_OIDC_CLIENT_ID` and a registered
   `E2E_OIDC_REDIRECT_URI`. If `/oauth2/authorize` redirects the E2E session to
   a login screen instead of returning a `code`, register a dedicated E2E client
   whose redirect_uri allows capture-only.
4. *(optional)* **Foreign company** - note a company id from a different tenant
   as `E2E_FOREIGN_COMPANY_ID` to strengthen the cross-tenant leak canary. The
   canary runs either way: when unset, `global.setup.ts` uses a random,
   well-formed UUID the E2E tenant cannot own.
5. Store all of the above as Forgejo Actions secrets for
   `.forgejo/workflows/e2e.yml` (PMS-271). The secret names follow the table in
   [Required configuration](#required-configuration): three vars use the
   deployment's own variable names (`MOKOSH_OIDC_CLIENT_ID`, a single shared
   value; `MOKOSH_APPS_REDIRECT_URIS_STAGING` / `_PRODUCTION`;
   `OIDC_ISSUER_STAGING` / `OIDC_ISSUER_PRODUCTION`), and the test-only vars use
   `E2E_STAGING_<NAME>` / `E2E_PRODUCTION_<NAME>` (e.g. `E2E_STAGING_BASE_URL`,
   `E2E_PRODUCTION_TOTP_SECRET`). Provision the staging set first, then
   production; the shared `MOKOSH_OIDC_CLIENT_ID` is set once. The workflow
   selects per var and exposes the result on the plain `E2E_*` job env per run.

   **Secret-rotation source (record per secret).** So each value can be rotated
   later, document where it is generated/provisioned, per environment: the
   Forgejo Actions secret store entry itself; the E2E tenant + account
   (`*_EMAIL` / `*_PASSWORD` / `*_TENANT_ID`, from steps 1-2 above); the OIDC
   client registration (`*_OIDC_CLIENT_ID` / `*_OIDC_REDIRECT_URI`, step 3); and
   the TOTP enrollment (`*_TOTP_SECRET`, step 2). Keep this here or in the team's
   secret-management runbook so a rotation has a documented source for every
   value.

## Test-data policy

Every record a test creates carries an embedded tag `e2e-<epochMs>-<runId>-<n>`
in its name and lives only in the E2E tenant. `global.teardown.ts`:

- deletes the top-level named records created by **this** run - across
  tickets, projects, contracts, assets/asset-types, appointments, on-call
  schedules, SLA policies/business-hours/holiday-calendars, KB
  articles/categories, work types, rounding rules, task statuses, rate cards,
  tax rates, contacts, and companies - sweeping children before parents (the
  company is referenced by almost everything, so it goes last). The sweep list
  lives in `global.teardown.ts`; add a row when a new named resource is
  covered. Gated-module sweeps no-op when the module is disabled (their list
  route 404s); and
- sweeps any `e2e-`-tagged residue older than **24h** left by earlier failed runs.

Records without a run-suffixed name (time entries, tasks, contract items,
payments, invoices, time-off, configuration items) are not name-matchable;
specs delete those inline in reverse-dependency order, and the name sweep is
only a backstop for the
top-level residue a failed run leaves behind. Sweeps for gated-module resources
no-op when the module is disabled (their list route 404s).

On failure, this run's residue is intentionally left for debugging and the next
run's sweep removes it once it ages past 24h. Teardown is best-effort and never
throws, so it cannot mask a test result.

**Demo seeding (PMS-157):** the server seeds a demo company + contacts + tickets into a tenant on its first authenticated visit. Those rows are NOT `e2e-`-tagged, so the teardown sweep will not remove them, and they would otherwise appear in list assertions against the shared E2E tenant. The staging/E2E deployment must set `MOKOSH_DEMO_SEED=false` to disable first-visit seeding. (The server also skips seeding any tenant that already has companies, so an E2E tenant with residual data is protected even if the flag is left on, but set it explicitly to be safe.)

Tickets are hard-deletable via `DELETE /api/v1/tickets/{id}`
(`src/modules/tickets/routes.rs`, added in PMS-149); deleting a ticket cascades
its notes/status-history. They carry run-tagged titles and are swept before
their parent companies.

## Email

Out of scope this phase. No signup-token or mailbox-dependent flow is tested;
auth uses the pre-seeded account.

## Run locally

```
cp e2e/.env.example e2e/.env   # then fill in the secrets
just test-e2e                  # from the repo root
# or, from e2e/:
npm ci
npx playwright install --with-deps chromium
npx playwright test
npx playwright show-report     # after a run
```

`just test-e2e --headed` (or any `playwright test` flag) passes through.

## CI

`.forgejo/workflows/e2e.yml` runs on three triggers, all serialised through a
single concurrency group (the suite shares one E2E account and the per-email
login rate limit is 5/min, so parallel runs would collide):

| Trigger | Environment | Purpose | Pre-flight gate | Notes |
| --- | --- | --- | --- | --- |
| `push` to `main` | staging | Post-merge validation: assert the deployed commit is actually serving on staging | `scripts/wait-for-deploy.mjs` polls `GET /api/v1/version` until staging reports the pushed commit's git hash (poll 15s, 10-min timeout). Walks back to the last build-relevant commit when the merged commit is doc/CI-only | Originally PMS-140 |
| `pull_request` targeting `main` (incl. `release/*` PRs) | staging | Merge gate: every PR must pass the suite against staging before merge | `scripts/health-check.mjs` GETs `/api/v1/health` (one-shot, 30s timeout). A PR's SHA never deploys to staging so a version-SHA gate would always time out; this checks staging is up and the suite has something to talk to | PMS-141. Add `e2e` to required status checks on main branch protection to make the gate enforceable |
| `workflow_dispatch` | `environment` input (`staging` default / `production`) | Manual ad-hoc runs | `staging`: deploy-sync gate (`wait-for-deploy.mjs`), like `push`. `production`: reachability check (`health-check.mjs`) - the dispatched SHA is unlikely to be what prod serves, so the SHA-polling gate would time out | Production runs ONLY here (PMS-271). The write-heavy suite is never run against prod automatically; a human dispatches and selects it |

**Environment secrets (PMS-271).** CI holds staging and production config side
by side as Forgejo Actions secrets. The job `env:` block selects per var and
exposes the result on the plain `E2E_*` names via a Forgejo expression
(`${{ inputs.environment == 'production' && secrets.<PRODUCTION> || secrets.<STAGING> }}`),
except the shared client id which is a single `secrets.MOKOSH_OIDC_CLIENT_ID`
with no switch. Secret names match the deployment's own variable names where one
exists (`MOKOSH_OIDC_CLIENT_ID`, `MOKOSH_APPS_REDIRECT_URIS_*`, `OIDC_ISSUER_*`);
test-only vars use `E2E_STAGING_*` / `E2E_PRODUCTION_*`. On `push` /
`pull_request` the `inputs` context is empty, so each expression resolves to its
staging secret; a manual dispatch lets the operator pick. See the
[Required configuration](#required-configuration) table for the full mapping and
[One-time provisioning](#one-time-staging-provisioning-manual) step 5 for
rotation sources.

Each run installs Node + Chromium, runs the suite against the selected
deployment, and uploads `playwright-report/` + `test-results/` as artifacts on
failure.
