# mokosh-server E2E suite: how it works, running it, and troubleshooting

A practical engineering reference for the mokosh-server end-to-end (E2E) test suite: what it is, how it is wired, how to run it, and the failure modes you will actually hit. Source of truth in the repo: `e2e/README.md` (suite overview, env table, provisioning), `e2e/playwright.config.ts` (project model), and `.forgejo/workflows/e2e.yml` (CI triggers, gates, environment selection). This doc is the synthesis; when the two disagree, the code wins.

## What it is

A Playwright suite that runs against a **deployed** mokosh instance (staging by default), not a CI-built artifact and never a locally-spun stack. It drives the real mokosh-apps SPA login (through the bunyip SSO hub) and the mokosh-server `/api/v1` JSON API, plus the bunyip OIDC OP token flow. What it exercises is exactly what a user hits in a browser.

Key consequence: the suite asserts against whatever the target environment is currently serving. On a post-merge run it first waits for the deployment to actually serve the merged commit before testing (the deploy-sync gate). Staging's redeploy is, in turn, gated on the E2E suite passing, which creates a deadlock trap for new-route tests (see Troubleshooting).

## Architecture: the project model

The suite shares ONE E2E account and ONE tenant, and login is rate-limited to **5 requests per minute per email** (`src/modules/auth/routes.rs`, the layered per-IP + per-email `AuthRateLimiter` from `src/modules/auth/rate_limit.rs`). So the Playwright projects are serialised (`workers: 1`, `fullyParallel: false`) and logins are spent sparingly: the `setup` project logs in exactly once and every API spec reuses the captured credential.

| Project | Tests | Auth | Notes |
| --- | --- | --- | --- |
| `preflight` | `tests/preflight.setup.ts` | none | Aggregates EVERY missing required env var into one fail-loud error before anything runs (`lib/env.ts::preflightRequiredEnv`). A misconfigured CI names all gaps in one round trip instead of dying one var at a time. |
| `setup` | `tests/global.setup.ts` | logs in ONCE | Drives the SPA login in a real browser (TOTP-aware), captures the bunyip-issued bearer to `.auth/token.txt`, the OP session cookies to `.auth/op-state.json`, and the cross-tenant canary id to `.auth/foreign-company.txt`. Depends on `preflight`. |
| `auth-ui` | `tests/auth.spec.ts` | ANONYMOUS | Drives the SPA login form in a fresh browser and asserts on URL transitions (login leaves `/login`, logout returns to it). DOM-only, no API probe. Depends on `preflight`, NOT `setup` (its own login + logout must not invalidate the shared API token). Currently `test.fixme` (PMS-148). |
| `form-ui` | `tests/form-validation.spec.ts` | ANONYMOUS | Browser-driven form-validation coverage (PMS-518 AC7): drives the SPA create forms and asserts every missing required field flags at once (per-field inline + banner) with no navigation. DOM-only (the FormGuard validation is client-side). Does its own `loginViaSpa`. Depends on `preflight`. Currently `test.fixme` (needs the FormGuard SPA deployed + PMS-148). |
| `api` | `tests/{tickets,contacts,oidc,time-tracking,projects,billing,contracts,calendar,sla,assets,knowledge-base,notifications,settings,audit,reports,rmm,dispatch}.spec.ts` | request context | No browser. Bearer header for PSA-API specs, replayed OP cookies for `oidc.spec.ts`. Depends on `setup`. |

When you add a spec file to the `api` project you MUST widen the `testMatch` regex in `playwright.config.ts`, or it silently never runs.

## The two auth paths

mokosh's E2E auth is split because the PSA API and the bunyip OP are authenticated differently, and the SPA's own token is unreachable from a test:

- **Bearer path (`lib/fixtures.ts` default `test`).** Every PSA-API call carries the bunyip-issued `at+jwt` the setup project captured. mokosh verifies it on the bunyip Resource-Server path (`ensure_user_from_bunyip`, `src/modules/auth/middleware.rs`). Used by `tickets`, `contacts`, and all the module specs.
- **OP-cookie path (`lib/fixtures.ts` `oidcTest`).** Replays the OP session cookies via `request.newContext({ storageState })` and does NOT attach a bearer. `tests/oidc.spec.ts` uses this so `/oauth2/authorize` sees a server-validated OP session (bunyip PR #67) and 302s to the registered redirect_uri with a `code`, instead of bouncing to the hub login. A bearer here would carry the wrong audience and confuse the OP, so the fixture deliberately omits it.

Why not just `POST /api/v1/auth/login` and skip the browser entirely? Three independent reasons (`tests/global.setup.ts`):

- mokosh hosts no OP and no token endpoint (PMS-295 removed the `crates/mokosh-auth*` subsystem), so there is nothing in this repo to mint a token from. bunyip is the OP, and the suite holds no client credentials for a service-to-service grant against it.
- Legacy `POST /api/v1/auth/login` works only against rows in mokosh's local `users` table; SPA accounts that signed up through the bunyip hub live elsewhere and 401 there.
- The SPA keeps its bearer in WASM thread-local memory (`mokosh-clients/src/hooks/fetch.rs`), so `page.evaluate()` / `storageState` cannot read it.

Intercepting the real SPA auth flow is the only path that reuses production auth without registering a new client or maintaining a parallel signup pipeline.

## Token capture: why two capture paths

`global.setup.ts` captures the access token two ways, with the **OIDC token-endpoint response as PRIMARY**:

1. Read `access_token` straight out of the first successful `/oauth2/token` response body. This fires as part of OIDC itself, so it is observable even when the SPA's data-fetching layer is broken.
2. Backstop: sniff the first outbound request that carries an `Authorization: Bearer` header.

The reason path 1 exists: a bug in the SPA's post-login navigation (mokosh-apps #84) once put the SPA into an infinite-OIDC loop on staging. Tokens were exchanged at `/oauth2/token` but the SPA never reached a render that fired a Bearer-carrying API call. The header-only capture timed out, the E2E suite failed, the staging redeploy was gated on E2E, and the SPA fix could not deploy. Reading the response body breaks that cycle: capture survives a fully-broken SPA, the suite passes, the fix deploys.

On timeout the setup builds a rich diagnostic: the post-login URL trail, the SPA bundle hash (identifies WHICH mokosh-apps build staging served, so "fix landed but staging hasn't redeployed" is obvious), the `/oauth2/token` responses observed, and the Bearer-carrying requests. Read that block first when setup fails.

## Module gating

Most feature modules (`time_tracking`, `projects`, `billing`, `contracts`, `calendar`, `assets`, `knowledge_base`, `reports`, `rmm_integration`) are tenant-gated and default to DISABLED: `SettingsService::is_module_enabled` COALESCEs a missing `module_config` row to `FALSE`, so every route behind a `RequireModuleEnabled` extractor returns **404** until the module is turned on. Each spec for a gated module enables it up front via `PUT /api/v1/settings/modules/{module}` (admin-only, idempotent) through `lib/factories.ts::enableModule`. The enable persists on the E2E tenant; that is configuration, not swept residue. SLA, notifications, settings, and audit are NOT gated; their writes are simply admin-only.

## Configuration

Set via `e2e/.env` locally (copy from `e2e/.env.example`) or Forgejo Actions secrets in CI. The suite reads only the plain `E2E_*` names; CI holds staging and production side by side and selects per var, exposing the result on the plain names (PMS-271), so `env.ts` and the gate scripts stay environment-agnostic.

| Var | Required | Purpose |
| --- | --- | --- |
| `E2E_BASE_URL` | yes | SPA host the browser navigates to. No default. Staging `https://msp.a8n.systems`, prod `https://msp.psa.systems`. |
| `E2E_API_BASE_URL` | no | `/api/v1` host. Defaults to prepending `api.` to `E2E_BASE_URL` (`msp.a8n.systems` -> `api.msp.a8n.systems`). |
| `E2E_OP_BASE_URL` | recommended | OIDC OP host (`/oauth2/*`, `/.well-known/*`). On bunyip-as-OP deploys the OP runs on the apex `api.<tld>`, NOT the mokosh API host, so set it explicitly (e.g. `https://api.a8n.systems`). Defaults to `E2E_API_BASE_URL`. |
| `E2E_EMAIL` / `E2E_PASSWORD` | yes | The dedicated E2E account (2FA enabled, admin role). |
| `E2E_TENANT_ID` | yes | UUID of the dedicated E2E tenant. |
| `E2E_OIDC_CLIENT_ID` | yes | Public PKCE client id for the OP token-flow spec. |
| `E2E_OIDC_REDIRECT_URI` | yes | redirect_uri registered for that client. Must match EXACTLY or the OP returns `invalid_redirect_uri`. Only the `code` is captured; the URL is never loaded. |
| `E2E_TOTP_SECRET` | yes | base32 TOTP secret for the account; the second factor is computed at runtime. |
| `E2E_FOREIGN_COMPANY_ID` | no | A company id in ANOTHER tenant, to strengthen the cross-tenant leak canary. When unset, setup falls back to a random, well-formed UUID the E2E tenant cannot own (the canary still runs). |

In CI the three vars with a deployment equivalent use the deployment's own names (`MOKOSH_OIDC_CLIENT_ID` single shared; `MOKOSH_APPS_REDIRECT_URIS_STAGING`/`_PRODUCTION`; `OIDC_ISSUER_STAGING`/`_PRODUCTION`); test-only vars use `E2E_STAGING_*` / `E2E_PRODUCTION_*`. Automatic runs (push, PR) always resolve to staging; production is manual-dispatch only.

## One-time staging provisioning (manual)

Done once by a human before the suite can pass (full detail in `e2e/README.md`):

1. **E2E account** - a bunyip user, provisioned on staging by bunyip's `bunyip-e2e-bootstrap` (docker repo: `just e2e-bootstrap`, which creates `e2e-user@a8n.run`). Record `E2E_EMAIL` / `E2E_PASSWORD`, plus `E2E_TOTP_SECRET` if 2FA is enabled on the account.
2. **E2E tenant** - NOT pre-created. The account's first mokosh SSO login JIT-creates its `users` row in an auto-provisioned personal tenant and sets the role to **`admin`** automatically (`place_bunyip_user`, `src/modules/auth/middleware.rs`; MAPPS-330 floors every Mokosh user to admin of its own instance), so there is no manual elevation. Admin is REQUIRED (the suite enables gated modules and many writes are `RequireAdmin`/`RequireManager`/`RequireFinance`); the JIT default satisfies it. After first login, record that tenant's UUID as `E2E_TENANT_ID` (`SELECT tenant_id FROM users WHERE email = '<E2E_EMAIL>'` on the staging mokosh Postgres); re-capture it after any re-seed, since a new bunyip `sub` yields a new personal tenant.
3. **OIDC client** - reuse the staging SPA public PKCE client or register a dedicated one; record `E2E_OIDC_CLIENT_ID` + a registered `E2E_OIDC_REDIRECT_URI`.
4. **`MOKOSH_DEMO_SEED=false`** on the staging deployment. The server seeds a demo company + contacts + tickets into a tenant on its first authenticated visit (`src/modules/seed/service.rs`). Those rows are NOT `e2e-`-tagged, so teardown will not remove them and they pollute list assertions. (The server also skips seeding a tenant that already has companies, but set the flag explicitly.)
5. Store everything as Forgejo Actions secrets per the table in `e2e/README.md`, and record a rotation source per secret.

## Running locally

```
cp e2e/.env.example e2e/.env   # then fill in the secrets
just test-e2e                  # from the repo root
# or, from e2e/:
npm ci
npx playwright install --with-deps chromium
npx playwright test
npx playwright show-report     # after a run
```

Any `playwright test` flag passes through, e.g. `just test-e2e --headed`. Locally on a Debian/Ubuntu box `--with-deps` is fine; in CI it is not (see Troubleshooting).

## CI behaviour

Workflow: `.forgejo/workflows/e2e.yml`. Three triggers, all serialised through a single concurrency group (`e2e-staging`, `cancel-in-progress: false`) because of the 5/min/email login cap. Slow throughput is the accepted trade-off; throughput never beats correctness for an auth-rate-limited gate.

| Trigger | Environment | Purpose | Pre-flight gate |
| --- | --- | --- | --- |
| `push` to `main` | staging | Post-merge validation: assert the deployed commit is actually serving | `scripts/wait-for-deploy.mjs` polls `GET /api/v1/version` until staging reports the pushed commit's git hash (15s poll, 10-min timeout). On a doc/CI-only commit it walks back to the last build-relevant commit so it does not poll a SHA staging never serves. |
| `pull_request` to `main` (incl. `release/*`) | staging | Merge gate: every PR passes the suite against staging before merge | `scripts/health-check.mjs` GETs `/api/v1/health` once (30s timeout). A PR's SHA never deploys to staging, so a SHA gate would always time out; this just confirms staging is up. |
| `workflow_dispatch` | input (`staging` default / `production`) | Manual ad-hoc runs | `staging`: deploy-sync gate like `push`. `production`: reachability check (the dispatched SHA is unlikely to be what prod serves). Production runs ONLY here; the write-heavy suite is never run against prod automatically. |

On every staging trigger the suite first probes bunyip's `GET /e2e-bootstrapped` (`e2e/scripts/check-e2e-bootstrapped.mjs`, PMS-656): when it reports `{bootstrapped: false}` - the shared E2E account is not provisioned, e.g. after a staging data wipe - the suite is SKIPPED with a notice pointing at the re-seed recipe (`just e2e-bootstrap` in the docker repo) and the job stays green, instead of every login failing opaquely. Only an explicit `false` skips; a missing endpoint (production never enables it) or any probe error runs the suite normally.

To make `e2e` enforce, add it to the required status checks on the `main` branch protection (PMS-141 sets a 10-consecutive-green stability bar before flipping that switch).

The job runs on the dev runner label (`RUNS_ON_OPENSUSE_DEV_LATEST`), whose image pre-bakes bun, `node24` and the Playwright browsers; the base image carries none of that (PMS-719). On failure it uploads `playwright-report/` + `test-results/` as artifacts.

## Coverage status and quarantined specs

Runnable specs assert now; quarantined specs are `test.fixme` with their blocker named inline.

| Spec | Status | Blocker |
| --- | --- | --- |
| `tests/auth.spec.ts` (logout) | `test.fixme` | PMS-148: after the PMS-142 fix merged, post-merge CI exposed a separate failure where the auth-ui login deterministically stalls when run after `setup` finishes (submit click no-ops, URL stays on `/login`). Bunyip's BUNYIP-53 `/logout` fix IS deployed; this is a different problem. |
| `tests/oidc.spec.ts` (OP token flow) | `test.fixme` | PMS-435 / BUNYIP-146: the diagnostic run proved `bunyip_op_session` is captured, persisted on the right domain, and replayed, yet `/oauth2/authorize` still 302s to `/login` with no `state`. Root cause is bunyip's `COOKIE_DOMAIN` / `bunyip_op_session` scoping, not an e2e forwarding defect. Un-fixme when BUNYIP-146 ships. |
| `tests/form-validation.spec.ts` (PMS-518 / AC7) | `test.fixme` | Needs BOTH: (1) the target's mokosh-apps SPA to include the PMS-518 `FormGuard` migration (merged to mokosh-apps `main` AND staging redeployed - on an older SPA the assertions fail), and (2) the browser-login path green (shares `loginViaSpa`, blocked by the PMS-148 stall). Un-fixme once both hold. |

The PSA-API specs (tickets, contacts, and the 14 PMS-155 module specs) run and assert.

## Test-data policy

Every record a test creates carries an embedded tag `e2e-<epochMs>-<runId>-<n>` in its name and lives only in the E2E tenant. `global.teardown.ts` deletes this run's top-level named records (children before parents; the company goes last because almost everything references it) and sweeps any `e2e-`-tagged residue older than 24h left by earlier failed runs. Teardown is best-effort and never throws, so it cannot mask a test result.

Records without a run-suffixed name (time entries, tasks, contract items, payments, invoices, configuration items) are not name-matchable; specs delete those inline in reverse-dependency order. **Invoices have no `DELETE /api/v1/invoices/{id}` route**, so the billing spec smoke-reads the invoice list only; creating an invoice would be permanent residue.

## Issues you can run into (troubleshooting)

**Login rate limit (5/min/email).** The single most common source of spurious failures. The suite shares one account, so anything that adds logins (a new spec calling login, parallel projects, two CI runs overlapping) trips it. Mitigations are baked in: serial projects, single `setup` login reused via `.auth/token.txt`, and a non-cancelling serial CI concurrency group. If you add a spec, do NOT call `loginViaSpa` in the `api` project; read the stored token.

**Setup times out: "no access_token captured".** Read the diagnostic block. If `/oauth2/token` responses show successful exchanges but no Bearer-carrying request followed, the SPA looped post-login (mokosh-apps #84 class) - the primary response-body capture should still have succeeded, so a true timeout here means OIDC never completed. Compare the printed `spaBundles` hash against the mokosh-apps build for the commit on main; a mismatch means staging has not redeployed yet, not a regression.

**Deploy-gate deadlock on a new route.** E2E runs against deployed staging, and staging's redeploy is gated on E2E passing. A test that hard-asserts a BRAND-NEW endpoint in the SAME PR that introduces it deadlocks: staging still runs the old binary (route 405s), the test fails, and the deploy that would add the route waits on that failing test. Bit us on PMS-149 (`DELETE /tickets/{id}`). Fix: make the new assertion deploy-tolerant (accept 405 = "route not live yet", gate deeper assertions behind a 200), or land the route first and the asserting test in a follow-up.

**Gated-module routes 404.** The module is disabled for the E2E tenant. Call `lib/factories.ts::enableModule(request, '<slug>')` up front; the slug is the gate name (`time_tracking`, `projects`, `billing`, `contracts`, `rmm_integration`, ...). A persistent 404 after enabling usually means a typo'd slug.

**Everything admin-gated returns 403.** No longer expected: first bunyip SSO login JIT-creates the mokosh `users` row as `admin` (`place_bunyip_user`, MAPPS-330 floors every Mokosh user to admin of its own instance), so a freshly provisioned E2E account is admin with no manual step. If it happens anyway, the row's role was changed after creation - inspect it (`SELECT role FROM users WHERE email = '<E2E_EMAIL>'`; the role is resolved per request from the local `users` row, not the bunyip token) instead of re-running an elevation that the JIT path already performs.

**`invalid_redirect_uri` at authorize/token.** `E2E_OIDC_REDIRECT_URI` must match a registered redirect_uri for `E2E_OIDC_CLIENT_ID` EXACTLY. The token-flow spec only captures the `code`; it never loads the URL, so a mismatch surfaces as an OP error, not a navigation failure.

**OIDC authorize bounces to `/login` ("state mismatch").** `/oauth2/authorize` gates code minting on a server-validated `bunyip_op_session` cookie. A `COOKIE_DOMAIN` change on the OP can strand the session cookie on a host outside the e2e cookie filter, so authorize 302s to `/login` with no `state`. This is the BUNYIP-146 / PMS-435 cause behind the quarantined `oidc.spec.ts`; check `COOKIE_DOMAIN` on the target deployment.

**Demo-seed rows pollute list assertions.** Set `MOKOSH_DEMO_SEED=false` on the staging deployment. The first-visit seeder writes non-`e2e-`-tagged company/contacts/tickets that teardown will not sweep.

**`DELETE /api/v1/contacts/companies/{id}` returns 500 in teardown.** An unguarded FK violation (`23503`) surfaces as a generic 500 instead of 400 (PMS-170). Teardown is best-effort and swallows it, so it does not fail the run, but it leaves residue the 24h sweep cleans up later.

**npm / Playwright on the OpenSUSE CI runner.** The image ships `nodejs24` only: the bare `node`/`npm`/`npx` are libalternatives wrappers that dispatch to an absent `*-default` target, and versioned `npm24`/`npx24` are not installed. Run JS package management through `corepack npm` / `corepack npx`, and node scripts through the concrete `node24` binary (PMS-429 / PMS-462). Do NOT use `playwright install --with-deps` in CI: `--with-deps` shells out to `apt-get`, which the OpenSUSE runner does not have; the image already carries the X/GTK/NSS libs Chromium needs.

**`wait-for-deploy.mjs` finds no build-relevant commit.** The Forgejo `actions/checkout` has been observed to honour `fetch-depth: 0` inconsistently and to apply object filters that strip the trees `git log -- <path>` needs, so the build-SHA walk silently returns nothing. The script self-heals (unshallow, then `git fetch --refetch`); if all attempts fail it skips the gate with a loud warning rather than poll a SHA staging never serves. Keep `BUILD_TRIGGER_PATHS` in lock-step with `on.push.paths` in `build-oci-image.yml` or the gate polls for the wrong SHA.

## References

- `e2e/README.md` - suite overview, full env table, one-time provisioning + rotation sources, test-data policy
- `e2e/playwright.config.ts` - the project model (preflight / setup / auth-ui / api)
- `e2e/tests/global.setup.ts` - login + token/cookie capture and the timeout diagnostic
- `e2e/lib/{env,fixtures,auth-state,login,factories,api}.ts` - env loading, auth fixtures, captured-artifact readers, login helper, factories, route map
- `e2e/scripts/{wait-for-deploy,health-check}.mjs` - the CI pre-flight gates
- `.forgejo/workflows/e2e.yml` - CI triggers, environment selection, concurrency, gates
