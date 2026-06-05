# Mokosh E2E suite (Playwright)

End-to-end tests that run against a **deployed** mokosh-server instance (staging
by default), not a CI-built artifact. Phase 1 (PMS-140): stand up the harness,
shake out flakiness. The CI run is **post-merge and informational**, not a merge
gate (that is PMS-141).

## What it covers

| Area | File | How |
| --- | --- | --- |
| Auth login / session / logout | `tests/auth.spec.ts` | real browser drives the SPA login form (TOTP-aware), opens the avatar menu (click-retries through Dioxus WASM hydration), clicks Logout, asserts URL returns to the hub's `/login` |
| OIDC token flow | `tests/oidc.spec.ts` | request context: `/oauth2/authorize` -> code -> `/oauth2/token` -> `/oauth2/userinfo` -> refresh (PKCE) (**quarantined - `test.fixme`**; bunyip's `/oauth2/authorize` needs an OP session cookie the request context does not carry, so it 302s to the hub login instead of the registered redirect. Mokosh-server's RS path is exercised indirectly by every other api test) |
| Tickets CRUD | `tests/tickets.spec.ts` | request context against `/api/v1/tickets` |
| Contacts + tenants + cross-tenant canary | `tests/contacts.spec.ts` | request context, tenant-scoped smoke + leak check |

**Harness shape.** Two independent auth paths because the mokosh-clients SPA
keeps its bearer token in WASM memory (`mokosh-clients/src/hooks/fetch.rs`),
which Playwright's `storageState` cannot replay; and direct
`POST /api/v1/auth/login` does not work either (the OP advertises only
`authorization_code` + `refresh_token`, and SPA-signed-up accounts do not
exist in mokosh's local `users` table):

- **`setup` project** (`tests/global.setup.ts`) drives the SPA login in a
  real browser (TOTP-aware), then listens for the first outbound request
  carrying an `Authorization: Bearer` header (any host - the SPA's first
  authenticated call lands on the bunyip hub's `/v1/auth/memberships`, and
  the same bearer authenticates mokosh's RS-verified `/api/v1/*`). The
  captured token is written to `e2e/.auth/token.txt`. The `api` project
  (`oidc`, `tickets`, `contacts`) uses a custom `test` fixture
  (`lib/fixtures.ts`) that injects the token as `Authorization: Bearer ...`
  on every request. Teardown reads the same file.
- **`auth-ui` project** (`tests/auth.spec.ts`) drives the SPA login form in
  a real browser and asserts on URL transitions (login leaves `/login`,
  logout returns to it). DOM-only, no API probe - the SPA's in-memory token
  cannot be exfiltrated for an external request context to use. Captures a
  URL trail + request log via `lib/page-diagnostics.ts` and folds them into
  the thrown error on failure.

## Required configuration

Set via `e2e/.env` locally (copy from `.env.example`) or Forgejo Actions secrets
in CI. Required unless noted:

| Var | Purpose |
| --- | --- |
| `E2E_BASE_URL` | SPA host the auth-ui project navigates to (default `https://msp.a8n.systems`) |
| `E2E_API_BASE_URL` | *optional* - API host for `/api/v1`. Defaults to prepending `api.` to `E2E_BASE_URL` (e.g. `msp.a8n.systems` -> `api.msp.a8n.systems`). Set when the deployment uses a different naming scheme |
| `E2E_OP_BASE_URL` | *optional* - OIDC OP host for `/oauth2/*` + `/.well-known/openid-configuration`. Defaults to `E2E_API_BASE_URL`. On bunyip-as-OP deploys the OP runs on the apex `api.<tld>`, NOT the mokosh API host, so set this explicitly (e.g. `https://api.a8n.systems`) |
| `E2E_EMAIL` | dedicated E2E account login |
| `E2E_PASSWORD` | E2E account password |
| `E2E_TENANT_ID` | UUID of the dedicated E2E tenant |
| `E2E_OIDC_CLIENT_ID` | public OIDC client id for the token-flow test |
| `E2E_OIDC_REDIRECT_URI` | redirect_uri registered for that client (no default; must match exactly or the OP returns `invalid_redirect_uri`). Only the `code` is captured, the URL is never loaded |
| `E2E_TOTP_SECRET` | base32 TOTP secret for the E2E account. Setup generates the second-factor code at runtime; same string you pasted into your authenticator when enrolling 2FA on the account |
| `E2E_FOREIGN_COMPANY_ID` | *optional* - a company id in **another** tenant; enables the cross-tenant company canary, otherwise that test is skipped |

## One-time staging provisioning (manual)

Done once by a human before the suite can pass against a deployment:

1. **E2E tenant** - create a dedicated tenant for E2E. Record its UUID as
   `E2E_TENANT_ID`. All test records live here and are swept after each run.
2. **E2E account** - create a user in that tenant with permission to manage
   tickets, companies, and contacts. Record `E2E_EMAIL` / `E2E_PASSWORD`.
   Enable 2FA on the account and save the base32 secret (the string under
   the QR code at enrollment) as `E2E_TOTP_SECRET` - the setup test
   computes the second factor at runtime.
3. **OIDC client** - reuse the staging SPA public client (PKCE) or register a
   dedicated E2E client. Record `E2E_OIDC_CLIENT_ID` and a registered
   `E2E_OIDC_REDIRECT_URI`. If `/oauth2/authorize` redirects the E2E session to
   a login screen instead of returning a `code`, register a dedicated E2E client
   whose redirect_uri allows capture-only.
4. *(optional)* **Foreign company** - note a company id from a different tenant
   as `E2E_FOREIGN_COMPANY_ID` to enable the cross-tenant leak canary.
5. Store all of the above as Forgejo Actions secrets for `.forgejo/workflows/e2e.yml`.

## Test-data policy

Every record a test creates carries an embedded tag `e2e-<epochMs>-<runId>-<n>`
in its name and lives only in the E2E tenant. `global.teardown.ts`:

- deletes companies and contacts created by **this** run, and
- sweeps any `e2e-`-tagged residue older than **24h** left by earlier failed runs.

On failure, this run's residue is intentionally left for debugging and the next
run's sweep removes it once it ages past 24h. Teardown is best-effort and never
throws, so it cannot mask a test result.

**Tickets caveat:** the tickets module exposes no DELETE route
(`src/modules/tickets/routes.rs`), so test-created tickets are not hard-deleted.
They sit in the E2E tenant with run-tagged titles; their parent companies are
deleted by teardown.

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

| Trigger | Purpose | Pre-flight gate | Notes |
| --- | --- | --- | --- |
| `push` to `main` | Post-merge validation: assert the deployed commit is actually serving on staging | `scripts/wait-for-deploy.mjs` polls `GET /api/v1/version` until staging reports the pushed commit's git hash (poll 15s, 10-min timeout). Walks back to the last build-relevant commit when the merged commit is doc/CI-only | Originally PMS-140 |
| `pull_request` targeting `main` (incl. `release/*` PRs) | Merge gate: every PR must pass the suite against staging before merge | `scripts/health-check.mjs` GETs `/api/v1/health` (one-shot, 30s timeout). A PR's SHA never deploys to staging so a version-SHA gate would always time out; this checks staging is up and the suite has something to talk to | PMS-141. Add `e2e` to required status checks on main branch protection to make the gate enforceable |
| `workflow_dispatch` | Manual ad-hoc runs | Treated like `push` (runs the deploy-sync gate) | Use to force a re-run without pushing |

Each run installs Node + Chromium, runs the suite against the configured
staging deployment, and uploads `playwright-report/` + `test-results/` as
artifacts on failure.
