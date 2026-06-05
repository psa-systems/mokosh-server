# Mokosh E2E suite (Playwright)

End-to-end tests that run against a **deployed** mokosh-server instance (staging
by default), not a CI-built artifact. Phase 1 (PMS-140): stand up the harness,
shake out flakiness. The CI run is **post-merge and informational**, not a merge
gate (that is PMS-141).

## What it covers

| Area | File | How |
| --- | --- | --- |
| Auth login / session / logout | `tests/auth.spec.ts` | real browser drives the SPA login form, logout invalidates the session |
| OIDC token flow | `tests/oidc.spec.ts` | request context: `/oauth2/authorize` -> code -> `/oauth2/token` -> `/oauth2/userinfo` -> refresh (PKCE) |
| Tickets CRUD | `tests/tickets.spec.ts` | request context against `/api/v1/tickets` |
| Contacts + tenants + cross-tenant canary | `tests/contacts.spec.ts` | request context, tenant-scoped smoke + leak check |

**Hybrid harness:** `tests/global.setup.ts` logs in through the SPA in a real
browser and saves the session to `.auth/state.json` (`storageState`). The `api`
Playwright project reuses that session for request-context API calls. The
`auth-ui` project logs in fresh on its own so its logout assertion never
invalidates the shared session.

## Required configuration

Set via `e2e/.env` locally (copy from `.env.example`) or Forgejo Actions secrets
in CI. Required unless noted:

| Var | Purpose |
| --- | --- |
| `E2E_BASE_URL` | deployment under test (default `https://msp.a8n.systems`) |
| `E2E_EMAIL` | dedicated E2E account login |
| `E2E_PASSWORD` | E2E account password |
| `E2E_TENANT_ID` | UUID of the dedicated E2E tenant |
| `E2E_OIDC_CLIENT_ID` | public OIDC client id for the token-flow test |
| `E2E_OIDC_REDIRECT_URI` | redirect_uri registered for that client (default `E2E_BASE_URL`); only the `code` is captured, the URL is never loaded |
| `E2E_FOREIGN_COMPANY_ID` | *optional* - a company id in **another** tenant; enables the cross-tenant company canary, otherwise that test is skipped |

## One-time staging provisioning (manual)

Done once by a human before the suite can pass against a deployment:

1. **E2E tenant** - create a dedicated tenant for E2E. Record its UUID as
   `E2E_TENANT_ID`. All test records live here and are swept after each run.
2. **E2E account** - create a user in that tenant with permission to manage
   tickets, companies, and contacts. Record `E2E_EMAIL` / `E2E_PASSWORD`.
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

`.forgejo/workflows/e2e.yml` runs on push to `main`. It installs Node + the
Chromium browser, waits for `GET /api/v1/version` to report the pushed commit's
git hash (poll 15s, 10-min timeout - the **deploy-sync gate**), runs the suite,
and uploads `playwright-report/` + `test-results/` as artifacts on failure.
