import { defineConfig, devices } from '@playwright/test';
// `lib/env` self-loads e2e/.env (dotenv) on first import so consumers see
// the populated process.env, and exposes the SPA-vs-API split needed below.
import { env } from './lib/env';

export default defineConfig({
  testDir: './tests',
  // Teardown deletes this run's records and sweeps stale residue.
  globalTeardown: './global.teardown.ts',
  // Serial: tests share one E2E tenant + bearer token; parallel mutation
  // invites cross-test interference during this stabilisation phase.
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: [['list'], ['html', { open: 'never' }]],
  // No top-level baseURL: SPA vs API have different hosts on the canonical
  // deployment (msp.a8n.systems vs api.msp.a8n.systems). Each project picks
  // the right one in its own `use:` block.
  use: {
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    // 0. Aggregate-all-missing env-var check. Runs before everything else so
    //    a misconfigured CI names every gap in one round trip instead of
    //    dying at the first missing key and forcing a fix-rerun per var.
    {
      name: 'preflight',
      testMatch: /preflight\.setup\.ts$/,
    },
    // 1. Drive the SPA login in a real browser, sniff the first /api/v1
    //    request, and persist its `Authorization: Bearer` header to
    //    e2e/.auth/token.txt for the api project to pick up. Why intercept
    //    rather than POSTing /api/v1/auth/login directly: the OP advertises
    //    only authorization_code + refresh_token (no client_credentials, no
    //    password grant), and SPA accounts created via the bunyip hub do
    //    not exist in mokosh's local `users` table so legacy login 401s.
    //    Reusing the real SPA flow is the only path that works without
    //    registering a new OIDC client or maintaining a parallel signup
    //    pipeline. baseURL targets the SPA host.
    {
      name: 'setup',
      testMatch: /global\.setup\.ts$/,
      dependencies: ['preflight'],
      // Run setup in FIREFOX, not chromium, and PMS-1408 keeps it there on
      // purpose rather than while waiting for something. The bearer this project
      // persists is read off the OIDC `/oauth2/token` response and is
      // browser-agnostic, so capturing it in a second engine buys no coverage;
      // what it would buy is the token every `api` spec depends on sitting behind
      // the engine that is still being re-proven. Chromium coverage of the SPA
      // login comes from the `chromium` project below, which is where a
      // chromium-only regression should surface: in one spec, not in twenty that
      // never touched a browser.
      use: { ...devices['Desktop Firefox'], baseURL: env.baseURL },
    },
    // 2. Browser-driven coverage across all three engines (PMS-423). Each
    //    project runs the SPA-driven specs - auth/session (`auth.spec.ts`) and
    //    form-validation (`form-validation.spec.ts`, PMS-518 AC7) - against a
    //    different browser the opensuse-dev runner pre-bakes (chromium /
    //    firefox / webkit). These specs do their own SPA login, so they never
    //    invalidate the API token and do not depend on `setup`; they depend on
    //    `preflight` only so a misconfigured CI fails clean. They drive the SPA
    //    form and assert on the DOM / URL transitions, not request-context API
    //    state, and use the SPA host the human-facing app is served on.
    //
    //    PMS-1408 corrected what this said about which specs run:
    //    `form-validation.spec.ts` runs in all three projects, and only
    //    `auth.spec.ts`'s logout test is `test.fixme` (PMS-148). The per-email
    //    login rate limit (5/min, `src/modules/auth/routes.rs`) is therefore a
    //    live cross-browser concern rather than a future one, which is why
    //    form-validation is ONE test with ONE login rather than a login per
    //    case: three engines plus `setup` already spend four of the five.
    {
      name: 'chromium',
      testMatch: /(auth|form-validation)\.spec\.ts$/,
      dependencies: ['preflight'],
      // --disable-dev-shm-usage routes chromium's shared memory to /tmp instead
      // of /dev/shm. PMS-1408: defence in depth, not the fix. The runners now
      // pass --shm-size=2g (DEV-396) and the crash this flag was credited with
      // turned out to be a missing font package (DEV-756), so nothing here
      // depends on it - but 64 MB is still the container default, and a
      // workstation or a runner that has not taken the config keeps working with
      // it. It costs nothing, so it stays.
      use: {
        ...devices['Desktop Chrome'],
        baseURL: env.baseURL,
        launchOptions: { args: ['--disable-dev-shm-usage'] },
      },
    },
    {
      name: 'firefox',
      testMatch: /(auth|form-validation)\.spec\.ts$/,
      dependencies: ['preflight'],
      use: { ...devices['Desktop Firefox'], baseURL: env.baseURL },
    },
    {
      name: 'webkit',
      testMatch: /(auth|form-validation)\.spec\.ts$/,
      dependencies: ['preflight'],
      use: { ...devices['Desktop Safari'], baseURL: env.baseURL },
    },
    // 3. Request-context API coverage. The lib/fixtures.ts custom `test`
    //    fixture loads the bearer token written by `setup` and attaches it
    //    via extraHTTPHeaders on every request. Uses the API host, not the
    //    SPA host. Transitively depends on `preflight` via `setup`.
    {
      name: 'api',
      testMatch:
        /(oidc|tickets|contacts|time-tracking|projects|billing|contracts|calendar|sla|assets|knowledge-base|notifications|settings|audit|reports|rmm|dispatch)\.spec\.ts$/,
      dependencies: ['setup'],
      use: { baseURL: env.apiBaseURL },
    },
    // 4. External-service exclusion guard (PMS-608). Carries the `@external`
    //    tag, so the production run's `--grep-invert @external` (see
    //    .forgejo/workflows/e2e.yml) drops it on prod and keeps it on
    //    staging/PR/push. It reads only E2E_ENVIRONMENT (no auth/tenant), so it
    //    does not depend on `setup`; it depends on `preflight` only so a
    //    misconfigured CI fails clean. See tests/external-guard.spec.ts.
    {
      name: 'guard',
      testMatch: /external-guard\.spec\.ts$/,
      dependencies: ['preflight'],
    },
  ],
});
