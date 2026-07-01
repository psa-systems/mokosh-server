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
      // --disable-dev-shm-usage: CI runs headless chromium in a container
      // whose /dev/shm defaults to 64 MB. The WASM SPA + post-login data load
      // exhausts it and the tab crashes with "Target page, context or browser
      // has been closed" (chromium only; firefox/webkit are unaffected). This
      // flag routes chromium's shared memory to /tmp instead - the standard
      // fix for that crash in CI (PMS-592).
      use: {
        ...devices['Desktop Chrome'],
        baseURL: env.baseURL,
        launchOptions: { args: ['--disable-dev-shm-usage'] },
      },
    },
    // 2. Browser-driven coverage across all three engines (PMS-423). Each
    //    project runs the SPA-driven specs - auth/session (`auth.spec.ts`) and
    //    form-validation (`form-validation.spec.ts`, PMS-518 AC7) - against a
    //    different browser the opensuse-dev runner pre-bakes (chromium /
    //    firefox / webkit). These specs do their own SPA login, so they never
    //    invalidate the API token and do not depend on `setup`; they depend on
    //    `preflight` only so a misconfigured CI fails clean. They drive the SPA
    //    form and assert on the DOM / URL transitions, not request-context API
    //    state, and use the SPA host the human-facing app is served on. Both
    //    specs are currently `test.fixme` (see tests/auth.spec.ts and
    //    tests/form-validation.spec.ts for the un-fixme conditions), so the
    //    per-email login rate limit (5/min) is not yet a cross-browser concern.
    {
      name: 'chromium',
      testMatch: /(auth|form-validation)\.spec\.ts$/,
      dependencies: ['preflight'],
      // --disable-dev-shm-usage: CI runs headless chromium in a container
      // whose /dev/shm defaults to 64 MB. The WASM SPA + post-login data load
      // exhausts it and the tab crashes with "Target page, context or browser
      // has been closed" (chromium only; firefox/webkit are unaffected). This
      // flag routes chromium's shared memory to /tmp instead - the standard
      // fix for that crash in CI (PMS-592).
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
  ],
});
