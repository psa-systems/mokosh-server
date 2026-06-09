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
      use: { ...devices['Desktop Chrome'], baseURL: env.baseURL },
    },
    // 2. Browser-driven auth/session coverage. Does not depend on `setup`
    //    (it does its own SPA login so its logout assertion never
    //    invalidates the API token) but does depend on `preflight` so it
    //    fails clean on a misconfigured CI. Drives the SPA form and asserts
    //    on URL transitions, not request-context API state. Uses the SPA
    //    host the human-facing app is served on.
    {
      name: 'auth-ui',
      testMatch: /auth\.spec\.ts$/,
      dependencies: ['preflight'],
      use: { ...devices['Desktop Chrome'], baseURL: env.baseURL },
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
