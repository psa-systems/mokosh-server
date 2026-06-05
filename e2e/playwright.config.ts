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
  // deployment (msp.a8n.systems vs msp-api.a8n.systems). Each project picks
  // the right one in its own `use:` block.
  use: {
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  projects: [
    // 1. Direct `POST /api/v1/auth/login` against the deployment; persists the
    //    returned access_token to e2e/.auth/token.txt for the api project to
    //    pick up. No browser - the SPA holds tokens in WASM memory so
    //    storageState replay cannot authenticate the API context
    //    (see e2e/lib/auth-state.ts).
    {
      name: 'setup',
      testMatch: /global\.setup\.ts$/,
      use: { baseURL: env.apiBaseURL },
    },
    // 2. Browser-driven auth/session coverage. Independent of `setup` so its
    //    logout assertion never invalidates the API token. Drives the SPA
    //    form and asserts on URL transitions, not request-context API state.
    //    Uses the SPA host the human-facing app is served on.
    {
      name: 'auth-ui',
      testMatch: /auth\.spec\.ts$/,
      use: { ...devices['Desktop Chrome'], baseURL: env.baseURL },
    },
    // 3. Request-context API coverage. The lib/fixtures.ts custom `test`
    //    fixture loads the bearer token written by `setup` and attaches it
    //    via extraHTTPHeaders on every request. Uses the API host, not the
    //    SPA host.
    {
      name: 'api',
      testMatch: /(oidc|tickets|contacts)\.spec\.ts$/,
      dependencies: ['setup'],
      use: { baseURL: env.apiBaseURL },
    },
  ],
});
