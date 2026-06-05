import { defineConfig, devices } from '@playwright/test';
import { config as loadEnv } from 'dotenv';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

// Local runs read e2e/.env; CI injects the same vars from Forgejo secrets, so a
// missing file is fine (override:false keeps real env winning).
loadEnv({ path: resolve(here, '.env'), override: false });

const baseURL = process.env.E2E_BASE_URL ?? 'https://msp.a8n.systems';

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
  use: {
    baseURL,
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
    },
    // 2. Browser-driven auth/session coverage. Independent of `setup` so its
    //    logout assertion never invalidates the API token. Drives the SPA
    //    form and asserts on URL transitions, not request-context API state.
    {
      name: 'auth-ui',
      testMatch: /auth\.spec\.ts$/,
      use: { ...devices['Desktop Chrome'] },
    },
    // 3. Request-context API coverage. The lib/fixtures.ts custom `test`
    //    fixture loads the bearer token written by `setup` and attaches it
    //    via extraHTTPHeaders on every request.
    {
      name: 'api',
      testMatch: /(oidc|tickets|contacts)\.spec\.ts$/,
      dependencies: ['setup'],
    },
  ],
});
