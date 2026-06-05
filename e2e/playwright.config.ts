import { defineConfig, devices } from '@playwright/test';
import { config as loadEnv } from 'dotenv';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

// Local runs read e2e/.env; CI injects the same vars from Forgejo secrets, so a
// missing file is fine (override:false keeps real env winning).
loadEnv({ path: resolve(here, '.env'), override: false });

// storageState produced by the browser SPA login (tests/global.setup.ts) and
// consumed by the request-context API projects.
export const STORAGE_STATE = resolve(here, '.auth', 'state.json');

const baseURL = process.env.E2E_BASE_URL ?? 'https://msp.a8n.systems';

export default defineConfig({
  testDir: './tests',
  // Teardown deletes this run's records and sweeps stale residue.
  globalTeardown: './global.teardown.ts',
  // Serial: tests share one E2E tenant + session; parallel mutation invites
  // cross-test interference during this stabilisation phase.
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
    // 1. Browser logs into the staging SPA and writes storageState.
    {
      name: 'setup',
      testMatch: /global\.setup\.ts$/,
      use: { ...devices['Desktop Chrome'] },
    },
    // 2. Browser-driven auth/session coverage. Uses its OWN fresh login so its
    //    logout assertion never invalidates the shared API session.
    {
      name: 'auth-ui',
      testMatch: /auth\.spec\.ts$/,
      use: { ...devices['Desktop Chrome'] },
    },
    // 3. Request-context API coverage, authenticated via the shared session.
    {
      name: 'api',
      testMatch: /(oidc|tickets|contacts)\.spec\.ts$/,
      dependencies: ['setup'],
      use: { ...devices['Desktop Chrome'], storageState: STORAGE_STATE },
    },
  ],
});
