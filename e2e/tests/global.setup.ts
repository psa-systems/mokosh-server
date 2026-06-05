import { test as setup } from '@playwright/test';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { STORAGE_STATE } from '../playwright.config';
import { loginViaSpa } from '../lib/login';

// Runs once before the `api` project. Logs into the staging SPA in a real
// browser and persists the resulting session as storageState, which the
// request-context API tests then reuse (the hybrid harness, PMS-140).
setup('authenticate via SPA', async ({ page }) => {
  await loginViaSpa(page);
  mkdirSync(dirname(STORAGE_STATE), { recursive: true });
  await page.context().storageState({ path: STORAGE_STATE });
});
