import { test as setup } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { TOKEN_FILE } from '../lib/auth-state';
import { loginViaApi } from '../lib/login';

// Runs once before the `api` project. Calls `POST /api/v1/auth/login`
// directly and persists the returned `access_token` on disk; the custom
// `test` fixture in lib/fixtures.ts injects it as the `Authorization`
// header on every API request. The browser SPA is bypassed here on purpose
// because the SPA keeps its token in WASM memory
// (mokosh-clients/src/hooks/fetch.rs:189) and Playwright's `storageState`
// cookie/localStorage replay would not authenticate the API context. See
// e2e/lib/auth-state.ts.
setup('authenticate via API', async ({ request }) => {
  const token = await loginViaApi(request);
  mkdirSync(dirname(TOKEN_FILE), { recursive: true });
  writeFileSync(TOKEN_FILE, token);
});
