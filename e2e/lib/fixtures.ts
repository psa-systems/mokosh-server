// Custom Playwright `test` for the `api` project. Wraps the built-in `request`
// fixture so every API call carries the bearer token the setup project wrote
// to disk. See e2e/lib/auth-state.ts for the why - the mokosh-clients SPA
// keeps tokens in WASM memory rather than cookies, so Playwright's
// `storageState` reuse cannot authenticate the API context on its own.

import { test as base, request as requestFactory, type APIRequestContext } from '@playwright/test';
import { readToken } from './auth-state';

interface AuthFixtures {
  request: APIRequestContext;
}

export const test = base.extend<AuthFixtures>({
  request: async ({ playwright: _playwright }, use, testInfo) => {
    const token = readToken();
    const baseURL = testInfo.project.use.baseURL;
    const ctx = await requestFactory.newContext({
      baseURL,
      extraHTTPHeaders: { Authorization: `Bearer ${token}` },
    });
    await use(ctx);
    await ctx.dispose();
  },
});

export { expect } from '@playwright/test';
