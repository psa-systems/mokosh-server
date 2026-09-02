// Custom Playwright `test` fixtures for the `api` project.
//
// Two `request` fixtures coexist because the mokosh PSA API and the
// bunyip OP are authenticated differently:
//
// - `test` (default): every API call carries the bunyip-issued bearer
//   token the setup project captured. Used by all PSA-API specs
//   (tickets, contacts, tenants). The mokosh-apps SPA keeps its token
//   in WASM memory rather than cookies, so Playwright's `storageState`
//   alone cannot authenticate the PSA context - the captured Bearer
//   header is the only path.
//
// - `oidcTest`: replays the OP session cookies the setup project
//   persisted via `request.newContext({ storageState })`, and does NOT
//   attach a bearer header. The OIDC flow specs use this so
//   `/oauth2/authorize` sees a server-validated OP session (bunyip PR
//   #67) and 302s to the registered redirect_uri with a `code` rather
//   than bouncing to the hub login screen. A bearer header on these
//   requests would carry the wrong audience and confuse the OP, so the
//   fixture deliberately omits it.

import { test as base, request as requestFactory, type APIRequestContext } from '@playwright/test';
import { env } from './env';
import { readOpStorageState, readToken } from './auth-state';

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

export const oidcTest = base.extend<AuthFixtures>({
  request: async ({ playwright: _playwright }, use) => {
    const storageState = readOpStorageState();
    // baseURL is the OP host; OIDC specs hit absolute URLs from
    // discovery, but a baseURL still gives relative paths (e.g.
    // `/.well-known/openid-configuration` in `discoverOidc`) a sensible
    // resolution.
    const ctx = await requestFactory.newContext({
      baseURL: env.opBaseURL,
      storageState,
    });
    await use(ctx);
    await ctx.dispose();
  },
});

export { expect } from '@playwright/test';
