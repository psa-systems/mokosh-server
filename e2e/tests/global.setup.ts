import { expect, test as setup } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { TOKEN_FILE } from '../lib/auth-state';
import { loginViaSpa } from '../lib/login';

// Runs once before the `api` project. Drives the staging SPA login in a real
// browser, sniffs the first `/api/v1` request the post-login SPA fires, and
// pulls the bearer token straight from its `Authorization` header.
//
// Why network sniff and not POST /api/v1/auth/login directly?
//   - The OP (crates/mokosh-auth-oidc/src/discovery.rs:47) only advertises
//     `authorization_code` + `refresh_token`. No client_credentials, no
//     password grant - so a service-to-service token mint is not available.
//   - Legacy POST /api/v1/auth/login only works against rows in mokosh's
//     local `users` table; SPA accounts that signed up through the bunyip
//     hub live elsewhere and return 401 there.
//   - The SPA's bearer token lives in WASM thread-local memory
//     (mokosh-clients/src/hooks/fetch.rs:189), so page.evaluate() cannot
//     read it.
// Intercepting the outbound request header is the only path that reuses the
// real auth flow without registering a new OIDC client or maintaining a
// parallel signup pipeline.
setup('capture bearer from the SPA login', async ({ page }) => {
  let token: string | null = null;
  page.on('request', (req) => {
    if (token) return;
    if (!req.url().includes('/api/v1/')) return;
    const auth = req.headers()['authorization'];
    if (auth && auth.toLowerCase().startsWith('bearer ')) {
      token = auth.slice('bearer '.length).trim();
    }
  });

  await loginViaSpa(page);

  // After the SPA lands on its dashboard it fires an authenticated `/api/v1`
  // call (typically /auth/me or a list endpoint) to hydrate the UI. Poll
  // until that request is intercepted. 20s covers a slow staging hydrate
  // without bumping the global test timeout.
  await expect
    .poll(() => token, {
      timeout: 20_000,
      message:
        'SPA login completed but no /api/v1 request carrying `Authorization: Bearer` ' +
        'fired within 20s. Either the SPA stopped using Bearer auth, or the post-login ' +
        'route does not hit /api/v1 anymore.',
    })
    .not.toBeNull();

  mkdirSync(dirname(TOKEN_FILE), { recursive: true });
  writeFileSync(TOKEN_FILE, token!);
});
