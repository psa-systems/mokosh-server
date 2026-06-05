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

// Routes the SPA almost certainly hits on landing. Visiting one of these
// post-login forces the SPA to fire an authenticated `/api/v1` request even
// if the default landing route does not.
const POST_LOGIN_PROBES = ['/dashboard', '/tickets'];

setup('capture bearer from the SPA login', async ({ page }) => {
  let token: string | null = null;
  const seenApiUrls: string[] = [];
  page.on('request', (req) => {
    const url = req.url();
    if (!url.includes('/api/v1')) return;
    seenApiUrls.push(url);
    if (token) return;
    const auth = req.headers()['authorization'];
    if (auth && auth.toLowerCase().startsWith('bearer ')) {
      token = auth.slice('bearer '.length).trim();
    }
  });

  await loginViaSpa(page);

  // Force the SPA to hit a data-loading route so we are not at the mercy of
  // whichever landing page the post-login redirect happens to use. Either
  // probe is fine - if one 404s the SPA still fires the auth'd API call
  // backing its router-level data fetch. Tolerate nav errors; the listener
  // captures whatever requests fly past, regardless of HTTP status.
  for (const path of POST_LOGIN_PROBES) {
    if (token) break;
    await page.goto(path, { waitUntil: 'domcontentloaded' }).catch(() => {});
  }

  try {
    await expect
      .poll(() => token, {
        timeout: 30_000,
        message: 'no /api/v1 request with `Authorization: Bearer` observed after SPA login',
      })
      .not.toBeNull();
  } catch (err) {
    // Re-throw with the captured URL list - expect.poll only accepts a static
    // string message, but the URLs we DID see are the load-bearing diagnostic.
    const observed =
      seenApiUrls.length === 0 ? '(none)' : seenApiUrls.slice(0, 10).join(', ');
    throw new Error(
      `SPA login completed but no /api/v1 request carrying \`Authorization: Bearer\` ` +
        `fired within 30s. /api/v1 requests observed (no Bearer header): ${observed}. ` +
        `Either the SPA stopped using Bearer auth, or it hits a different API base ` +
        `than e2e/lib/env.ts assumes. Underlying: ${String(err)}`,
    );
  }

  mkdirSync(dirname(TOKEN_FILE), { recursive: true });
  writeFileSync(TOKEN_FILE, token!);
});
