import { expect, test as setup } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { TOKEN_FILE } from '../lib/auth-state';
import { loginViaSpa } from '../lib/login';

// Runs once before the `api` project. Drives the staging SPA login in a real
// browser, sniffs the FIRST request that carries an `Authorization: Bearer`
// header (any host, any path), and persists the token for the api project.
//
// Why "any host"? Post-login the SPA fires `/v1/auth/memberships` against
// the bunyip hub (api.a8n.systems) FIRST, before any mokosh-server PSA
// call. Both endpoints accept the same bunyip-issued at+jwt: mokosh-server
// runs the bunyip-RS verifier (src/modules/auth/middleware.rs:69) and
// JIT-mirrors the (sub, email) into its own users table on first use. So
// the bearer attached to the membership request is the same token that
// authenticates /api/v1/tickets later, and we can capture it on whichever
// authenticated request fires first.
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
// post-login forces the SPA to fire an authenticated request even if the
// default landing route does not.
const POST_LOGIN_PROBES = ['/dashboard', '/tickets'];

// Cap on URL samples included in the timeout diagnostic. High enough to see
// the actual SPA traffic pattern, low enough to keep the error readable.
const URL_SAMPLE_CAP = 30;

setup('capture bearer from the SPA login', async ({ page }) => {
  let token: string | null = null;
  let tokenSourceUrl: string | null = null;
  const allRequestUrls: string[] = [];
  const bearerRequestUrls: string[] = [];
  page.on('request', (req) => {
    const url = req.url();
    allRequestUrls.push(url);
    const auth = req.headers()['authorization'];
    if (!auth || !auth.toLowerCase().startsWith('bearer ')) return;
    bearerRequestUrls.push(url);
    if (token) return;
    token = auth.slice('bearer '.length).trim();
    tokenSourceUrl = url;
  });

  // Track every URL the top frame lands on. On timeout we dump the trail so
  // we can see whether the SPA bounced through the bunyip hub correctly.
  const urlTrail: string[] = [];
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) urlTrail.push(frame.url());
  });

  await loginViaSpa(page);
  const postLoginUrl = page.url();

  // Force the SPA to hit a data-loading route so we are not at the mercy of
  // whichever landing page the post-login redirect happens to use. Either
  // probe is fine - if one 404s the SPA still fires the auth'd request
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
        message: 'no request with `Authorization: Bearer` observed after SPA login',
      })
      .not.toBeNull();
  } catch (err) {
    // expect.poll's `message` is a static string, so the dynamic diagnostic
    // gets rebuilt here on the way out. The captured trail tells us whether
    // (a) login actually completed, (b) the SPA fired ANY requests
    // post-login, and (c) whether any of them carried a Bearer header.
    const sample = (arr: string[]) =>
      arr.length === 0 ? '(none)' : arr.slice(-URL_SAMPLE_CAP).join('\n    ');
    const finalUrl = page.url();
    throw new Error(
      [
        'SPA login completed but no request carrying `Authorization: Bearer` ' +
          `fired within 30s.`,
        `  postLoginUrl=${postLoginUrl}`,
        `  finalUrl=${finalUrl}`,
        `  urlTrail (last ${URL_SAMPLE_CAP}):\n    ${sample(urlTrail)}`,
        `  Bearer-carrying requests (last ${URL_SAMPLE_CAP}):\n    ${sample(bearerRequestUrls)}`,
        `  ALL requests (last ${URL_SAMPLE_CAP}):\n    ${sample(allRequestUrls)}`,
        `  underlying: ${String(err)}`,
      ].join('\n'),
    );
  }

  console.log(`[setup] captured bearer from ${tokenSourceUrl}`);
  mkdirSync(dirname(TOKEN_FILE), { recursive: true });
  writeFileSync(TOKEN_FILE, token!);
});
