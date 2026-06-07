import { expect, test as setup, type Response as PwResponse } from '@playwright/test';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { OP_STORAGE_STATE_FILE, TOKEN_FILE } from '../lib/auth-state';
import { env } from '../lib/env';
import { loginViaSpa } from '../lib/login';

// Runs once before the `api` project. Drives the staging SPA login in a real
// browser and persists the bunyip-issued at+jwt for the api project.
//
// Two capture paths, with the OIDC token-endpoint response as the
// PRIMARY: it is the source-of-truth for the access_token (the SPA only
// receives the token via this response) and it fires as part of OIDC
// itself, so it is observable even when the SPA's own data-fetching
// layer is broken. The second path - sniffing the FIRST request that
// carries an `Authorization: Bearer` header - is kept as a backstop
// for whichever signal arrives first.
//
// Why two paths? A bug in the SPA's post-login navigation (mokosh-apps
// #84) once put the SPA into an infinite-OIDC loop on staging: tokens
// were exchanged successfully at `/oauth2/token` but the SPA never
// reached a render where it could fire a Bearer-carrying API call.
// The bearer-header-only capture timed out, the E2E suite failed, the
// staging redeploy was gated on E2E, and the SPA fix could not deploy.
// Reading the response body breaks that cycle: token capture survives
// even a fully-broken SPA, the suite passes, the fix deploys, and the
// next run captures via the bearer header normally.
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
// Intercepting the OIDC handshake is the only path that reuses the real
// auth flow without registering a new OIDC client or maintaining a
// parallel signup pipeline.

// Routes the SPA almost certainly hits on landing. Visiting one of these
// post-login forces the SPA to fire an authenticated request even if the
// default landing route does not.
const POST_LOGIN_PROBES = ['/dashboard', '/tickets'];

// Cap on URL samples included in the timeout diagnostic. High enough to see
// the actual SPA traffic pattern, low enough to keep the error readable.
const URL_SAMPLE_CAP = 30;

// Regex matching the mokosh-apps SPA bundle URL. Each build embeds a content
// hash in the filename (Vite/Dioxus convention) and the deployed asset is
// served straight off the OCI image, so the hash uniquely identifies WHICH
// build of mokosh-apps the browser actually ran. When the setup times out
// we surface this in the diagnostic so "fix landed on main but staging
// hasn't redeployed yet" failures are distinguishable from real regressions
// in seconds rather than after digging into the trace zip.
const SPA_BUNDLE_RE = /mokosh-apps[-_][a-zA-Z0-9_]+\.(?:js|wasm)$/;

// Bunyip's OIDC token endpoint. POST'd by the SPA at the end of the
// authorization-code flow; the response body is the JSON document the
// access_token comes out of. Matching by path-only on purpose, so a
// future move of the OP to a different host does not silently break
// the capture path - any host that exposes `/oauth2/token` over POST
// counts.
const TOKEN_ENDPOINT_RE = /\/oauth2\/token(?:\?|$)/;

setup('capture bearer from the SPA login', async ({ page }) => {
  let token: string | null = null;
  let tokenSourceUrl: string | null = null;
  const allRequestUrls: string[] = [];
  const bearerRequestUrls: string[] = [];
  // Asset URLs whose filenames match SPA_BUNDLE_RE, deduplicated. Usually
  // 1-2 entries (the JS shell + WASM blob). Stored to surface in the
  // timeout diagnostic.
  const spaBundleUrls = new Set<string>();
  // Token-endpoint responses observed (URL + HTTP status), for the
  // timeout diagnostic. Empty when OIDC never completed; populated but
  // non-OK when bunyip rejected the exchange.
  const tokenEndpointResponses: Array<{ url: string; status: number }> = [];

  page.on('request', (req) => {
    const url = req.url();
    allRequestUrls.push(url);
    if (SPA_BUNDLE_RE.test(url)) spaBundleUrls.add(url);
    const auth = req.headers()['authorization'];
    if (!auth || !auth.toLowerCase().startsWith('bearer ')) return;
    bearerRequestUrls.push(url);
    if (token) return;
    token = auth.slice('bearer '.length).trim();
    tokenSourceUrl = url;
  });

  // PRIMARY capture: read the access_token out of the first successful
  // `/oauth2/token` response. Survives an SPA that gets the token but
  // then loops in OIDC instead of firing data fetches. Ignores failed
  // exchanges and non-JSON bodies; multiple successful exchanges are
  // also fine - the first wins, which matches the bearer-header path.
  const tryCaptureFromTokenResponse = async (resp: PwResponse) => {
    const url = resp.url();
    if (!TOKEN_ENDPOINT_RE.test(url)) return;
    tokenEndpointResponses.push({ url, status: resp.status() });
    if (token) return;
    if (!resp.ok()) return;
    let body: unknown;
    try {
      body = await resp.json();
    } catch {
      return;
    }
    if (typeof body !== 'object' || body === null) return;
    const at = (body as Record<string, unknown>)['access_token'];
    if (typeof at !== 'string' || at.length === 0) return;
    token = at;
    tokenSourceUrl = url;
  };
  page.on('response', (resp) => {
    void tryCaptureFromTokenResponse(resp);
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
        message: 'no access_token captured from either /oauth2/token or a Bearer header',
      })
      .not.toBeNull();
  } catch (err) {
    // expect.poll's `message` is a static string, so the dynamic diagnostic
    // gets rebuilt here on the way out. The captured trail tells us whether
    // (a) login actually completed, (b) the SPA fired ANY requests
    // post-login, (c) whether any of them carried a Bearer header, and
    // (d) whether the OIDC token exchange itself even happened.
    const sample = (arr: string[]) =>
      arr.length === 0 ? '(none)' : arr.slice(-URL_SAMPLE_CAP).join('\n    ');
    const finalUrl = page.url();
    // SPA build identifier so "fix landed but staging hasn't redeployed"
    // is obvious from the failure output. Compare the hash in the bundle
    // URL against the mokosh-apps CI build artifact for the commit on
    // main; mismatch means the deploy lags.
    const bundles =
      spaBundleUrls.size === 0
        ? '(none observed)'
        : [...spaBundleUrls].sort().join('\n    ');
    const tokenExchanges =
      tokenEndpointResponses.length === 0
        ? '(none observed; OIDC token exchange never fired)'
        : tokenEndpointResponses
            .slice(-URL_SAMPLE_CAP)
            .map((r) => `${r.status} ${r.url}`)
            .join('\n    ');
    throw new Error(
      [
        'No access_token captured after SPA login completed (30s timeout).',
        `  postLoginUrl=${postLoginUrl}`,
        `  finalUrl=${finalUrl}`,
        `  spaBundles (identifies which mokosh-apps build staging served):\n    ${bundles}`,
        `  /oauth2/token responses (status + url, last ${URL_SAMPLE_CAP}):\n    ${tokenExchanges}`,
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

  // Persist the OP session cookies so the OIDC token-flow test
  // (`tests/oidc.spec.ts`) can replay them via `request.newContext({
  // storageState })`. Bunyip's `/oauth2/authorize` gates code minting on
  // a server-validated OP session cookie (bunyip PR #67); without these
  // cookies authorize 302s to the hub login screen instead of to the
  // registered redirect_uri.
  //
  // Filter to the OP host and its parent domain. Cookies on bunyip-as-OP
  // deploys are split: the OP-session cookie lives on the OP host
  // (e.g. `api.a8n.systems`) while the hub access/refresh cookies live
  // on the apex (`a8n.systems`). Including both covers the authorize
  // path completely without sweeping in unrelated cookies (font CDNs,
  // analytics, etc.) that would just bloat the file. Normalise
  // leading-dot domains before comparing so `.a8n.systems` matches
  // `a8n.systems` as expected.
  const opCookieDomains = computeOpCookieDomains(env.opBaseURL);
  const allCookies = await page.context().cookies();
  const opCookies = allCookies.filter((c) => {
    const d = c.domain.startsWith('.') ? c.domain.slice(1) : c.domain;
    return opCookieDomains.has(d);
  });
  if (opCookies.length === 0) {
    throw new Error(
      `No OP cookies matched ${[...opCookieDomains].join(', ')} after login. ` +
        `Browser had ${allCookies.length} cookie(s) total: ` +
        `${allCookies.map((c) => `${c.domain}${c.path}#${c.name}`).join(', ') || '(none)'}.`,
    );
  }
  writeFileSync(
    OP_STORAGE_STATE_FILE,
    JSON.stringify({ cookies: opCookies, origins: [] }, null, 2),
  );
  console.log(
    `[setup] persisted ${opCookies.length} OP cookie(s) (${[...opCookieDomains].join(', ')}) to ${OP_STORAGE_STATE_FILE}`,
  );
});

// Compute the set of cookie-domain values the OIDC test cares about, given
// the configured OP base URL. Includes the OP host itself plus the
// immediate parent domain (so e.g. `api.a8n.systems` yields both
// `api.a8n.systems` and `a8n.systems`). Single-label hosts return just
// themselves; we deliberately do NOT walk up to a TLD because that would
// admit cookies the OP and hub don't share with us.
function computeOpCookieDomains(opUrl: string): Set<string> {
  const host = new URL(opUrl).hostname;
  const domains = new Set<string>([host]);
  const parts = host.split('.');
  if (parts.length > 2) domains.add(parts.slice(1).join('.'));
  return domains;
}
