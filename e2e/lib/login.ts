import { authenticator } from 'otplib';
import { expect, type APIRequestContext, type Page } from '@playwright/test';
import { env } from './env';
import { routes } from './api';

// Drive the staging SPA login form to establish a real session.
//
// The form markup is owned by the bunyip hub (the SPA redirects to it), not
// this repo. Selectors are scoped to a `<form>` ancestor and prefer
// `data-testid` hooks the hub exposes, falling back to standard input types.
// The post-login proof is DOM-based (URL navigates fully out of the /login
// flow) because the SPA holds its access token in WASM memory and there is
// no DOM-accessible session for an external request context to reuse - see
// e2e/lib/auth-state.ts.
//
// The E2E account has 2FA enabled (matching the production hardening
// posture). After credentials submit, the hub redirects to `/login/2fa` and
// the helper enters a TOTP code derived from `E2E_TOTP_SECRET`. The poll
// uses `/^\/login(\/|$)/` so multi-step flows count as IN /login and the
// helper only returns once the hub has actually let us through.
export async function loginViaSpa(page: Page): Promise<void> {
  await page.goto('/login');

  const form = page.locator('form').first();

  const email = form
    .locator(
      'input[data-testid="email"], input[type="email"], input[name="email"], input[autocomplete="username"]',
    )
    .first();
  const password = form
    .locator(
      'input[data-testid="password"], input[type="password"], input[name="password"], input[autocomplete="current-password"]',
    )
    .first();

  await email.waitFor({ state: 'visible' });
  await email.fill(env.email);
  await password.fill(env.password);

  await form
    .getByRole('button', { name: /sign ?in|log ?in|continue|submit/i })
    .first()
    .click();

  // Wait for the hub to land on the next page. /login/2fa is the expected
  // step for an MFA-enabled account; anything else (success or error) flows
  // through to the URL-out-of-/login poll below.
  await page
    .waitForURL(/\/login\/(2fa|mfa)(\/|$|\?)/, { timeout: 15_000 })
    .catch(() => {});
  if (/^\/login\/(2fa|mfa)/.test(new URL(page.url()).pathname)) {
    await fillTotpStep(page);
  }

  // The SPA + hub navigate fully out of the /login path family on success.
  // Match anything that starts with /login (not just `/login` or `/login/`)
  // so multi-step flows like `/login/2fa`, `/login/mfa`, `/login/recovery`,
  // etc are still treated as IN the login flow. A previous CI run got past
  // a narrower check while sitting on `/login/2fa` and then thrashed for
  // 30s trying to capture a bearer that no successful login had produced.
  await expect
    .poll(() => new URL(page.url()).pathname, {
      timeout: 30_000,
      message:
        'SPA login never navigated away from the /login flow ' +
        '(still on /login, /login/2fa, /login/mfa, or similar)',
    })
    .not.toMatch(/^\/login(\/|$)/);
}

// Compute the current TOTP code from E2E_TOTP_SECRET (RFC 6238, 30s window,
// 6 digits, SHA-1 - the otplib defaults match the mokosh-auth-crypto totp
// module). Fill it into the 2FA form and submit. Selectors are deliberately
// permissive because the hub's markup may evolve; the regex on the submit
// button covers "Verify" copy in addition to the standard login verbs.
async function fillTotpStep(page: Page): Promise<void> {
  const code = authenticator.generate(env.totpSecret);
  const form = page.locator('form').first();
  const codeInput = form
    .locator(
      'input[data-testid="totp"], ' +
        'input[autocomplete="one-time-code"], ' +
        'input[name="code"], ' +
        'input[name="otp"], ' +
        'input[name="totp"], ' +
        'input[inputmode="numeric"]',
    )
    .first();
  await codeInput.waitFor({ state: 'visible', timeout: 10_000 });
  await codeInput.fill(code);
  await form
    .getByRole('button', { name: /verify|continue|submit|sign ?in|log ?in/i })
    .first()
    .click();
}

// An authenticated session can read the tenant-scoped tickets list (200); an
// anonymous one is rejected (401/403). Cheapest universal session proof.
export async function expectAuthenticated(request: APIRequestContext): Promise<void> {
  const res = await request.get(`${routes.tickets}?per_page=1`);
  expect(res.status(), `GET ${routes.tickets} should be 200 when authenticated`).toBe(200);
}

export async function expectAnonymous(request: APIRequestContext): Promise<void> {
  const res = await request.get(`${routes.tickets}?per_page=1`);
  expect(
    [401, 403],
    `GET ${routes.tickets} should be 401/403 when logged out, got ${res.status()}`,
  ).toContain(res.status());
}

// Browser-driven "logged out" proof: the SPA bounces back to /login when the
// session is gone. Used by the auth-ui project so it never touches a request
// context (which would need its own bearer token). Logout redirects through
// the bunyip hub's /logout (cross-origin POST + Set-Cookie + redirect to the
// hub's /login), so the wait budget covers that round-trip. Match any
// /login* path so an intermediate hub step (e.g. consent screen) still
// counts as "back at login".
export async function expectAtLoginScreen(page: Page): Promise<void> {
  await expect
    .poll(() => new URL(page.url()).pathname, {
      timeout: 30_000,
      message: 'expected SPA/hub to navigate to /login after logout',
    })
    .toMatch(/^\/login(\/|$)/);
}
