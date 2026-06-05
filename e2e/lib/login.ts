import { expect, type APIRequestContext, type Page } from '@playwright/test';
import { env } from './env';
import { routes } from './api';

// Drive the staging SPA login form to establish a real session.
//
// The form markup is owned by the mokosh-clients SPA, not this repo, so the
// selectors below are deliberately permissive and may need adjusting as the
// SPA evolves (this is the phase-1 flakiness-shakeout suite, PMS-140). The
// post-login proof is an API probe, which is stable regardless of the DOM.
export async function loginViaSpa(page: Page): Promise<void> {
  await page.goto('/login');

  const email = page
    .locator(
      'input[type="email"], input[name="email"], input[autocomplete="username"]',
    )
    .first();
  const password = page
    .locator(
      'input[type="password"], input[name="password"], input[autocomplete="current-password"]',
    )
    .first();

  await email.waitFor({ state: 'visible' });
  await email.fill(env.email);
  await password.fill(env.password);

  await page
    .getByRole('button', { name: /sign ?in|log ?in|continue|submit/i })
    .first()
    .click();

  // Wait until the session cookie actually authorises an API call rather than
  // racing a client-side redirect.
  await expect
    .poll(async () => (await page.request.get(`${routes.tickets}?per_page=1`)).status(), {
      timeout: 30_000,
      message: 'SPA login never produced an authenticated session',
    })
    .toBe(200);
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
