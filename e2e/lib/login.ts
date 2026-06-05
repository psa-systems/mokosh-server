import { expect, type APIRequestContext, type Page } from '@playwright/test';
import { env } from './env';
import { routes } from './api';

// Drive the staging SPA login form to establish a real session.
//
// The form markup is owned by the mokosh-clients SPA, not this repo. Selectors
// are scoped to a `<form>` ancestor and prefer `data-testid` hooks the SPA
// exposes, falling back to standard input types. The post-login proof is
// DOM-based (URL navigates away from /login) because the SPA holds its access
// token in WASM memory and there is no DOM-accessible session for an external
// request context to reuse - see e2e/lib/auth-state.ts.
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

  // The SPA navigates away from /login on a successful sign-in. Polling on
  // the URL is DOM-agnostic, so it survives marketing-side redesigns better
  // than asserting on any specific landing-page element.
  await expect
    .poll(() => new URL(page.url()).pathname, {
      timeout: 30_000,
      message: 'SPA login never navigated away from /login',
    })
    .not.toMatch(/^\/login\/?$/);
}

// Bypass the SPA: call `POST /api/v1/auth/login` directly and return the
// `access_token` from the JSON response. Used by `tests/global.setup.ts` to
// seed the bearer token the API project tests reuse.
export async function loginViaApi(request: APIRequestContext): Promise<string> {
  const res = await request.post(routes.authLogin, {
    data: { email: env.email, password: env.password },
  });
  if (!res.ok()) {
    throw new Error(`POST ${routes.authLogin} -> ${res.status()}: ${await res.text()}`);
  }
  const body = (await res.json()) as { access_token?: string };
  if (!body.access_token) {
    throw new Error(`login response missing access_token: ${JSON.stringify(body)}`);
  }
  return body.access_token;
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
// context (which would need its own bearer token).
export async function expectAtLoginScreen(page: Page): Promise<void> {
  await expect
    .poll(() => new URL(page.url()).pathname, {
      timeout: 15_000,
      message: 'expected SPA to navigate back to /login after logout',
    })
    .toMatch(/^\/login\/?$/);
}
