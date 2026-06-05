import { expect, test, type Page } from '@playwright/test';
import { expectAtLoginScreen, loginViaSpa } from '../lib/login';

// Browser-driven auth coverage (AC coverage area 1). DOM-level assertions:
// the SPA stores its access token in WASM memory, so an external request
// context would lack the bearer header and 401 spuriously.
//
// Login and logout are folded into a SINGLE test because each loginViaSpa
// call counts toward the per-email rate limit (5/min in
// src/modules/auth/routes.rs). Setup runs first (1 login) and may retry
// once on CI (2). Splitting login/logout into two tests would add another
// 2-4 logins (test bodies + retries) and cross the cap, so keep auth-ui
// down to one login attempt per project run.
test.describe('auth login / session', () => {
  test('login + logout round-trip', async ({ page }) => {
    await loginViaSpa(page);
    // loginViaSpa already polled "URL is no longer /login"; verify the SPA
    // settled on a non-error landing page rather than 404 or transient
    // error route.
    expect(page.url(), 'post-login URL').not.toMatch(/\/(login|error|404)\/?$/);

    await logout(page);
    await expectAtLoginScreen(page);
  });
});

// Open the avatar-button user menu in the top bar, then click Logout in the
// popup. Markup pinned in mokosh-clients/src/components/layout.rs:386 - the
// button carries `aria-label="User menu"`, the dropdown is `role="menu"`,
// and Logout is a `button` (not an `<a>`) so the menu does not navigate
// before the SPA's logout handler can clear local state. The logout handler
// then redirects to the bunyip hub's /logout which itself ends up on /login;
// the surrounding test asserts on the final URL.
async function logout(page: Page): Promise<void> {
  const userMenu = page.getByRole('button', { name: 'User menu' });
  await userMenu.waitFor({ state: 'visible', timeout: 10_000 });
  await userMenu.click();

  const menu = page.getByRole('menu');
  await menu.getByRole('button', { name: /^logout$/i }).click();
}
