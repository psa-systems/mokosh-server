import { expect, test, type Page } from '@playwright/test';
import { expectAtLoginScreen, loginViaSpa } from '../lib/login';

// Browser-driven auth coverage (AC coverage area 1). This project drives the
// SPA in a real browser and asserts on URL transitions: the SPA stores its
// access token in WASM memory, so any request-context API probe from outside
// the SPA would lack the bearer header and 401 spuriously. DOM-level assertions
// keep this test honest about what the browser experience proves.
test.describe('auth login / session', () => {
  test('SPA login leaves the /login screen', async ({ page }) => {
    await loginViaSpa(page);
    // loginViaSpa already polls for "URL no longer matches /login"; a second
    // assertion here would be redundant, but verify the SPA settled on a
    // non-error landing page rather than a 404 or transient error route.
    expect(page.url(), 'post-login URL').not.toMatch(/\/(login|error|404)\/?$/);
  });

  test('logout returns the SPA to /login', async ({ page }) => {
    await loginViaSpa(page);
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
