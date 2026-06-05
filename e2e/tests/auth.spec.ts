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

// Click the SPA's logout control. The control must clear the in-memory token
// and navigate back to /login; if no control is found the SPA is broken and
// the test fails loudly rather than papering over with a backend logout call.
async function logout(page: Page): Promise<void> {
  const control = page
    .getByRole('button', { name: /log ?out|sign ?out/i })
    .or(page.getByRole('link', { name: /log ?out|sign ?out/i }))
    .first();

  await control.waitFor({ state: 'visible', timeout: 10_000 });
  await control.click();
}
