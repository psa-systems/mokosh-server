import { expect, test, type Page } from '@playwright/test';
import { routes } from '../lib/api';
import { expectAnonymous, expectAuthenticated, loginViaSpa } from '../lib/login';

// Browser-driven auth coverage (AC coverage area 1). This project does NOT use
// the shared storageState: it logs in fresh so that its logout assertion tears
// down its own session and never invalidates the session the API tests share.
test.describe('auth login / session', () => {
  test('SPA login establishes an authenticated session', async ({ page }) => {
    await loginViaSpa(page);
    await expectAuthenticated(page.request);
  });

  test('logout invalidates the session', async ({ page }) => {
    await loginViaSpa(page);
    await expectAuthenticated(page.request);
    await logout(page);
    await expectAnonymous(page.request);
  });
});

// Log out through the SPA control when present; otherwise hit the legacy logout
// endpoint directly. Either path must clear the session cookie.
async function logout(page: Page): Promise<void> {
  const control = page
    .getByRole('button', { name: /log ?out|sign ?out/i })
    .or(page.getByRole('link', { name: /log ?out|sign ?out/i }))
    .first();

  if (await control.isVisible().catch(() => false)) {
    await control.click();
  } else {
    const res = await page.request.post(routes.authLogout);
    expect(
      res.ok() || res.status() === 401,
      `POST ${routes.authLogout} -> ${res.status()}`,
    ).toBeTruthy();
  }
}
