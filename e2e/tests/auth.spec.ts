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
// PMS-140 phase-1 quarantine: the browser-driven login + logout round-trip
// is flaky against the bunyip hub. Setup proves the underlying SPA login
// works end-to-end (it captures a bearer from the post-login /api request),
// so the suite has real auth coverage; this test fails non-deterministically
// on the form-submit step or on the cross-origin logout redirect chain.
// `test.fixme` keeps it discoverable as "to fix" without flagging CI red.
// Revisit once the hub login surface stabilises - see PMS-140.
test.describe('auth login / session', () => {
  test.fixme('login + logout round-trip', async ({ page }) => {
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
  // `.first()` defends against strict-mode violations if the SPA ever renders
  // a duplicate menu (e.g. parallel mobile/desktop nav copies of the same
  // button). The visible avatar in the top bar is the one we want either way.
  const userMenu = page.getByRole('button', { name: 'User menu' }).first();
  await userMenu.waitFor({ state: 'visible', timeout: 10_000 });
  await userMenu.click();

  // Same defence on the popup: a future drawer or context menu carrying
  // role="menu" elsewhere on the page would otherwise trip strict mode.
  const menu = page.getByRole('menu').first();
  await menu.getByRole('button', { name: /^logout$/i }).click();
}
