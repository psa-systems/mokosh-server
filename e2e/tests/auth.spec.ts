import { expect, test, type Page } from '@playwright/test';
import { expectAtLoginScreen, loginViaSpa } from '../lib/login';
import { attachPageDiagnostics } from '../lib/page-diagnostics';

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
//
// PMS-142 took this out of `test.fixme` quarantine. Two observed failure
// modes had previously made it flaky: (1) the bunyip hub form-submit not
// progressing past /login (transient hub-side, sometimes a credentials race
// with the WASM-hydrated SPA shim, sometimes legitimate user-error); (2)
// the post-logout URL stalling on /dashboard because the User-menu click
// reached the DOM before Dioxus had wired up the avatar's onclick
// (WASM hydration race - the SPA was visually rendered but not yet
// interactive). Mitigations:
//   - `loginViaSpa` itself stays as-is for now (the hub form is HTMX, not
//     WASM, so the hydration argument does not apply on its side; CI data
//     will tell us if more is needed).
//   - `logout` below clicks the avatar, then polls for the popup `role="menu"`
//     to actually appear. If it doesn't within a short window, it clicks
//     again (Dioxus toggles `open` per click, so the second click only fires
//     when the first one no-op'd against an unhydrated button).
//   - Both halves capture a diagnostic dump on failure via
//     attachPageDiagnostics so the next iteration is precise.
test.describe('auth login / session', () => {
  test('login + logout round-trip', async ({ page }) => {
    const diag = attachPageDiagnostics(page);

    try {
      await loginViaSpa(page);
    } catch (err) {
      throw new Error(`${String(err)}\n\n${diag.snapshot('login diagnostic', page)}`);
    }

    expect(page.url(), 'post-login URL').not.toMatch(/\/(login|error|404)\/?$/);

    try {
      await logout(page);
      await expectAtLoginScreen(page);
    } catch (err) {
      throw new Error(`${String(err)}\n\n${diag.snapshot('logout diagnostic', page)}`);
    }
  });
});

// Open the avatar-button user menu in the top bar, then click Logout in the
// popup. Markup pinned in mokosh-clients/src/components/layout.rs:386 - the
// button carries `aria-label="User menu"`, the dropdown is `role="menu"`,
// and Logout is a `button` (not an `<a>`) so the menu does not navigate
// before the SPA's logout handler can clear local state. The logout handler
// then redirects to the bunyip hub's /logout which itself ends up on /login;
// the surrounding test asserts on the final URL.
//
// The click-retry-if-menu-not-open loop defends against the Dioxus WASM
// hydration race: a visible avatar button does not mean its onclick handler
// has been wired up yet. If the first click no-op'd, the second one will
// fire against the now-hydrated handler. Cap at 3 attempts so a genuinely
// broken SPA fails clearly rather than spinning forever.
const MENU_OPEN_ATTEMPTS = 3;
const MENU_OPEN_WAIT_MS = 3_000;

async function logout(page: Page): Promise<void> {
  // `.first()` defends against strict-mode violations if the SPA ever renders
  // a duplicate menu (e.g. parallel mobile/desktop nav copies of the same
  // button). The visible avatar in the top bar is the one we want either way.
  const userMenu = page.getByRole('button', { name: 'User menu' }).first();
  await userMenu.waitFor({ state: 'visible', timeout: 10_000 });

  const menu = page.getByRole('menu').first();
  let opened = false;
  for (let attempt = 1; attempt <= MENU_OPEN_ATTEMPTS; attempt += 1) {
    await userMenu.click();
    try {
      await menu.waitFor({ state: 'visible', timeout: MENU_OPEN_WAIT_MS });
      opened = true;
      break;
    } catch {
      // Menu didn't appear within the window. Most likely the Dioxus
      // component had not finished hydrating; loop and try again. Each
      // click toggles `open`, so an odd number of clicks lands on "open".
    }
  }
  if (!opened) {
    throw new Error(
      `User menu did not open after ${MENU_OPEN_ATTEMPTS} clicks on the avatar ` +
        `(${MENU_OPEN_WAIT_MS / 1000}s wait each). SPA likely still not interactive ` +
        `or the markup has changed - check mokosh-clients/src/components/layout.rs.`,
    );
  }

  await menu.getByRole('button', { name: /^logout$/i }).click();
}
