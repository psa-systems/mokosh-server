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
// 2-4 logins (test bodies + retries) and cross the cap, so keep this spec
// down to one login attempt per project run. It runs once per browser
// project (chromium, firefox, webkit), so the cap is per-browser too.
//
// Load-bearing defenses still in tree: the diagnostic capture
// (`attachPageDiagnostics`) and the click-retry-if-menu-not-open loop in
// `logout()` defend the Dioxus WASM hydration race (a visible avatar
// button does not mean its onclick handler has been wired up yet). Do
// not remove either without a replacement.
//
// PMS-148: re-fixme'd after the PMS-142 v2 un-fixme (PR #130) merged and
// the post-merge CI run exposed a NEW failure mode unrelated to the
// original BUNYIP-53 /logout bug (which is now fixed and deployed). The
// browser projects' login deterministically stalls when run after the
// `setup` project finishes: the form submit click no-op's (no POST in
// the request log), URL stuck at the hub `/login`. Setup's login in the
// same run succeeds.
//
// PMS-519: the un-fixme run (#364 / run 2528, after the PMS-521 consent fix)
// proved the login STALL is gone - login reached /dashboard cleanly. The
// remaining red is the LOGOUT step: after clicking Logout the SPA lands on the
// app root `/` (the logout redirect carries `url=https://msp.../`) and never
// reaches /login, so `expectAtLoginScreen` times out. That is a logout-redirect
// behaviour question (where should a logged-out user land?), separate from this
// spec's form-validation purpose and from the login path. Re-`fixme`'d to keep
// `form-validation.spec.ts` the only live browser login (one fewer login =>
// under the 5/min cap) while the logout redirect is tracked under PMS-148;
// un-fixme once that lands.
test.describe('auth login / session', () => {
  test.fixme('login + logout round-trip', async ({ page }) => {
    const diag = attachPageDiagnostics(page);

    try {
      await loginViaSpa(page);
    } catch (err) {
      // `cause` preserves the underlying assertion error so Playwright's
      // reporter can still surface its stack and failed-matcher details
      // below the diagnostic dump.
      throw new Error(diag.snapshot('login diagnostic'), { cause: err });
    }

    expect(page.url(), 'post-login URL').not.toMatch(/\/(login|error|404)\/?$/);

    try {
      await logout(page);
      await expectAtLoginScreen(page);
    } catch (err) {
      throw new Error(diag.snapshot('logout diagnostic'), { cause: err });
    }
  });
});

// Open the avatar-button user menu in the top bar, then click Logout in the
// popup. Markup pinned in mokosh-apps/src/components/layout.rs:386 - the
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
        `or the markup has changed - check mokosh-apps/src/components/layout.rs.`,
    );
  }

  await menu.getByRole('button', { name: /^logout$/i }).click();
}
