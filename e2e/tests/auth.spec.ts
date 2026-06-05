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
// PMS-142: this test stays `test.fixme` until an upstream bunyip bug is
// fixed. The CI diagnostic dump from the first un-fixme attempt showed:
//
//   - Login worked end-to-end (TOTP, OIDC callback, lands on /dashboard).
//   - The logout click reached `https://a8n.systems/logout` (visible in
//     the request log).
//   - Immediately after `/logout`, the SPA fired ANOTHER `/oauth2/authorize`
//     and the OP returned a `code` (the OP session survived the supposed
//     logout). The SPA exchanged the code, landed back on `/dashboard`, and
//     `expectAtLoginScreen` timed out at `/dashboard`.
//
// Bunyip's GET `/logout` clears `access_token` and `refresh_token` cookies
// (see `bunyip/crates/bunyip-domain/src/middleware/auth.rs:272` for
// `AuthCookies::clear`), but `/oauth2/authorize` was still able to issue a
// fresh code, meaning some persistence path (op_session, hub session
// cookie, or browser-side refresh) keeps the user authenticated past the
// logout. The SPA author actually predicted this in
// `mokosh-clients/src/components/layout.rs:367-373`:
//
//   "Without that round-trip, the OP cookie would still be live and a
//    subsequent visit here would silently sign the user back in via the
//    SSO bridge."
//
// The intended round-trip is happening client-side, but the server-side
// cookie clear isn't enough on staging. Needs an upstream bunyip fix
// (file an issue against the BUNYIP project when this gets prioritised).
// Re-fixme until bunyip's `/logout` fully terminates the OP session - at
// that point this test should pass without further changes here.
//
// Kept in tree: the diagnostic capture (`attachPageDiagnostics`) and the
// click-retry-if-menu-not-open loop in `logout()` (Dioxus WASM hydration
// race defense). Both are load-bearing for the eventual un-fixme.
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
