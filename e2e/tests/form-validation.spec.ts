import { expect, test } from '@playwright/test';
import { loginViaSpa } from '../lib/login';
import { attachPageDiagnostics } from '../lib/page-diagnostics';

// AC7 regression for the PMS-515 form-validation unification (PMS-516 component
// `rules` + PMS-517 `FormGuard` + PMS-518 per-form migration): a form that
// presents required fields must reject an empty submit with a per-field inline
// error for EVERY missing field at once (not just the first), stay on the form
// (no POST / no navigation), and clear a field's error as it is corrected.
//
// Browser-driven (real Chromium, DOM assertions), like `auth.spec.ts` - the SPA
// holds its bearer in WASM memory, so this UI behaviour can only be observed by
// driving the page, not an API request context. It exercises the deployed
// mokosh-apps SPA on the target environment.
//
// PMS-519 verification status: the PMS-521 consent fix landed, so `setup` and
// this spec's shared `loginViaSpa` now log in (the OP consent screen is
// clicked through). The first un-fixme run (#364 / run 2528) still failed
// here - the `Create Ticket` button never appeared on `/tickets/new` - but the
// spec carried NO diagnostics, so the failure mode (did the page bounce back to
// /login after the hard `goto` reboot of the WASM app? did it render an OLD SPA
// without the FormGuard build? did the button name differ?) was invisible. fj
// cannot download the Playwright trace artifact, so the diagnostics are folded
// INTO the thrown error (`attachPageDiagnostics`) the way `auth.spec.ts` does -
// the next run's log carries the currentUrl + urlTrail + request list.
//
// `auth.spec.ts` is re-`fixme`'d (its remaining red is the PMS-148 logout
// redirect, a separate bug) so this spec runs ALONE in the `form-ui` project:
// that drops the suite back to two logins (setup + form-ui), well under the
// 5/min/email cap that rate-limited the earlier two-spec run's retry.
test.describe('form validation (PMS-518 / AC7)', () => {
  // ONE test, ONE login. The suite is rate-limited to 5 logins/min/email
  // (src/modules/auth/routes.rs); `setup` already spends one, so both forms are
  // exercised in a single test rather than a login-per-test beforeEach.
  test('required fields report every error at once and block the submit', async ({ page }) => {
    const diag = attachPageDiagnostics(page);

    try {
      await loginViaSpa(page);

      // --- new-ticket: an empty submit flags every required field at once ---
      // A hard `goto` reboots the WASM SPA; wait for it to settle (it silently
      // re-auths from the persisted OP cookies) before asserting on the form.
      await page.goto('/tickets/new');
      await page.waitForLoadState('domcontentloaded').catch(() => {});
      await page.getByRole('button', { name: 'Create Ticket', exact: true }).click();

      // The PMS-514/518 fix: every missing required field reports together -
      // Title and Description in their own inline slots, Company in the
      // form-level banner (the CompanyPicker has no inline slot).
      await expect(page.getByText('Title is required.')).toBeVisible();
      await expect(page.getByText('Description is required.')).toBeVisible();
      await expect(page.getByText('Please pick a company first.')).toBeVisible();

      // No POST / no navigation - the guard blocked the submit, so we are still
      // on the create form.
      await expect(page).toHaveURL(/\/tickets\/new(\?|$)/);

      // Correcting one field clears only its error (per-field, not a shared
      // banner): filling Title removes its message while the still-empty
      // Description keeps its own.
      await page.locator('input#title').fill('Printer down in suite 200');
      await expect(page.getByText('Title is required.')).toBeHidden();
      await expect(page.getByText('Description is required.')).toBeVisible();

      // --- new-contact: an empty submit flags both name fields at once ---
      await page.goto('/contacts/new');
      await page.waitForLoadState('domcontentloaded').catch(() => {});
      await page.getByRole('button', { name: 'Create Contact', exact: true }).click();

      // First and Last name each get their own inline error (PMS-518 split the
      // old single shared "First and last name are required." banner message).
      await expect(page.getByText('First name is required.')).toBeVisible();
      await expect(page.getByText('Last name is required.')).toBeVisible();
      await expect(page).toHaveURL(/\/contacts\/new(\?|$)/);
    } catch (err) {
      // fj cannot fetch the trace artifact, so surface the URL trail + request
      // list in the thrown error. `cause` keeps Playwright's original matcher
      // detail below the diagnostic dump.
      throw new Error(diag.snapshot('form-validation diagnostic'), { cause: err });
    }
  });
});
