import { expect, test } from '@playwright/test';
import { loginViaSpa } from '../lib/login';

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
// Un-fixme'd in PMS-519 now that its two preconditions are believed met: (1) the
// PMS-518 FormGuard migration is fully merged to mokosh-apps `main` (so staging
// serves it after its redeploy), and (2) PMS-148 (the post-`setup` browser-login
// stall this spec's `loginViaSpa` shares) is resolved. If the CI run against
// staging shows a login stall, PMS-148 has regressed; if it shows the OLD
// single-error / no-validation behaviour, the staging SPA has not yet redeployed
// the FormGuard build (check the `[setup] spaBundles` diagnostic) - re-`fixme`
// either way and re-open the relevant blocker.
test.describe('form validation (PMS-518 / AC7)', () => {
  // ONE test, ONE login. The suite is rate-limited to 5 logins/min/email
  // (src/modules/auth/routes.rs) and `setup` + `auth-ui` already spend logins,
  // so both forms are exercised in a single test rather than a login-per-test
  // beforeEach - a per-test login here would trip the cap when un-fixme'd.
  test('required fields report every error at once and block the submit', async ({ page }) => {
    await loginViaSpa(page);

    // --- new-ticket: an empty submit flags every required field at once ---
    await page.goto('/tickets/new');
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
    await page.getByRole('button', { name: 'Create Contact', exact: true }).click();

    // First and Last name each get their own inline error (PMS-518 split the
    // old single shared "First and last name are required." banner message).
    await expect(page.getByText('First name is required.')).toBeVisible();
    await expect(page.getByText('Last name is required.')).toBeVisible();
    await expect(page).toHaveURL(/\/contacts\/new(\?|$)/);
  });
});
