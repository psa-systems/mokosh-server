import { expect, test, type Page } from '@playwright/test';
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
// NAVIGATION MUST BE IN-APP (router link clicks), NOT `page.goto`. A hard
// `goto('/tickets/new')` reboots the WASM app, which wipes the in-memory bearer;
// the app then silently re-auths from the persisted OP cookies and its
// `/auth/callback` lands on the DEFAULT route (`/dashboard`), dropping the
// deep-linked path entirely. PMS-519 run 2531 proved this: after
// `goto('/tickets/new')` the page sat on `/dashboard` and `Create Ticket` never
// appeared. Clicking the sidebar + list-page router `Link`s keeps the single
// WASM instance alive, so the bearer survives and the requested route renders.
// (The deep-link-drops-route behaviour is a separate SPA bug, tracked apart
// from this spec.)
//
// `attachPageDiagnostics` folds the URL trail + request list into any thrown
// error - fj cannot download the Playwright trace artifact, so this is the only
// way to see the failure mode in CI logs. `auth.spec.ts` is `test.fixme` (its
// remaining red is the PMS-148 logout redirect), so this spec runs ALONE in the
// `form-ui` project: two logins total (setup + form-ui), under the 5/min/email
// cap.
// In-app sidebar/list navigation. Firefox paints the post-WASM-nav DOM more
// slowly than Chromium/WebKit, so a bare `.click()` on its default action
// timeout could miss the link before it rendered (PMS-543, run 2782:
// `a[href="/tickets"]` "never visible" on firefox while chromium/webkit pass).
// Wait for the `:visible` instance explicitly first - the same 15s visibility
// wait the Create buttons below already use. The `:visible` + `.first()`
// semantics are unchanged (see the load-bearing note inside the test).
async function navClick(page: Page, href: string): Promise<void> {
  const link = page.locator(`a[href="${href}"]:visible`).first();
  await link.waitFor({ state: 'visible', timeout: 15_000 });
  await link.click();
}

test.describe('form validation (PMS-518 / AC7)', () => {
  // ONE test, ONE login. The suite is rate-limited to 5 logins/min/email
  // (src/modules/auth/routes.rs); `setup` already spends one, so both forms are
  // exercised in a single test rather than a login-per-test beforeEach.
  test('required fields report every error at once and block the submit', async ({ page }) => {
    const diag = attachPageDiagnostics(page);

    try {
      await loginViaSpa(page);

      // --- new-ticket: an empty submit flags every required field at once ---
      // In-app nav: sidebar Tickets -> list "New Ticket" -> the create form.
      // `:visible` is load-bearing: the layout renders the sidebar TWICE - a
      // mobile drawer (`lg:hidden`, so `display:none` at the Desktop Chrome
      // 1280px viewport) that is DOM-first, and the desktop sidebar
      // (`hidden lg:flex`, visible). A bare `.first()` grabbed the hidden
      // drawer and timed out (run 2534). `:visible` picks the desktop instance;
      // `.first()` then guards the list page rendering the New-X affordance
      // twice (header action + empty-state CTA).
      await navClick(page, '/tickets');
      await navClick(page, '/tickets/new');
      const createTicket = page.getByRole('button', { name: 'Create Ticket', exact: true });
      await createTicket.waitFor({ state: 'visible', timeout: 15_000 });
      await createTicket.click();

      // The PMS-514/518 fix: every missing required field reports together -
      // Title, Description, and Company each in their own inline slot. MAPPS-322
      // routed the missing-company error into the CompanyPicker's own inline
      // slot (it now takes an `error:` prop), so it reads "Company is required."
      // from the shared `Rule::Required` message - matching the Title/Description
      // copy - instead of the old form-level "Please pick a company first." banner.
      await expect(page.getByText('Title is required.')).toBeVisible();
      await expect(page.getByText('Description is required.')).toBeVisible();
      await expect(page.getByText('Company is required.')).toBeVisible();

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
      await navClick(page, '/contacts');
      await navClick(page, '/contacts/new');
      const createContact = page.getByRole('button', { name: 'Create Contact', exact: true });
      await createContact.waitFor({ state: 'visible', timeout: 15_000 });
      await createContact.click();

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
