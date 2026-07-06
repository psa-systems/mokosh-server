import { authenticator } from 'otplib';
import { expect, type APIRequestContext, type Locator, type Page } from '@playwright/test';
import { env } from './env';
import { routes } from './api';

// Drive the staging SPA login form to establish a real session.
//
// The form markup is owned by the bunyip hub (the SPA redirects to it), not
// this repo. Selectors are scoped to a `<form>` ancestor and prefer
// `data-testid` hooks the hub exposes, falling back to standard input types.
// The post-login proof is DOM-based (URL navigates fully out of the /login
// flow) because the SPA holds its access token in WASM memory and there is
// no DOM-accessible session for an external request context to reuse - see
// e2e/lib/auth-state.ts.
//
// The E2E account has 2FA enabled (matching the production hardening
// posture). After credentials submit, the hub redirects to `/login/2fa` and
// the helper enters a TOTP code derived from `E2E_TOTP_SECRET`. The poll
// uses `/^\/login(\/|$)/` so multi-step flows count as IN /login and the
// helper only returns once the hub has actually let us through.
export async function loginViaSpa(page: Page): Promise<void> {
  await page.goto('/login');

  await submitCredentials(page);

  // Wait for the hub to land on the next page. /login/2fa is the expected
  // step for an MFA-enabled account; anything else (success or error) flows
  // through to the URL-out-of-/login poll below.
  await page
    .waitForURL(/\/login\/(2fa|mfa)(\/|$|\?)/, { timeout: 15_000 })
    .catch(() => {});
  if (/^\/login\/(2fa|mfa)/.test(new URL(page.url()).pathname)) {
    await fillTotpStep(page);
  }

  // The SPA + hub navigate fully out of the /login path family on success - but
  // the OP first routes the post-2FA authorize through `/oauth2/consent` when the
  // E2E account has un-granted scopes (PMS-521: `profile` is in the request and
  // the account had not consented to it, so authorize 302s to consent and loops
  // forever, the token exchange never fires, and setup captures no bearer). Click
  // Allow there so the grant is POSTed and persists server-side; subsequent
  // authorize calls then skip consent and the SPA completes login. Mirrors
  // bunyip's e2e `driveConsent` and `bunyip-web/src/handlers/consent.rs` (the
  // Allow control is `button[name="action"][value="allow"]`).
  //
  // Match anything under /login (multi-step flows like /login/2fa, /login/mfa,
  // /login/recovery) as STILL in the login flow. A previous CI run got past a
  // narrower check while sitting on /login/2fa and thrashed for 30s capturing a
  // bearer no successful login had produced.
  const deadline = Date.now() + 30_000;
  let lastPath = '';
  for (;;) {
    lastPath = new URL(page.url()).pathname;
    if (/^\/oauth2\/consent(\/|$)/.test(lastPath)) {
      const allow = page
        .locator('button[name="action"][value="allow"]')
        .or(page.getByRole('button', { name: /^(allow|authorize|approve)$/i }))
        .first();
      await allow.click({ timeout: 10_000 }).catch(() => {});
      await page.waitForLoadState('domcontentloaded', { timeout: 10_000 }).catch(() => {});
      continue;
    }
    if (!/^\/login(\/|$)/.test(lastPath)) {
      return; // out of /login and past any consent -> in the app
    }
    if (Date.now() > deadline) {
      break;
    }
    await page.waitForTimeout(250);
  }
  throw new Error(
    'SPA login never navigated away from the /login or /oauth2/consent flow ' +
      `(30s timeout; last path: ${lastPath}). If stuck on /oauth2/consent the ` +
      'Allow control may have moved - check bunyip-web/src/handlers/consent.rs.',
  );
}

// Set a login input's value via a direct DOM assignment instead of Playwright
// `fill()`. On the CI runner's headless chromium, `fill()` is a no-op on the
// bunyip hub login inputs - the value never sticks, so the "re-render race"
// guards below never had anything to submit and the credential step spun until
// timeout (the real cause behind PMS-592 / PMS-595; proven by the BUNYIP-168
// probe). A DOM `el.value = ...` assignment works and persists, and the native
// hub form serializes each input's `.value` on submit, so a DOM-set value is
// POSTed correctly. Retries in case the value lands in a form frame that is
// about to be replaced.
async function setInputValue(loc: Locator, value: string): Promise<void> {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    await loc.evaluate((el, v) => {
      const input = el as HTMLInputElement;
      input.value = v as string;
      input.dispatchEvent(new Event('input', { bubbles: true }));
      input.dispatchEvent(new Event('change', { bubbles: true }));
    }, value);
    if ((await loc.inputValue()) === value) return;
    await loc.page().waitForTimeout(200);
  }
  throw new Error(
    `login field value did not stick after a DOM set (holds ${(await loc.inputValue()).length} chars, expected ${value.length})`,
  );
}

// Fill the bunyip hub's credential form and submit it, recovering from the
// race where the server-rendered form re-renders (htmx / a redirect) between
// `fill` and `click`. On chromium that race cleared the inputs, so the click
// POSTed an EMPTY form; the hub rejected it and 302'd back to a fresh
// `/login`, the SPA login never reached `/login/2fa`, and the helper polled a
// never-submitted form until the 30s timeout (PMS-592, run 2871: `setup`
// logged in fine on Desktop Chrome 2s earlier, then form-validation - same
// helper, same engine - sat on a bare `/login`). firefox/webkit won the race
// and passed. The guard: confirm the typed values survived right before
// submitting, then confirm the credential step was actually consumed (the
// password field leaves the DOM as the hub advances to 2FA / onward). If
// either check fails, the form was re-rendered out from under us, so re-fill
// the freshly-rendered form and submit again.
//
// PMS-595 (run 2874): the PMS-592 "verify the values stuck right before the
// click" guard was still insufficient on chromium - the swap landed in the
// window between the click and the POST being serialised, so the body still
// went out empty and re-filling into a form that was mid-re-render lost the
// next attempt the same way. Two changes close it: (1) let the form settle
// before each fill (drain in-flight network from the hub's hydration / htmx
// swap on a short budget, then give a synchronous client re-render a frame to
// land) so we type into the form the hub will actually submit, not one a frame
// from being replaced; and (2) treat the credential step as consumed on EITHER
// the password field detaching OR the URL advancing into the 2FA step, since on
// chromium the post-submit DOM teardown and the navigation do not always land
// in the same order.
async function submitCredentials(page: Page): Promise<void> {
  const maxAttempts = 4;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const form = page.locator('form').first();
    const email = form
      .locator(
        'input[data-testid="email"], input[type="email"], input[name="email"], input[autocomplete="username"]',
      )
      .first();
    const password = form
      .locator(
        'input[data-testid="password"], input[type="password"], input[name="password"], input[autocomplete="current-password"]',
      )
      .first();

    await email.waitFor({ state: 'visible', timeout: 15_000 });

    // Let the form settle before filling. The hub form is server-rendered and
    // chromium re-renders it (hydration / htmx swap) shortly after it first
    // paints and again after a rejected submit; filling a form a frame from
    // being replaced loses the input. Drain in-flight network on a short budget
    // (the swap's fetch), then give a synchronous client re-render a frame.
    await page.waitForLoadState('networkidle', { timeout: 3_000 }).catch(() => {});
    await page.waitForTimeout(300);

    await setInputValue(email, env.email);
    await setInputValue(password, env.password);

    // A re-render between the fills and the click would silently clear the
    // inputs; submitting then POSTs an empty form. Verify the values stuck
    // before clicking, and if they did not, re-fill on the next iteration.
    const stuck = await Promise.all([
      expect(email).toHaveValue(env.email, { timeout: 2_000 }),
      expect(password).toHaveValue(env.password, { timeout: 2_000 }),
    ]).then(
      () => true,
      () => false,
    );
    if (!stuck) {
      continue;
    }

    await form
      .getByRole('button', { name: /sign ?in|log ?in|continue|submit/i })
      .first()
      .click();

    // A successful submit takes the hub off the credentials step: the password
    // field detaches (navigation to /login/2fa or onward) and the URL moves into
    // the 2FA step. Accept EITHER signal - on chromium the post-submit DOM
    // teardown and the navigation do not always land in the same order, and a
    // transient empty re-render can briefly leave a visible password field while
    // the navigation is already under way. `state: 'hidden'` resolves on both
    // detach and invisibility, so it covers the navigate-away and the
    // empty-re-render cases. If neither fires the submit was swallowed or the hub
    // bounced back to a fresh credentials form, so retry the fill+submit; each
    // boolean settles to `true` only on success and `false` only at its own
    // timeout, so the race never resolves `false` early.
    const advanced = await Promise.race([
      password.waitFor({ state: 'hidden', timeout: 8_000 }).then(
        () => true,
        () => false,
      ),
      page.waitForURL(/\/login\/(2fa|mfa)(\/|$|\?)/, { timeout: 8_000 }).then(
        () => true,
        () => false,
      ),
    ]);
    if (advanced) {
      return;
    }
  }
  throw new Error(
    'SPA login could not get past the bunyip hub credentials step: the form ' +
      'kept re-rendering with empty fields after submit (PMS-592). Check the ' +
      'hub login markup / selectors in e2e/lib/login.ts.',
  );
}

// Compute the current TOTP code from E2E_TOTP_SECRET (RFC 6238, 30s window,
// 6 digits, SHA-1 - the otplib defaults match the mokosh-auth-crypto totp
// module). Fill it into the 2FA form and submit. Selectors are deliberately
// permissive because the hub's markup may evolve; the regex on the submit
// button covers "Verify" copy in addition to the standard login verbs.
async function fillTotpStep(page: Page): Promise<void> {
  const code = authenticator.generate(env.totpSecret);
  const form = page.locator('form').first();
  const codeInput = form
    .locator(
      'input[data-testid="totp"], ' +
        'input[autocomplete="one-time-code"], ' +
        'input[name="code"], ' +
        'input[name="otp"], ' +
        'input[name="totp"], ' +
        'input[inputmode="numeric"]',
    )
    .first();
  await codeInput.waitFor({ state: 'visible', timeout: 10_000 });
  await setInputValue(codeInput, code);
  // The bunyip hub auto-submits the 2FA form the instant the code reaches six
  // digits (BUNYIP-331 OTP autosubmit). `setInputValue` dispatches an `input`
  // event, which fires that autosubmit, so the form is usually already
  // navigating to the OIDC callback by the time we get here and the submit
  // button is detached. Click only as a fallback (for the case where autosubmit
  // did not fire) and race it against the navigation off the 2FA step, so the
  // happy autosubmit path never hangs waiting on a vanished button.
  const submit = form
    .getByRole('button', { name: /verify|continue|submit|sign ?in|log ?in/i })
    .first();
  await Promise.race([
    submit.click().catch(() => {}),
    page.waitForURL((url) => !url.pathname.endsWith('/login/2fa'), {
      timeout: 15_000,
    }),
  ]);
}

// An authenticated session can read the tenant-scoped tickets list (200); an
// anonymous one is rejected (401/403). Cheapest universal session proof.
export async function expectAuthenticated(request: APIRequestContext): Promise<void> {
  const res = await request.get(`${routes.tickets}?per_page=1`);
  expect(res.status(), `GET ${routes.tickets} should be 200 when authenticated`).toBe(200);
}

export async function expectAnonymous(request: APIRequestContext): Promise<void> {
  const res = await request.get(`${routes.tickets}?per_page=1`);
  expect(
    [401, 403],
    `GET ${routes.tickets} should be 401/403 when logged out, got ${res.status()}`,
  ).toContain(res.status());
}

// Browser-driven "logged out" proof: the SPA bounces back to /login when the
// session is gone. Used by the auth-ui project so it never touches a request
// context (which would need its own bearer token). Logout redirects through
// the bunyip hub's /logout (cross-origin POST + Set-Cookie + redirect to the
// hub's /login), so the wait budget covers that round-trip. Match any
// /login* path so an intermediate hub step (e.g. consent screen) still
// counts as "back at login".
export async function expectAtLoginScreen(page: Page): Promise<void> {
  await expect
    .poll(() => new URL(page.url()).pathname, {
      timeout: 30_000,
      message: 'expected SPA/hub to navigate to /login after logout',
    })
    .toMatch(/^\/login(\/|$)/);
}
