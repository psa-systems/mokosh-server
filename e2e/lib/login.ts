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
  // The E2E account shares one email, and the bunyip hub rate-limits login at 5
  // requests / 60s PER EMAIL (bunyip RateLimitConfig::LOGIN, checked BEFORE
  // credential verification). The former helper retried the fill+submit up to 4x
  // on ONE page load with no backoff, firing four login POSTs in seconds and
  // blowing that window; the hub then re-rendered /login with a rate-limit banner
  // for every further POST, which the loop misread as a form-re-render race and
  // retried harder - a self-reinforcing failure that swallowed the hub's actual
  // reason (PMS-654; the hub was verified frozen and healthy, not a regression).
  // Instead: submit ONCE per attempt, read the hub's rendered error banner, and
  // only retry after waiting out the interval the hub names on a rate-limit
  // rejection. Fail fast, surfacing the banner text, on any other rejection so
  // bad credentials or a stalled POST (PMS-148) are self-diagnosing in the log.
  // Each attempt does a fresh `goto('/login')`, so the re-render race is still
  // covered by a clean reload rather than a same-page re-POST burst.
  const maxAttempts = 4;
  for (let attempt = 1; ; attempt += 1) {
    await page.goto('/login');
    const outcome = await submitCredentialsOnce(page);
    if (outcome === 'advanced') break;

    // Retry on a rate-limit rejection (after the named backoff) or on an unclear
    // submit (no banner and no navigation: a stalled POST or a fill lost to a
    // re-render), but never on a definite credential rejection.
    const backoffMs = rateLimitBackoffMs(outcome);
    const retryable = backoffMs !== null || outcome === null;
    if (retryable && attempt < maxAttempts) {
      if (backoffMs !== null) {
        await page.waitForTimeout(backoffMs);
      }
      continue;
    }
    throw new Error(
      'SPA login was rejected at the bunyip hub credentials step ' +
        `(attempt ${attempt}/${maxAttempts}, path ${new URL(page.url()).pathname})` +
        (outcome
          ? `: "${outcome}"`
          : ' - no error banner and no navigation; the submit may not have POSTed ' +
            '(PMS-148) or the form was re-rendered out from under the fill.') +
        ' See PMS-654.',
    );
  }

  // Credentials accepted. Enter the TOTP code if the hub advanced to the 2FA step
  // for this MFA-enabled account.
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
    // BUNYIP-331: bunyip-web ships a six-digit TOTP auto-submit that fires on
    // the bubbling `input` event above, so the `#code` field on `/login/2fa`
    // detaches as `form.requestSubmit()` navigates the page. This readback
    // then hits Playwright's default 180s action timeout waiting for an
    // element that will never re-attach on `/dashboard`. Bound the readback
    // to 500ms and treat a detach as "write took, form has already
    // submitted"; the 5-attempt retry loop remains honest for the email +
    // password fields (no auto-submit, no detach).
    let current: string;
    try {
      current = await loc.inputValue({ timeout: 500 });
    } catch {
      return;
    }
    if (current === value) return;
    await loc.page().waitForTimeout(200);
  }
  throw new Error(
    `login field value did not stick after a DOM set (holds ${(await loc.inputValue()).length} chars, expected ${value.length})`,
  );
}

// Fill the bunyip hub credential form and submit it ONCE, then classify what
// happened: 'advanced' when the hub accepted the credentials and moved to the
// 2FA step (or otherwise left the bare /login credentials page), the hub's
// rendered error-banner text on a rejection (a rate-limit message or "The email
// or password you entered is incorrect."), or null when neither a banner nor a
// navigation appeared within the budget (a stalled POST / PMS-148, or a fill
// lost to a re-render). The caller (loginViaSpa) decides whether to back off and
// retry. Assumes the page is freshly on /login. Submitting once - rather than
// re-POSTing up to 4x on the same page - is what keeps the login under the hub's
// 5/min per-email rate limit (PMS-654).
async function submitCredentialsOnce(page: Page): Promise<'advanced' | string | null> {
  const form = page.locator('form[action="/login"]').first();
  const email = form
    .locator(
      'input#email, input[data-testid="email"], input[type="email"], input[name="email"], input[autocomplete="username"]',
    )
    .first();
  const password = form
    .locator(
      'input#password, input[data-testid="password"], input[type="password"], input[name="password"], input[autocomplete="current-password"]',
    )
    .first();

  await email.waitFor({ state: 'visible', timeout: 15_000 });

  // Let the server-rendered form settle before filling (drain the hub's
  // hydration / any htmx swap on a short budget, then give a synchronous
  // re-render a frame) so we type into the form the hub will actually submit.
  await page.waitForLoadState('networkidle', { timeout: 3_000 }).catch(() => {});
  await page.waitForTimeout(300);

  await setInputValue(email, env.email);
  await setInputValue(password, env.password);

  // A re-render between the fills and the click would silently clear the inputs
  // and POST an empty form. If the values did not survive to just before the
  // click, report an unclear submit (null) so the caller reloads and retries
  // rather than POSTing blanks (which the hub would reject as bad credentials).
  const stuck = await Promise.all([
    expect(email).toHaveValue(env.email, { timeout: 2_000 }),
    expect(password).toHaveValue(env.password, { timeout: 2_000 }),
  ]).then(
    () => true,
    () => false,
  );
  if (!stuck) {
    return null;
  }

  await form
    .getByRole('button', { name: /sign ?in|log ?in|continue|submit/i })
    .first()
    .click();

  // Race the hub's next state: a redirect to the 2FA step (credentials accepted)
  // against the error banner becoming visible (rejected). Racing surfaces a
  // rejection in ~1s instead of waiting out the full 2FA timeout, keeping each
  // attempt cheap enough for the backoff loop to retry within the test budget.
  const reach2fa = page
    .waitForURL(/\/login\/(2fa|mfa)(\/|$|\?)/, { timeout: 15_000 })
    .then(() => 'advanced' as const)
    .catch(() => 'timeout' as const);
  const earlyError = page
    .locator('.text-destructive')
    .first()
    .waitFor({ state: 'visible', timeout: 15_000 })
    .then(() => 'error' as const)
    .catch(() => 'timeout' as const);
  await Promise.race([reach2fa, earlyError]);

  const path = (): string => new URL(page.url()).pathname;
  if (/^\/login\/(2fa|mfa)/.test(path())) {
    return 'advanced';
  }
  // Not on 2FA: a rendered banner is the rejection reason; otherwise, if the
  // flow already left the bare /login credentials page, treat it as advanced.
  const banner = await readLoginError(page);
  if (banner) {
    return banner;
  }
  if (!/^\/login\/?$/.test(path())) {
    return 'advanced';
  }
  return null;
}

// Read the hub's login error banner (`.text-destructive`, bunyip-web
// views/ui.rs error_box) into a single-line string, or null when none is
// rendered. The box holds an icon (svg, no text) plus the message, so innerText
// is the message.
async function readLoginError(page: Page): Promise<string | null> {
  try {
    const box = page.locator('.text-destructive').first();
    if ((await box.count()) === 0) {
      return null;
    }
    const text = (await box.innerText()).trim().replace(/\s+/g, ' ');
    return text.length > 0 ? text : null;
  } catch {
    return null;
  }
}

// Classify a login error banner as a rate-limit rejection and return the backoff
// to wait before resubmitting (ms), or null when the reason is NOT the rate
// limit (so the caller fails fast on a real credential error). The hub renders
// "Too many requests. Please wait N seconds and try again."; parse N, add a 1s
// cushion for the window boundary, and cap at the 60s login window. Defaults to
// 5s when no count is rendered.
function rateLimitBackoffMs(reason: string | null): number | null {
  if (!reason || !/too many|rate.?limit/i.test(reason)) {
    return null;
  }
  const match = reason.match(/(\d+)\s*second/i);
  const seconds = match ? Number(match[1]) : 5;
  return Math.min(seconds, 60) * 1_000 + 1_000;
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
  // BUNYIP-331: bunyip-web auto-submits the six-digit TOTP form the moment
  // the input event fires (data-otp-autosubmit snippet). setInputValue's
  // bubbling `input` event triggers that path, so the page usually navigates
  // off /login/2fa before we can click the submit button below. Wait for the
  // URL to leave the 2fa step; only click as a fallback if the auto-submit
  // did not fire, so we never double-POST (a second submit trips the per-IP
  // 2fa_verify rate limit and burns the current TOTP step). Mirrors the
  // matching helper in bunyip's own e2e (login.ts:238).
  await setInputValue(codeInput, code);
  const autoSubmitted = await page
    .waitForURL((url) => !/\/login\/(2fa|mfa)(\/|$|\?)/.test(url.pathname), { timeout: 15_000 })
    .then(() => true)
    .catch(() => false);
  if (!autoSubmitted) {
    await form
      .getByRole('button', { name: /verify|continue|submit|sign ?in|log ?in/i })
      .first()
      .click();
  }
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
