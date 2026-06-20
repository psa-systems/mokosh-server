import { expect, oidcTest as test } from '../lib/fixtures';
import { discoverOidc, makePkce, randomToken } from '../lib/api';
import { env } from '../lib/env';

// OIDC authorization-code + PKCE flow (AC coverage area 2), driven entirely
// by request context. /oauth2/authorize is supposed to issue a code for an
// already-authenticated OP session; the code is captured from the 302
// Location WITHOUT following the redirect.
//
// PMS-143: uses the `oidcTest` fixture instead of the default `test`. The
// fixture replays the OP session cookies that setup persists to
// `e2e/.auth/op-state.json` via `request.newContext({ storageState })`
// and deliberately omits the bearer header (bunyip's authorize handler
// reads the OP session from the cookie; an inbound bearer with the wrong
// audience would just be noise). Mokosh-server's bunyip-RS verifier is
// covered indirectly by every other api test, so this test is here to
// assert the full OP token-flow contract against staging, not to
// exercise mokosh's RS path.
//
// PMS-435: quarantined (`test.fixme`) - blocked on a server-side bunyip bug,
// not an e2e cookie-forwarding defect. The PMS-434 diagnostic run (#2098)
// proved the OP session cookie is captured and replayed correctly: setup
// logged `KEEP .a8n.systems#bunyip_op_session` and persisted all three OP
// cookies (`access_token, refresh_token, bunyip_op_session`) to
// `op-state.json`, and `oidcTest` loads that storageState into the request
// context. Despite the session cookie being present on the right domain,
// `/oauth2/authorize` still 302s to `/login` with no `state`, so the test
// fails at the `state` assertion ("state mismatch", received null). That
// bounce is bunyip's COOKIE_DOMAIN / `bunyip_op_session` scoping issue tracked
// in BUNYIP-146, not a mokosh-server regression - every other api test and
// staging health pass. Quarantine (same convention as auth.spec.ts / PMS-148)
// so this external blocker stops gating unrelated PRs; un-fixme when
// BUNYIP-146 ships.
test.describe('OIDC token flow', () => {
  test.fixme('authorize -> token -> userinfo -> refresh', async ({ request }) => {
    const oidc = await discoverOidc(request, env.opBaseURL);
    const pkce = makePkce();
    const state = randomToken();
    const nonce = randomToken();

    // 1. /oauth2/authorize: do not follow the redirect; read `code` from Location.
    const authorizeUrl = new URL(oidc.authorization_endpoint);
    authorizeUrl.search = new URLSearchParams({
      response_type: 'code',
      client_id: env.oidcClientId,
      redirect_uri: env.oidcRedirectUri,
      // offline_access is required by the OP to mint a refresh_token (the
      // last leg of this test). See crates/mokosh-auth-oidc/.
      scope: 'openid profile email offline_access',
      state,
      nonce,
      code_challenge: pkce.challenge,
      code_challenge_method: pkce.method,
    }).toString();

    const authRes = await request.get(authorizeUrl.toString(), { maxRedirects: 0 });
    const REDIRECT_STATUSES = [301, 302, 303, 307, 308];
    if (!REDIRECT_STATUSES.includes(authRes.status())) {
      // Surface bunyip's actual rejection so the failure names a root cause
      // instead of just an unexpected status. Most likely causes on a 4xx:
      //   - 400 invalid_request: redirect_uri does not match a value the
      //     OIDC client registered, OR client_id is not a valid UUID, OR
      //     scope omitted `openid`. Bunyip's body includes the specific
      //     error code.
      //   - 400 unknown client_id: the configured `E2E_OIDC_CLIENT_ID` is
      //     not registered on this deploy.
      //   - 302 to `/login?...`: OP session cookie not accepted (the cookie
      //     captured by setup is wrong, expired, or scoped to the wrong
      //     host). Verify setup logged the expected `bunyip_op_session`
      //     cookie domain.
      const body = await authRes.text().catch(() => '(unreadable body)');
      const contentType = authRes.headers()['content-type'] ?? '(no content-type)';
      throw new Error(
        [
          `authorize should 3xx-redirect with a code; got ${authRes.status()}.`,
          `  client_id=${env.oidcClientId}`,
          `  redirect_uri=${env.oidcRedirectUri}`,
          `  content-type=${contentType}`,
          `  body (first 2000 chars):`,
          `    ${body.slice(0, 2000).replace(/\n/g, '\n    ')}`,
        ].join('\n'),
      );
    }

    const location = authRes.headers()['location'];
    expect(location, 'authorize 3xx had no Location header').toBeTruthy();
    const redirected = new URL(location, env.opBaseURL);

    // When authorize 3xx-redirects WITHOUT a `code`, it bounced to an
    // interstitial instead of the registered redirect_uri. A /login and a
    // /consent bounce share the exact same signature (top-level `state`,
    // `code`, and `error` all absent, because the original params live nested
    // inside `return_to`), so the bare "state mismatch" assertion below cannot
    // tell them apart. Name the actual destination here:
    //   - `/login`   => bunyip rejected the bunyip_op_session cookie (session
    //                   missing / expired / revoked).
    //   - `/consent` => session is valid, but a requested scope is not in
    //                   granted_scopes for this (user, client). Since BUNYIP-140
    //                   scopes only reach granted_scopes via /oauth2/consent, a
    //                   non-interactive client that never visited the consent
    //                   screen (e.g. offline_access not pre-granted) lands here.
    // Surface path + param KEYS only; values are redacted because the nested
    // return_to echoes state/nonce. See BUNYIP-146.
    if (!redirected.searchParams.get('code')) {
      const paramKeys = [...redirected.searchParams.keys()].join(',') || '(none)';
      throw new Error(
        `authorize did not return an authorization code; it redirected to ` +
          `${redirected.origin}${redirected.pathname} ` +
          `(param keys: ${paramKeys}; error=${redirected.searchParams.get('error') ?? 'none'}). ` +
          `A /login target => the bunyip_op_session cookie was not accepted; a /consent target => ` +
          `the session is valid but a requested scope is not granted for this client (BUNYIP-146).`,
      );
    }
    expect(
      redirected.searchParams.get('error'),
      `authorize returned error=${redirected.searchParams.get('error')}`,
    ).toBeNull();
    expect(redirected.searchParams.get('state'), 'state mismatch').toBe(state);
    const code = redirected.searchParams.get('code');
    expect(code, 'no authorization code in redirect Location').toBeTruthy();

    // 2. /oauth2/token: authorization_code grant.
    const tokenRes = await request.post(oidc.token_endpoint, {
      form: {
        grant_type: 'authorization_code',
        code: code!,
        redirect_uri: env.oidcRedirectUri,
        client_id: env.oidcClientId,
        code_verifier: pkce.verifier,
      },
    });
    expect(tokenRes.status(), `token exchange failed: ${await tokenRes.text()}`).toBe(200);
    const tokens = (await tokenRes.json()) as {
      access_token: string;
      refresh_token?: string;
      token_type: string;
    };
    expect(tokens.access_token, 'no access_token').toBeTruthy();
    expect(tokens.token_type.toLowerCase()).toBe('bearer');

    // 3. /oauth2/userinfo: bearer-authenticated claims.
    const userinfoRes = await request.get(oidc.userinfo_endpoint, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    expect(userinfoRes.status(), `userinfo failed: ${await userinfoRes.text()}`).toBe(200);
    const claims = (await userinfoRes.json()) as { sub?: string };
    expect(claims.sub, 'userinfo missing sub claim').toBeTruthy();

    // 4. /oauth2/token: refresh_token grant.
    expect(tokens.refresh_token, 'no refresh_token issued (need offline_access?)').toBeTruthy();
    const refreshRes = await request.post(oidc.token_endpoint, {
      form: {
        grant_type: 'refresh_token',
        refresh_token: tokens.refresh_token!,
        client_id: env.oidcClientId,
      },
    });
    expect(refreshRes.status(), `refresh failed: ${await refreshRes.text()}`).toBe(200);
    const refreshed = (await refreshRes.json()) as { access_token?: string };
    expect(refreshed.access_token, 'refresh returned no access_token').toBeTruthy();
  });
});
