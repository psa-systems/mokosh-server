import { expect, test } from '../lib/fixtures';
import { discoverOidc, makePkce, randomToken } from '../lib/api';
import { env } from '../lib/env';

// OIDC authorization-code + PKCE flow (AC coverage area 2), driven entirely by
// request context. Reuses the SPA session from storageState as the OP session
// so /oauth2/authorize issues a code for the already-authenticated E2E user.
// The code is captured from the 302 Location WITHOUT following the redirect.
test.describe('OIDC token flow', () => {
  test('authorize -> token -> userinfo -> refresh', async ({ request }) => {
    const oidc = await discoverOidc(request, env.baseURL);
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
    expect(
      [301, 302, 303, 307, 308],
      `authorize should 3xx-redirect with a code; got ${authRes.status()}. ` +
        `If it redirected to a login screen the OP session was not accepted - ` +
        `provision a dedicated E2E OIDC client (see e2e/README.md).`,
    ).toContain(authRes.status());

    const location = authRes.headers()['location'];
    expect(location, 'authorize 3xx had no Location header').toBeTruthy();
    const redirected = new URL(location, env.baseURL);
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
