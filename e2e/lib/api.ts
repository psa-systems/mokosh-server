// Shared API helpers: route constants, PKCE primitives, and OIDC discovery.
//
// The PSA JSON API lives under /api/v1; the OIDC/SSO surface is mounted at the
// deployment root (/oauth2/*, /.well-known/openid-configuration) - see
// crates/mokosh-auth-http/src/router.rs. The `api` Playwright project picks up
// a Bearer token from the setup project (see e2e/lib/auth-state.ts) and the
// custom `test` fixture in e2e/lib/fixtures.ts attaches it as the
// `Authorization` header on every request, so handlers see the same auth path
// the SPA uses (`src/modules/auth/middleware.rs:67,121-127`).

import { createHash, randomBytes } from 'node:crypto';
import type { APIRequestContext } from '@playwright/test';

export const API_V1 = '/api/v1';

export const routes = {
  version: `${API_V1}/version`,
  health: `${API_V1}/health`,
  tickets: `${API_V1}/tickets`,
  ticket: (id: string) => `${API_V1}/tickets/${id}`,
  companies: `${API_V1}/contacts/companies`,
  company: (id: string) => `${API_V1}/contacts/companies/${id}`,
  contacts: `${API_V1}/contacts/contacts`,
  contact: (id: string) => `${API_V1}/contacts/contacts/${id}`,
  tenants: `${API_V1}/tenants`,
  tenant: (id: string) => `${API_V1}/tenants/${id}`,
  authMe: `${API_V1}/auth/me`,
  authLogout: `${API_V1}/auth/logout`,
  oidcDiscovery: '/.well-known/openid-configuration',
} as const;

function base64url(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export interface Pkce {
  verifier: string;
  challenge: string;
  method: 'S256';
}

// RFC 7636 PKCE pair (S256). Verifier is 43-128 chars of base64url.
export function makePkce(): Pkce {
  const verifier = base64url(randomBytes(48));
  const challenge = base64url(createHash('sha256').update(verifier).digest());
  return { verifier, challenge, method: 'S256' };
}

export interface OidcEndpoints {
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint: string;
  jwks_uri: string;
  issuer: string;
}

// Fetch the live discovery document so the token-flow test targets whatever
// endpoints the deployment actually advertises rather than hard-coded paths.
export async function discoverOidc(
  request: APIRequestContext,
  baseURL: string,
): Promise<OidcEndpoints> {
  const res = await request.get(`${baseURL}${routes.oidcDiscovery}`);
  if (!res.ok()) {
    throw new Error(
      `OIDC discovery failed: GET ${routes.oidcDiscovery} -> ${res.status()}`,
    );
  }
  return (await res.json()) as OidcEndpoints;
}

// A throwaway base64url token suitable for `state` / `nonce`.
export function randomToken(): string {
  return base64url(randomBytes(16));
}
