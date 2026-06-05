// Centralised env-var access for the E2E suite. Required vars fail loud so a
// misconfigured CI run dies with a clear message instead of a confusing
// mid-test 401.

import { config as loadEnv } from 'dotenv';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Load e2e/.env BEFORE reading process.env so dotenv-only values are visible
// to every consumer. CI injects the same vars from Forgejo secrets, so a
// missing file is fine (override:false keeps real env winning).
const here = dirname(fileURLToPath(import.meta.url));
loadEnv({ path: resolve(here, '..', '.env'), override: false });

function required(name: string): string {
  const value = process.env[name];
  if (value === undefined || value.trim() === '') {
    throw new Error(
      `Missing required env var ${name}. Set it in e2e/.env (local) or as a ` +
        `Forgejo Actions secret (CI). See e2e/README.md.`,
    );
  }
  return value.trim();
}

function optional(name: string): string | undefined {
  const value = process.env[name];
  return value === undefined || value.trim() === '' ? undefined : value.trim();
}

// Derive the API host from the SPA host the same way the SPA itself does
// (`mokosh-clients/src/hooks/fetch.rs`): `msp.<rest>` -> `msp-api.<rest>`.
// Returns null when no derivation applies (a custom hostname or localhost).
function deriveApiBase(spaUrl: string): string | null {
  try {
    const u = new URL(spaUrl);
    if (u.hostname.startsWith('msp.')) {
      const rest = u.hostname.slice('msp.'.length);
      return `${u.protocol}//msp-api.${rest}`;
    }
    return null;
  } catch {
    return null;
  }
}

const spaBaseURL = optional('E2E_BASE_URL') ?? 'https://msp.a8n.systems';
const derivedApi = deriveApiBase(spaBaseURL);
const apiBaseURL = optional('E2E_API_BASE_URL') ?? derivedApi ?? spaBaseURL;

export const env = {
  // Where a human browser hits the SPA (login form, dashboard). The auth-ui
  // project navigates here.
  baseURL: spaBaseURL,
  // Where the JSON API and OIDC endpoints live. The api project, teardown,
  // and the deploy-sync gate all hit this host. Defaults to the canonical
  // `msp-api.<tld>` derivation; override with E2E_API_BASE_URL when the
  // deployment is not on a `msp.*` SPA host.
  apiBaseURL,
  get email() {
    return required('E2E_EMAIL');
  },
  get password() {
    return required('E2E_PASSWORD');
  },
  get tenantId() {
    return required('E2E_TENANT_ID');
  },
  get oidcClientId() {
    return required('E2E_OIDC_CLIENT_ID');
  },
  get oidcRedirectUri() {
    // Required: OIDC clients are registered with specific callback paths.
    // Defaulting to the bare deployment root produced invalid_redirect_uri
    // either at /oauth2/authorize or at /oauth2/token. Force the operator
    // to set a registered URI explicitly.
    return required('E2E_OIDC_REDIRECT_URI');
  },
  foreignCompanyId: optional('E2E_FOREIGN_COMPANY_ID'),
} as const;
