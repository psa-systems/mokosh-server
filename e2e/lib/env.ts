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

// Derive the API host from the SPA host by prepending `api.`. The canonical
// staging deploy serves the SPA at `msp.a8n.systems` and the API at
// `api.msp.a8n.systems`. Returns null when the SPA host is already prefixed
// or the URL cannot be parsed.
function deriveApiBase(spaUrl: string): string | null {
  try {
    const u = new URL(spaUrl);
    if (u.hostname.startsWith('api.')) return null;
    return `${u.protocol}//api.${u.hostname}`;
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
  // and the deploy-sync gate all hit this host. Defaults to prepending
  // `api.` to E2E_BASE_URL (so `msp.a8n.systems` -> `api.msp.a8n.systems`);
  // override with E2E_API_BASE_URL when the deployment uses a different
  // naming scheme.
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
  get totpSecret() {
    // Required: the E2E account is expected to have 2FA on, mirroring the
    // production account hardening posture. Setup drives the second factor
    // by generating a TOTP code from this base32 secret (the same string
    // the user originally pasted into their authenticator app when
    // enrolling). See e2e/lib/login.ts for the use.
    return required('E2E_TOTP_SECRET');
  },
  foreignCompanyId: optional('E2E_FOREIGN_COMPANY_ID'),
} as const;

// All env vars the suite cannot run without, in the order an operator
// would reasonably fill them in. Each entry pairs the var name with a
// one-line purpose so the aggregated error message names what each
// missing value is for, not just which key is empty.
const REQUIRED: Array<{ name: string; purpose: string }> = [
  { name: 'E2E_EMAIL', purpose: 'login email of the dedicated E2E account' },
  { name: 'E2E_PASSWORD', purpose: 'password for E2E_EMAIL' },
  { name: 'E2E_TENANT_ID', purpose: 'UUID of the dedicated E2E tenant' },
  { name: 'E2E_OIDC_CLIENT_ID', purpose: 'public OIDC client id for the token-flow test' },
  {
    name: 'E2E_OIDC_REDIRECT_URI',
    purpose: 'redirect_uri registered for E2E_OIDC_CLIENT_ID (must match exactly)',
  },
  {
    name: 'E2E_TOTP_SECRET',
    purpose:
      'base32 TOTP secret for the E2E account, used to compute the second factor',
  },
];

/// Verify every required env var is present and non-empty. Aggregates ALL
/// missing names into a single error so the operator sees the full
/// configuration gap in one round trip instead of fixing-and-rerunning
/// once per missing key. Called from the `preflight` setup project so it
/// runs before any other project's tests.
export function preflightRequiredEnv(): void {
  const missing = REQUIRED.filter(({ name }) => {
    const value = process.env[name];
    return value === undefined || value.trim() === '';
  });
  if (missing.length === 0) return;
  const lines = missing.map(({ name, purpose }) => `  - ${name}: ${purpose}`);
  throw new Error(
    `Missing ${missing.length} required env var(s). Set in e2e/.env (local) or as ` +
      `Forgejo Actions secrets (CI). See e2e/README.md.\n${lines.join('\n')}`,
  );
}
