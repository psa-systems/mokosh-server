// Centralised env-var access for the E2E suite. Required vars fail loud so a
// misconfigured CI run dies with a clear message instead of a confusing
// mid-test 401.

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

export const env = {
  baseURL: optional('E2E_BASE_URL') ?? 'https://msp.a8n.systems',
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
