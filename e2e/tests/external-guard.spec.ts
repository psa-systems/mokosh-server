import { expect, test } from '@playwright/test';

// PMS-608: canary + mechanical guard for the production external-service
// exclusion.
//
// `@external` is the marker for any test that requires Stripe or another
// external service (real Stripe customers/subscriptions, outbound mail/SMS, a
// live payment gateway, etc.). The production E2E run in
// `.forgejo/workflows/e2e.yml` excludes the `@external` set with
// `--grep-invert @external`, so on production these tests do NOT run. On staging
// (and local / PR / push) they DO run.
//
// This spec is itself tagged `@external` and does double duty:
//   1. It makes the exclusion demonstrable - `playwright test --grep-invert
//      @external --list` drops it, proving the gate filters `@external` tests.
//   2. It mechanically enforces the gate: if the `--grep-invert @external`
//      filter is ever removed from the production dispatch (or a real
//      `@external` test is run against prod without David's sign-off), this
//      test executes against production, reads E2E_ENVIRONMENT=production, and
//      FAILS - turning the prod run red instead of silently letting an
//      external-touching test hit prod.
//
// It intentionally depends on nothing but E2E_ENVIRONMENT (no auth, no tenant),
// so the guard fires even before the auth-dependent projects would.
test.describe('external-service exclusion guard', () => {
  test(
    'external-tagged tests never run against production',
    { tag: '@external' },
    async () => {
      const environment = process.env.E2E_ENVIRONMENT ?? 'unknown';
      expect(
        environment,
        'An @external-tagged test executed against production. Production E2E ' +
          'runs must not touch Stripe or other external services. Restore the ' +
          '`--grep-invert @external` gate in .forgejo/workflows/e2e.yml, or, if ' +
          'this external flow must run on prod, get David\'s sign-off and run it ' +
          'manually. See e2e/README.md "Production-safe subset".',
      ).not.toBe('production');
    },
  );
});
