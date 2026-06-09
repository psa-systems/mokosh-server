import { expect, test } from '../lib/fixtures';
import { routes } from '../lib/api';
import { enableModule } from '../lib/factories';

// Dispatch board read smoke (PMS-155). The dispatch view aggregates
// appointments, availability, time-off, and on-call coverage for a date range.
// It is served under the tenant-gated `calendar` module (enabled first) and
// REQUIRES both `from` and `to` RFC 3339 query params (it 400s without them).
// Read-only, so there is no residue to clean up.
test.describe('dispatch board', () => {
  test('aggregated board responds for a date range', async ({ request }) => {
    await enableModule(request, 'calendar');

    const from = new Date().toISOString();
    const to = new Date(Date.now() + 86_400_000).toISOString();
    const res = await request.get(
      `${routes.dispatch}?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`,
    );
    expect(res.status(), `dispatch board -> ${res.status()}`).toBe(200);
  });
});
