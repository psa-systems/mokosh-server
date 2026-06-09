import { expect, test } from '../lib/fixtures';
import { routes } from '../lib/api';
import { enableModule } from '../lib/factories';

// Reports read smoke (PMS-155). Reports are read-only aggregations behind the
// tenant-gated `reports` module (enabled first). Every endpoint returns 200
// with no mandatory params (date ranges default to the last 30 days; billing
// additionally needs a manager role, which the E2E admin has). Nothing is
// created, so there is no residue to clean up.
test.describe('reports read smoke', () => {
  test('report endpoints respond', async ({ request }) => {
    await enableModule(request, 'reports');

    for (const path of [
      routes.reports,
      routes.reportDashboard,
      routes.reportTickets,
      routes.reportTime,
      routes.reportBilling,
    ]) {
      const res = await request.get(path);
      expect(res.status(), `GET ${path} -> ${res.status()}`).toBe(200);
    }

    // CSV export of the dashboard report.
    const csv = await request.get(`${routes.reportExport('dashboard')}?format=csv`);
    expect(csv.status(), `export dashboard csv -> ${csv.status()}`).toBe(200);
  });
});
