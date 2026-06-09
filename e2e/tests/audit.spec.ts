import { expect, test } from '../lib/fixtures';
import { routes } from '../lib/api';
import { createCompany } from '../lib/factories';

// Audit-log read (PMS-155). The audit log is read-only (rows are written by the
// service/middleware on successful mutations, not by a create endpoint), and
// the list route is admin-only. The spec performs a real mutation - creating a
// company - then asserts the audit log surfaces a matching `create` entry for
// it, exercising the audit write+read path end to end. The company is cleaned
// up inline; its delete produces a further audit row, which is fine.
test.describe('audit log', () => {
  test('a company create is recorded and readable', async ({ request }) => {
    const company = await createCompany(request);

    // The contacts service writes the audit row in the same transaction as the
    // insert, so the entry is queryable immediately. Filter by entity + action
    // (there is no entity_id filter) and scan the page for our company.
    const res = await request.get(
      `${routes.auditLog}?entity_type=companies&action=create&per_page=100`,
    );
    expect(res.status(), `read audit log -> ${res.status()}`).toBe(200);
    const rows = ((await res.json()) as {
      data: Array<{ entity_type: string; action: string; entity_id: string | null }>;
    }).data;
    expect(
      rows.some((r) => r.entity_id === company.id && r.action === 'create'),
      `audit log missing create entry for company ${company.id}`,
    ).toBeTruthy();

    // Cleanup.
    const del = await request.delete(routes.company(company.id));
    expect(del.ok(), `delete company -> ${del.status()}`).toBeTruthy();
  });
});
