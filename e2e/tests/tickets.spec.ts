import { expect, test } from '@playwright/test';
import { routes } from '../lib/api';
import { createCompany } from '../lib/factories';
import { runSuffix } from '../lib/run';

// Tickets CRUD (AC coverage area 3), request-context against /api/v1, scoped to
// the E2E tenant by the shared session. A ticket needs a company, so we create
// one first (CreateTicketRequest.company_id is required).
//
// The tickets module has no DELETE route, so there is no hard-delete step; the
// parent company is removed in global teardown, and the run-suffixed title lets
// the stale sweep account for the residue. See e2e/README.md.
test.describe('tickets CRUD', () => {
  test('create / read / update / list a ticket', async ({ request }) => {
    const company = await createCompany(request);
    const title = runSuffix();

    // Create.
    const createRes = await request.post(routes.tickets, {
      data: { title, company_id: company.id, description: 'e2e created' },
    });
    expect(createRes.status(), `create ticket failed: ${await createRes.text()}`).toBe(200);
    const ticket = (await createRes.json()) as { id: string; title: string };
    expect(ticket.id).toBeTruthy();
    expect(ticket.title).toBe(title);

    // Read.
    const getRes = await request.get(routes.ticket(ticket.id));
    expect(getRes.status()).toBe(200);
    expect(((await getRes.json()) as { title: string }).title).toBe(title);

    // Update.
    const newTitle = `${title}-updated`;
    const putRes = await request.put(routes.ticket(ticket.id), { data: { title: newTitle } });
    expect(putRes.status(), `update ticket failed: ${await putRes.text()}`).toBe(200);
    expect(((await putRes.json()) as { title: string }).title).toBe(newTitle);

    // List, filtered to our company so the assertion is deterministic.
    const listRes = await request.get(`${routes.tickets}?company_id=${company.id}&per_page=50`);
    expect(listRes.status()).toBe(200);
    const list = (await listRes.json()) as { data: Array<{ id: string }> };
    expect(list.data.map((t) => t.id)).toContain(ticket.id);
  });
});
