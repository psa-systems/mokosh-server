import { expect, test } from '../lib/fixtures';
import { routes } from '../lib/api';
import { createCompany } from '../lib/factories';
import { runSuffix } from '../lib/run';

// Tickets CRUD (AC coverage area 3), request-context against /api/v1, scoped to
// the E2E tenant by the shared session. A ticket needs a company, so we create
// one first (CreateTicketRequest.company_id is required).
//
// The ticket and its parent company are hard-deleted inline at the end (the
// DELETE /tickets/{id} route landed in PMS-149); global teardown still backstops
// failed runs via the run-suffixed title/name sweep. See e2e/README.md.
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

    // Delete ticket, then company (teardown also sweeps, but verify the path
    // works: the company is undeletable until its ticket is gone).
    const delTicket = await request.delete(routes.ticket(ticket.id));
    expect(delTicket.ok(), `delete ticket -> ${delTicket.status()}`).toBeTruthy();
    const delCompany = await request.delete(routes.company(company.id));
    expect(delCompany.ok(), `delete company -> ${delCompany.status()}`).toBeTruthy();
  });
});
