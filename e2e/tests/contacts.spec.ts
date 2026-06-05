import { randomUUID } from 'node:crypto';
import { expect, test } from '../lib/fixtures';
import { routes } from '../lib/api';
import { env } from '../lib/env';
import { createCompany, createContact } from '../lib/factories';
import { runSuffix } from '../lib/run';

// Contacts + tenants coverage (AC coverage area 4): tenant-scoped CRUD smoke
// plus the cross-tenant leak canary.
test.describe('contacts CRUD', () => {
  test('company + contact create / read / update / list / delete', async ({ request }) => {
    const company = await createCompany(request);

    // Read company.
    const getCompany = await request.get(routes.company(company.id));
    expect(getCompany.status()).toBe(200);

    // Update company name.
    const newName = `${runSuffix()}-renamed`;
    const putCompany = await request.put(routes.company(company.id), { data: { name: newName } });
    expect(putCompany.status(), `update company failed: ${await putCompany.text()}`).toBe(200);
    expect(((await putCompany.json()) as { name: string }).name).toBe(newName);

    // Create + read + list contact.
    const contact = await createContact(request, company.id);
    const getContact = await request.get(routes.contact(contact.id));
    expect(getContact.status()).toBe(200);

    const listContacts = await request.get(`${routes.contacts}?company_id=${company.id}&per_page=50`);
    expect(listContacts.status()).toBe(200);
    const contactList = (await listContacts.json()) as { data: Array<{ id: string }> };
    expect(contactList.data.map((c) => c.id)).toContain(contact.id);

    // Delete contact, then company (teardown also sweeps, but verify the path works).
    const delContact = await request.delete(routes.contact(contact.id));
    expect(delContact.ok(), `delete contact -> ${delContact.status()}`).toBeTruthy();
    const delCompany = await request.delete(routes.company(company.id));
    expect(delCompany.ok(), `delete company -> ${delCompany.status()}`).toBeTruthy();
  });
});

test.describe('tenants smoke', () => {
  test('E2E account can read its own tenant', async ({ request }) => {
    const res = await request.get(routes.tenant(env.tenantId));
    // 200 for members; 403 if the route is admin-only on this deployment. Either
    // is a non-error signal; a 5xx or 404 would indicate a real problem.
    expect([200, 403], `GET own tenant -> ${res.status()}`).toContain(res.status());
  });
});

// Cross-tenant leak canary (AC), guarding against cross-cutting issue #8 in
// dev-docs/codebase-state.md.
test.describe('cross-tenant isolation', () => {
  test('foreign tenant id is not readable', async ({ request }) => {
    // A well-formed but foreign/non-existent tenant id must never return 200.
    // Random UUID avoids accidentally hitting a real tenant (a fixed nil UUID
    // would alias whatever future seed migrations might insert there).
    const foreignTenant = randomUUID();
    const res = await request.get(routes.tenant(foreignTenant));
    expect([403, 404], `foreign tenant read -> ${res.status()}`).toContain(res.status());
  });

  test('E2E account cannot read a foreign tenant company', async ({ request }) => {
    test.skip(
      !env.foreignCompanyId,
      'set E2E_FOREIGN_COMPANY_ID (a company in another tenant) to enable - see README',
    );
    const res = await request.get(routes.company(env.foreignCompanyId!));
    expect([403, 404], `foreign company read -> ${res.status()}`).toContain(res.status());
  });
});
