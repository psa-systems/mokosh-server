import { randomUUID } from 'node:crypto';
import { expect, test } from '../lib/fixtures';
import { routes } from '../lib/api';
import { env } from '../lib/env';
import { readForeignCompanyId } from '../lib/auth-state';
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
// docs/dev-docs/codebase-state.md.
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
    // Fixture from global.setup.ts: a real foreign-tenant company id when the
    // operator pinned E2E_FOREIGN_COMPANY_ID, otherwise a random, well-formed
    // UUID the E2E tenant cannot own. Either way the company route must never
    // return 200 (or a 5xx) for an id the caller does not own.
    const foreignCompanyId = readForeignCompanyId();
    const res = await request.get(routes.company(foreignCompanyId));
    expect([403, 404], `foreign company read -> ${res.status()}`).toContain(res.status());
  });
});

// MAPPS-915 / PMS-1290: the calls the vCard Import page makes, against the
// deployed stack. Upload and preview only: the import itself writes contacts,
// which the teardown sweep would have to learn, and its behaviour is pinned by
// the server's Postgres suite (tests/contact_import_vcard.rs). The upload row
// this leaves is discarded by the server a day later.
test.describe('vCard file import', () => {
  const card = (body: string) => `BEGIN:VCARD\r\nVERSION:3.0\r\n${body}END:VCARD\r\n`;

  test('an uploaded .vcf previews without writing a contact', async ({ request }) => {
    const suffix = runSuffix();
    const category = `${suffix}-clients`;
    const first = `${suffix}-ada@e2e.example`;
    const second = `${suffix}-grace@e2e.example`;
    const file = [
      card(`FN:Ada ${suffix}\r\nEMAIL:${first}\r\nCATEGORIES:${category}\r\n`),
      // A card with no END:VCARD: reported, and its neighbour still read.
      `BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Broken ${suffix}\r\n`,
      card(`FN:Grace ${suffix}\r\nEMAIL:${second}\r\n`),
    ].join('');

    const upload = await request.post(routes.vcardUploads, {
      multipart: {
        file: { name: `${suffix}.vcf`, mimeType: 'text/vcard', buffer: Buffer.from(file) },
      },
    });
    expect(upload.status(), `upload failed: ${await upload.text()}`).toBe(201);
    const body = (await upload.json()) as {
      file: { id: string; filename: string; contacts: number; failures: Array<{ card: number }> };
      preview: { groups: Array<{ id: string }>; totals: { create: number } };
    };
    expect(body.file.filename).toBe(`${suffix}.vcf`);
    expect(body.file.contacts).toBe(2);
    expect(body.file.failures.map((f) => f.card)).toEqual([2]);
    expect(body.preview.groups.map((g) => g.id).sort()).toEqual(
      [category, 'mokosh:ungrouped'].sort(),
    );
    expect(body.preview.totals.create).toBe(2);

    // Exact figures for one category, as the review step asks.
    const preview = await request.post(routes.vcardPreview(body.file.id), {
      data: { group_ids: [category] },
    });
    expect(preview.status(), `preview failed: ${await preview.text()}`).toBe(200);
    const totals = ((await preview.json()) as { totals: { contacts: number; create: number } })
      .totals;
    expect(totals).toMatchObject({ contacts: 1, create: 1 });

    // Nothing was written.
    for (const email of [first, second]) {
      const list = await request.get(`${routes.contacts}?q=${encodeURIComponent(email)}`);
      expect(list.status()).toBe(200);
      expect(((await list.json()) as { data: unknown[] }).data).toHaveLength(0);
    }
  });

  test('a file that is not a vCard is refused with a reason', async ({ request }) => {
    const upload = await request.post(routes.vcardUploads, {
      multipart: {
        file: { name: `${runSuffix()}.txt`, mimeType: 'text/plain', buffer: Buffer.from('just some text') },
      },
    });
    expect(upload.status()).toBe(422);
    expect(await upload.text()).toContain('BEGIN:VCARD');
  });
});
