import { expect, test } from '../lib/fixtures';
import { routes } from '../lib/api';
import { createCompany, enableModule, today } from '../lib/factories';
import { runSuffix } from '../lib/run';

// Contracts CRUD (PMS-155): contract -> contract item, plus a standalone rate
// card, and an hour-balance read smoke. The module is tenant-gated
// (RequireContracts, default disabled) and writes need a finance-capable role
// (admin satisfies it). Enabled first via the admin settings route.
//
// Rate-card *items* are intentionally skipped: they require a work_type_id,
// which would couple this spec to the time_tracking module. Records are
// run-suffixed and deleted inline in reverse-dependency order; teardown sweeps
// residue from a failed run.
test.describe('contracts CRUD', () => {
  test('contract + item + rate card lifecycle', async ({ request }) => {
    await enableModule(request, 'contracts');
    const company = await createCompany(request);

    // Contract. contract_type is a CHECK-constrained string; 'managed_services'
    // is one of the accepted values (migrations/009_contracts.sql).
    const cName = runSuffix();
    const createC = await request.post(routes.contracts, {
      data: {
        name: cName,
        company_id: company.id,
        contract_type: 'managed_services',
        start_date: today(),
      },
    });
    expect(createC.status(), `create contract failed: ${await createC.text()}`).toBe(200);
    const contract = (await createC.json()) as { id: string };
    expect(contract.id).toBeTruthy();

    const getC = await request.get(routes.contract(contract.id));
    expect(getC.status()).toBe(200);

    const updC = await request.put(routes.contract(contract.id), {
      data: { name: `${cName}-upd`, status: 'active' },
    });
    expect(updC.status(), `update contract failed: ${await updC.text()}`).toBe(200);

    const listC = await request.get(`${routes.contracts}?per_page=200`);
    expect(listC.status()).toBe(200);
    expect(((await listC.json()) as { data: Array<{ id: string }> }).data.map((c) => c.id)).toContain(
      contract.id,
    );

    // Hour-balance read smoke.
    const hb = await request.get(routes.hourBalance(contract.id));
    expect(hb.status(), `hour-balance -> ${hb.status()}`).toBe(200);

    // Contract item. item_type is CHECK-constrained; 'product' is accepted.
    const itemName = runSuffix();
    const createItem = await request.post(routes.contractItems(contract.id), {
      data: { name: itemName, item_type: 'product', quantity: '1', unit_price: '100' },
    });
    expect(createItem.status(), `create contract-item failed: ${await createItem.text()}`).toBe(200);
    const item = (await createItem.json()) as { id: string };
    expect(item.id).toBeTruthy();

    const listItems = await request.get(routes.contractItems(contract.id));
    expect(listItems.status()).toBe(200);
    expect(
      ((await listItems.json()) as { data: Array<{ id: string }> }).data.map((i) => i.id),
    ).toContain(item.id);

    const updItem = await request.put(routes.contractItem(item.id), {
      data: { name: `${itemName}-upd`, item_type: 'product', quantity: '2', unit_price: '120' },
    });
    expect(updItem.status(), `update contract-item failed: ${await updItem.text()}`).toBe(200);

    // Rate card (standalone; no items).
    const rcName = runSuffix();
    const createRc = await request.post(routes.rateCards, { data: { name: rcName } });
    expect(createRc.status(), `create rate-card failed: ${await createRc.text()}`).toBe(200);
    const rateCard = (await createRc.json()) as { id: string };
    expect(rateCard.id).toBeTruthy();

    const listRc = await request.get(`${routes.rateCards}?per_page=200`);
    expect(listRc.status()).toBe(200);
    expect(((await listRc.json()) as { data: Array<{ id: string }> }).data.map((r) => r.id)).toContain(
      rateCard.id,
    );

    const updRc = await request.put(routes.rateCard(rateCard.id), {
      data: { name: `${rcName}-upd` },
    });
    expect(updRc.status(), `update rate-card failed: ${await updRc.text()}`).toBe(200);

    // Cleanup, reverse-dependency order: item before contract; rate card and
    // company are independent.
    expect((await request.delete(routes.contractItem(item.id))).ok()).toBeTruthy();
    expect((await request.delete(routes.rateCard(rateCard.id))).ok()).toBeTruthy();
    expect((await request.delete(routes.contract(contract.id))).ok()).toBeTruthy();
    expect((await request.delete(routes.company(company.id))).ok()).toBeTruthy();
  });
});
