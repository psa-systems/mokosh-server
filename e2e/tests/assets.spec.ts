import { expect, test } from '../lib/fixtures';
import { routes } from '../lib/api';
import { createCompany, enableModule } from '../lib/factories';
import { runSuffix } from '../lib/run';

// Assets / CMDB CRUD (PMS-155): asset type -> asset -> configuration item. The
// module is tenant-gated (RequireAssets, default disabled), enabled first via
// the admin settings route. Asset-type and asset deletes are admin-gated; the
// E2E admin satisfies that.
//
// The configuration item exercises the encrypted-at-rest path: its `value` is
// encrypted on write and decrypted on the single-item GET (the list omits it).
// Records are deleted inline in reverse-dependency order; every delete runs
// before the asserts so one failure cannot orphan the rest (the config item
// has no flat list, so teardown cannot sweep it).
test.describe('assets CRUD', () => {
  test('asset type + asset + configuration item lifecycle', async ({ request }) => {
    await enableModule(request, 'assets');
    const company = await createCompany(request);

    // Asset type (admin-gated).
    const atName = runSuffix();
    const createAt = await request.post(routes.assetTypes, { data: { name: atName } });
    expect(createAt.status(), `create asset-type failed: ${await createAt.text()}`).toBe(200);
    const assetType = (await createAt.json()) as { id: string };
    expect(assetType.id).toBeTruthy();

    const updAt = await request.put(routes.assetType(assetType.id), {
      data: { name: `${atName}-upd` },
    });
    expect(updAt.status(), `update asset-type failed: ${await updAt.text()}`).toBe(200);

    // Asset (needs the asset type + a company).
    const aName = runSuffix();
    const createA = await request.post(routes.assets, {
      data: { name: aName, asset_type_id: assetType.id, company_id: company.id },
    });
    expect(createA.status(), `create asset failed: ${await createA.text()}`).toBe(200);
    const asset = (await createA.json()) as { id: string };
    expect(asset.id).toBeTruthy();

    const getA = await request.get(routes.asset(asset.id));
    expect(getA.status()).toBe(200);

    const updA = await request.put(routes.asset(asset.id), {
      data: { name: `${aName}-upd`, status: 'in_repair' },
    });
    expect(updA.status(), `update asset failed: ${await updA.text()}`).toBe(200);

    const listA = await request.get(`${routes.assets}?per_page=200`);
    expect(listA.status()).toBe(200);
    expect(((await listA.json()) as { data: Array<{ id: string }> }).data.map((a) => a.id)).toContain(
      asset.id,
    );

    // Configuration item under the asset (encrypted `value`).
    const ciName = runSuffix();
    const createCi = await request.post(routes.assetConfigItems(asset.id), {
      data: { name: ciName, value: 'e2e-secret', category: 'config' },
    });
    expect(createCi.status(), `create config-item failed: ${await createCi.text()}`).toBe(200);
    const configItem = (await createCi.json()) as { id: string };
    expect(configItem.id).toBeTruthy();

    // Single-item GET decrypts and returns the value.
    const getCi = await request.get(routes.configItem(configItem.id));
    expect(getCi.status()).toBe(200);
    expect(((await getCi.json()) as { value: string }).value).toBe('e2e-secret');

    // Cleanup, reverse-dependency order: config item -> asset -> asset type ->
    // company. Run every delete before asserting.
    const cleanup = [
      await request.delete(routes.configItem(configItem.id)),
      await request.delete(routes.asset(asset.id)),
      await request.delete(routes.assetType(assetType.id)),
      await request.delete(routes.company(company.id)),
    ];
    for (const res of cleanup) {
      expect(res.ok(), `cleanup delete -> ${res.status()}`).toBeTruthy();
    }
  });
});
