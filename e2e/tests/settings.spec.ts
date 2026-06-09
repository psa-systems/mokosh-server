import { expect, test } from '../lib/fixtures';
import { routes } from '../lib/api';
import { runSuffix } from '../lib/run';

// Settings CRUD (PMS-155): tenant settings keyed by (category, key). Not
// module-gated; writes are admin-only. A throwaway `e2e` category with a
// run-suffixed key is used so validate_setting_value accepts the value
// verbatim (unknown category/key pairs are accepted) and nothing real is
// overwritten. Full create/read/update/delete is available, so the row is
// removed inline and its absence confirmed with a 404.
test.describe('settings CRUD', () => {
  test('tenant setting upsert / read / update / delete', async ({ request }) => {
    const category = 'e2e';
    const key = runSuffix();

    // Upsert (create).
    const putRes = await request.put(routes.setting(category, key), {
      data: { value: 'e2e-value-1' },
    });
    expect(putRes.status(), `upsert setting failed: ${await putRes.text()}`).toBe(200);
    expect(((await putRes.json()) as { value: string }).value).toBe('e2e-value-1');

    // Read single.
    const getRes = await request.get(routes.setting(category, key));
    expect(getRes.status()).toBe(200);
    expect(((await getRes.json()) as { key: string; value: string }).value).toBe('e2e-value-1');

    // Update value.
    const updRes = await request.put(routes.setting(category, key), {
      data: { value: 'e2e-value-2' },
    });
    expect(updRes.status(), `update setting failed: ${await updRes.text()}`).toBe(200);
    expect(((await updRes.json()) as { value: string }).value).toBe('e2e-value-2');

    // Category listing responds (shape is a plain array; just smoke the status).
    const listRes = await request.get(routes.settingsCategory(category));
    expect(listRes.status(), `list category -> ${listRes.status()}`).toBe(200);

    // Delete, then confirm it is gone.
    const delRes = await request.delete(routes.setting(category, key));
    expect(delRes.ok(), `delete setting -> ${delRes.status()}`).toBeTruthy();

    const goneRes = await request.get(routes.setting(category, key));
    expect(goneRes.status(), `deleted setting read -> ${goneRes.status()}`).toBe(404);
  });
});
