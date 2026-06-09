import { expect, test } from '../lib/fixtures';
import { routes } from '../lib/api';
import { enableModule } from '../lib/factories';
import { runSuffix } from '../lib/run';

// RMM CRUD (PMS-155): connection -> alert rule + device mapping. The module is
// tenant-gated ('rmm_integration', default disabled) and every route is
// admin-only; the E2E admin satisfies both.
//
// A connection is created with throwaway credentials: create_connection only
// stores the api_key encrypted at rest (no live provider call - that is the
// separate /test route), and the connection response never echoes the key, so
// no real RMM system is needed. provider is a CHECK-constrained enum
// ('tactical_rmm'). Alert rules and device mappings reference the connection
// (FK), so they are deleted before it. Every delete runs before the asserts so
// one failure cannot orphan the rest.
test.describe('RMM CRUD', () => {
  test('connection + alert rule + device mapping lifecycle', async ({ request }) => {
    await enableModule(request, 'rmm_integration');

    // Connection (full CRUD; fake credentials).
    const connName = runSuffix();
    const createConn = await request.post(routes.rmmConnections, {
      data: {
        name: connName,
        provider: 'tactical_rmm',
        api_url: 'https://rmm.example.com',
        api_key: 'e2e-fake-key',
      },
    });
    expect(createConn.status(), `create connection failed: ${await createConn.text()}`).toBe(200);
    const connection = (await createConn.json()) as { id: string };
    expect(connection.id).toBeTruthy();

    const getConn = await request.get(routes.rmmConnection(connection.id));
    expect(getConn.status()).toBe(200);

    const updConn = await request.put(routes.rmmConnection(connection.id), {
      data: { name: `${connName}-upd`, is_active: true },
    });
    expect(updConn.status(), `update connection failed: ${await updConn.text()}`).toBe(200);

    const listConn = await request.get(`${routes.rmmConnections}?per_page=200`);
    expect(listConn.status()).toBe(200);
    expect(((await listConn.json()) as { data: Array<{ id: string }> }).data.map((c) => c.id)).toContain(
      connection.id,
    );

    // Alert rule (create/list/delete only; references the connection).
    const ruleName = runSuffix();
    const createRule = await request.post(routes.rmmAlertRules, {
      data: { rmm_connection_id: connection.id, name: ruleName },
    });
    expect(createRule.status(), `create alert-rule failed: ${await createRule.text()}`).toBe(200);
    const rule = (await createRule.json()) as { id: string };
    expect(rule.id).toBeTruthy();

    const listRules = await request.get(`${routes.rmmAlertRules}?per_page=200`);
    expect(listRules.status()).toBe(200);
    expect(((await listRules.json()) as { data: Array<{ id: string }> }).data.map((r) => r.id)).toContain(
      rule.id,
    );

    // Device mapping (create/list/delete only; references the connection).
    // device_name carries the run suffix so teardown can sweep it as a backstop.
    const createMap = await request.post(routes.rmmDeviceMappings, {
      data: {
        rmm_connection_id: connection.id,
        rmm_device_id: runSuffix(),
        device_name: runSuffix(),
      },
    });
    expect(createMap.status(), `create device-mapping failed: ${await createMap.text()}`).toBe(200);
    const mapping = (await createMap.json()) as { id: string };
    expect(mapping.id).toBeTruthy();

    const listMaps = await request.get(`${routes.rmmDeviceMappings}?per_page=200`);
    expect(listMaps.status()).toBe(200);
    expect(((await listMaps.json()) as { data: Array<{ id: string }> }).data.map((m) => m.id)).toContain(
      mapping.id,
    );

    // Cleanup, reverse-dependency order: the alert rule and device mapping
    // reference the connection, so they go first. Run every delete before
    // asserting so one failure cannot orphan the rest.
    const cleanup = [
      await request.delete(routes.rmmAlertRule(rule.id)),
      await request.delete(routes.rmmDeviceMapping(mapping.id)),
      await request.delete(routes.rmmConnection(connection.id)),
    ];
    for (const res of cleanup) {
      expect(res.ok(), `cleanup delete -> ${res.status()}`).toBeTruthy();
    }
  });
});
