import { expect, test } from '../lib/fixtures';
import { routes } from '../lib/api';
import { runSuffix } from '../lib/run';

// SLA CRUD (PMS-155): policies, business hours, holiday calendars. The SLA
// module is NOT tenant-gated (no enableModule needed), but every write is
// admin-only; the E2E admin satisfies that. SLA targets are skipped: they
// require a priority_id, which would couple this spec to the tickets module.
//
// Each resource is run-suffixed and deleted inline; every delete runs before
// the asserts so one failure cannot orphan the rest.
test.describe('SLA CRUD', () => {
  test('policy + business hours + holiday calendar lifecycle', async ({ request }) => {
    // Policy.
    const pName = runSuffix();
    const createP = await request.post(routes.slaPolicies, { data: { name: pName } });
    expect(createP.status(), `create sla-policy failed: ${await createP.text()}`).toBe(200);
    const policy = (await createP.json()) as { id: string; name: string };
    expect(policy.id).toBeTruthy();

    const getP = await request.get(routes.slaPolicy(policy.id));
    expect(getP.status()).toBe(200);

    const updP = await request.put(routes.slaPolicy(policy.id), {
      data: { name: `${pName}-upd`, description: 'e2e' },
    });
    expect(updP.status(), `update sla-policy failed: ${await updP.text()}`).toBe(200);

    const listP = await request.get(`${routes.slaPolicies}?per_page=200`);
    expect(listP.status()).toBe(200);
    expect(((await listP.json()) as { data: Array<{ id: string }> }).data.map((p) => p.id)).toContain(
      policy.id,
    );

    // Business hours.
    const bhName = runSuffix();
    const createBh = await request.post(routes.slaBusinessHours, { data: { name: bhName } });
    expect(createBh.status(), `create business-hours failed: ${await createBh.text()}`).toBe(200);
    const bh = (await createBh.json()) as { id: string };
    expect(bh.id).toBeTruthy();

    const updBh = await request.put(routes.slaBusinessHour(bh.id), {
      data: { name: `${bhName}-upd`, timezone: 'UTC' },
    });
    expect(updBh.status(), `update business-hours failed: ${await updBh.text()}`).toBe(200);

    // Holiday calendar.
    const hcName = runSuffix();
    const createHc = await request.post(routes.slaHolidayCalendars, { data: { name: hcName } });
    expect(createHc.status(), `create holiday-calendar failed: ${await createHc.text()}`).toBe(200);
    const hc = (await createHc.json()) as { id: string };
    expect(hc.id).toBeTruthy();

    const updHc = await request.put(routes.slaHolidayCalendar(hc.id), {
      data: { name: `${hcName}-upd` },
    });
    expect(updHc.status(), `update holiday-calendar failed: ${await updHc.text()}`).toBe(200);

    // Cleanup; run every delete before asserting. Policy references
    // business_hours_id only when set (it is not here), so order is free.
    const cleanup = [
      await request.delete(routes.slaPolicy(policy.id)),
      await request.delete(routes.slaBusinessHour(bh.id)),
      await request.delete(routes.slaHolidayCalendar(hc.id)),
    ];
    for (const res of cleanup) {
      expect(res.ok(), `cleanup delete -> ${res.status()}`).toBeTruthy();
    }
  });
});
