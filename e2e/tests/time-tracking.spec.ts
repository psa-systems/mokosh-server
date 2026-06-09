import { expect, test } from '../lib/fixtures';
import { routes } from '../lib/api';
import { createCompany, enableModule, getSelf, today } from '../lib/factories';
import { runSuffix } from '../lib/run';

// Time-tracking CRUD (PMS-155). Exercises the independently-deletable
// resources the module owns - work types, time entries, rounding rules -
// against the deployed API.
//
// The module is tenant-gated (RequireTimeTracking; is_module_enabled defaults
// FALSE), so the spec enables it first via the admin settings route. Every
// record carries a run suffix and is deleted inline in reverse-dependency
// order (a time entry references its work type, so the entry goes first);
// global teardown sweeps any residue from a failed run as a backstop.
test.describe('time-tracking CRUD', () => {
  test('work type + time entry + rounding rule lifecycle', async ({ request }) => {
    await enableModule(request, 'time_tracking');
    const self = await getSelf(request);
    const company = await createCompany(request);

    // Work type (admin-gated create).
    const wtName = runSuffix();
    const createWt = await request.post(routes.workTypes, {
      data: { name: wtName, default_billable: true, default_rate: '150' },
    });
    expect(createWt.status(), `create work-type failed: ${await createWt.text()}`).toBe(200);
    const workType = (await createWt.json()) as { id: string; name: string };
    expect(workType.id).toBeTruthy();

    const listWt = await request.get(`${routes.workTypes}?per_page=200`);
    expect(listWt.status()).toBe(200);
    expect(((await listWt.json()) as { data: Array<{ id: string }> }).data.map((w) => w.id)).toContain(
      workType.id,
    );

    const updWt = await request.put(routes.workType(workType.id), {
      data: { name: `${wtName}-upd`, default_billable: false },
    });
    expect(updWt.status(), `update work-type failed: ${await updWt.text()}`).toBe(200);

    // Time entry referencing the work type + company.
    const day = today();
    const createTe = await request.post(routes.timeEntries, {
      data: {
        user_id: self.id,
        date: day,
        duration_minutes: 60,
        work_type_id: workType.id,
        company_id: company.id,
        notes: `${runSuffix()} time entry`,
        is_billable: true,
      },
    });
    expect(createTe.status(), `create time-entry failed: ${await createTe.text()}`).toBe(200);
    const entry = (await createTe.json()) as { id: string };
    expect(entry.id).toBeTruthy();

    const getTe = await request.get(routes.timeEntry(entry.id));
    expect(getTe.status()).toBe(200);

    const updTe = await request.put(routes.timeEntry(entry.id), { data: { duration_minutes: 90 } });
    expect(updTe.status(), `update time-entry failed: ${await updTe.text()}`).toBe(200);

    const listTe = await request.get(
      `${routes.timeEntries}?date_from=${day}&date_to=${day}&per_page=200`,
    );
    expect(listTe.status()).toBe(200);
    expect(((await listTe.json()) as { data: Array<{ id: string }> }).data.map((e) => e.id)).toContain(
      entry.id,
    );

    // Rounding rule (admin-gated, independent of the entry/work-type chain).
    const rrName = runSuffix();
    const createRr = await request.post(routes.roundingRules, {
      data: { name: rrName, increment_minutes: 15, rounding_method: 'nearest', minimum_minutes: 15 },
    });
    expect(createRr.status(), `create rounding-rule failed: ${await createRr.text()}`).toBe(200);
    const rule = (await createRr.json()) as { id: string };
    expect(rule.id).toBeTruthy();

    const updRr = await request.put(routes.roundingRule(rule.id), {
      data: { name: `${rrName}-upd`, increment_minutes: 30, rounding_method: 'up' },
    });
    expect(updRr.status(), `update rounding-rule failed: ${await updRr.text()}`).toBe(200);

    // Cleanup, reverse-dependency order. The time entry references the work
    // type, so it must be deleted before the work type.
    expect((await request.delete(routes.roundingRule(rule.id))).ok()).toBeTruthy();
    expect((await request.delete(routes.timeEntry(entry.id))).ok()).toBeTruthy();
    expect((await request.delete(routes.workType(workType.id))).ok()).toBeTruthy();
    expect((await request.delete(routes.company(company.id))).ok()).toBeTruthy();
  });
});
