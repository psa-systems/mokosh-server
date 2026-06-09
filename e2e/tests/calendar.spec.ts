import { expect, test } from '../lib/fixtures';
import { routes } from '../lib/api';
import { enableModule, getSelf, today } from '../lib/factories';
import { runSuffix } from '../lib/run';

// Calendar / scheduling CRUD (PMS-155): appointments, time-off, and on-call
// schedules. The module is tenant-gated (RequireCalendar, default disabled),
// enabled first via the admin settings route. On-call and time-off approval
// are manager-gated; the E2E admin satisfies that.
//
// Records are deleted inline; every delete runs before the asserts so one
// failure cannot orphan the rest (time-off has no run-suffixed name, so
// teardown cannot sweep it as a backstop).
test.describe('calendar CRUD', () => {
  test('appointment + time-off + on-call lifecycle', async ({ request }) => {
    await enableModule(request, 'calendar');
    const self = await getSelf(request);

    // Appointment. start/end are RFC 3339 datetimes; end must follow start.
    const apptTitle = runSuffix();
    const start = new Date(Date.now() + 3_600_000).toISOString();
    const end = new Date(Date.now() + 7_200_000).toISOString();
    const createAppt = await request.post(routes.appointments, {
      data: {
        title: apptTitle,
        assigned_to_id: self.id,
        start_time: start,
        end_time: end,
        appointment_type: 'meeting',
      },
    });
    expect(createAppt.status(), `create appointment failed: ${await createAppt.text()}`).toBe(200);
    const appt = (await createAppt.json()) as { id: string; title: string };
    expect(appt.id).toBeTruthy();

    const getAppt = await request.get(routes.appointment(appt.id));
    expect(getAppt.status()).toBe(200);

    const updAppt = await request.put(routes.appointment(appt.id), {
      data: { title: `${apptTitle}-upd`, location: 'remote' },
    });
    expect(updAppt.status(), `update appointment failed: ${await updAppt.text()}`).toBe(200);

    const listAppt = await request.get(`${routes.appointments}?per_page=200`);
    expect(listAppt.status(), `list appointments -> ${listAppt.status()}`).toBe(200);

    // Time-off (type is a CHECK-constrained enum; 'personal' is accepted).
    const createTo = await request.post(routes.timeOff, {
      data: { user_id: self.id, start_date: today(), end_date: today(), type: 'personal' },
    });
    expect(createTo.status(), `create time-off failed: ${await createTo.text()}`).toBe(200);
    const timeOff = (await createTo.json()) as { id: string };
    expect(timeOff.id).toBeTruthy();

    const getTo = await request.get(routes.timeOffItem(timeOff.id));
    expect(getTo.status()).toBe(200);

    // On-call schedule (manager-gated; rotation_type defaults to 'weekly').
    const ocName = runSuffix();
    const createOc = await request.post(routes.onCallSchedules, { data: { name: ocName } });
    expect(createOc.status(), `create on-call failed: ${await createOc.text()}`).toBe(200);
    const onCall = (await createOc.json()) as { id: string };
    expect(onCall.id).toBeTruthy();

    const updOc = await request.put(routes.onCallSchedule(onCall.id), {
      data: { name: `${ocName}-upd`, rotation_type: 'daily' },
    });
    expect(updOc.status(), `update on-call failed: ${await updOc.text()}`).toBe(200);

    // Cleanup; run every delete before asserting so one failure does not orphan
    // the rest. These three are independent (no FK among them).
    const cleanup = [
      await request.delete(routes.appointment(appt.id)),
      await request.delete(routes.timeOffItem(timeOff.id)),
      await request.delete(routes.onCallSchedule(onCall.id)),
    ];
    for (const res of cleanup) {
      expect(res.ok(), `cleanup delete -> ${res.status()}`).toBeTruthy();
    }
  });
});
