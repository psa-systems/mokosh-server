import { test, expect, request as requestFactory, type APIRequestContext } from '@playwright/test';
import { env } from '../lib/env';
import { routes } from '../lib/api';
import { enableModule, getSelf } from '../lib/factories';
import { runSuffix } from '../lib/run';
import { readToken } from '../lib/auth-state';
import { loginViaSpa } from '../lib/login';
import { attachPageDiagnostics, trackApiErrors } from '../lib/page-diagnostics';

// Browser-level coverage for the shared reference-list selectors MAPPS-1001
// found empty on staging: work type (Log time, rate cards), technician
// (appointment assignment, dispatch board) and project task status. The
// existing specs for these modules (time-tracking.spec.ts, contracts.spec.ts,
// calendar.spec.ts, projects.spec.ts) only exercise the `request` fixture, so
// they proved the endpoints work while the UI was broken. This spec drives
// the real SPA pages instead and fails on any 4xx/5xx the page's own API
// calls see (`trackApiErrors`), not just on a missing option.
//
// ONE login for the whole spec (loginViaSpa counts against the hub's 5/min
// per-email rate limit - see lib/login.ts), then every page is visited in
// the same authenticated session. Seeding uses a raw APIRequestContext built
// from the setup project's bearer token rather than lib/fixtures.ts's
// `request` fixture, because that fixture resolves its baseURL from the
// Playwright project (the SPA host here), not the API host.
test.describe('UI reference-list selectors (PMS-1461)', () => {
  test('work type, technician and task status selectors are populated', async ({ page }) => {
    test.setTimeout(120_000);

    const api: APIRequestContext = await requestFactory.newContext({
      baseURL: env.apiBaseURL,
      extraHTTPHeaders: { Authorization: `Bearer ${readToken()}` },
    });

    await enableModule(api, 'time_tracking');
    await enableModule(api, 'projects');
    await enableModule(api, 'contracts');
    await enableModule(api, 'calendar');
    const self = await getSelf(api);

    const wtName = runSuffix();
    const createWt = await api.post(routes.workTypes, {
      data: { name: wtName, default_billable: true, default_rate: '150' },
    });
    expect(createWt.status(), `create work-type failed: ${await createWt.text()}`).toBe(200);
    const workType = (await createWt.json()) as { id: string };

    const rcName = runSuffix();
    const createRc = await api.post(routes.rateCards, { data: { name: rcName } });
    expect(createRc.status(), `create rate-card failed: ${await createRc.text()}`).toBe(200);
    const rateCard = (await createRc.json()) as { id: string };

    const pName = runSuffix();
    const createP = await api.post(routes.projects, { data: { name: pName } });
    expect(createP.status(), `create project failed: ${await createP.text()}`).toBe(200);
    const project = (await createP.json()) as { id: string };

    const tsName = runSuffix();
    const createTs = await api.post(routes.taskStatuses, {
      data: { name: tsName, color: '#3366cc' },
    });
    expect(createTs.status(), `create task-status failed: ${await createTs.text()}`).toBe(200);
    const taskStatus = (await createTs.json()) as { id: string };

    const now = new Date();
    const createAppt = await api.post(routes.appointments, {
      data: {
        title: runSuffix(),
        assigned_to_id: self.id,
        start_time: now.toISOString(),
        end_time: new Date(now.getTime() + 3_600_000).toISOString(),
      },
    });
    expect(createAppt.status(), `create appointment failed: ${await createAppt.text()}`).toBe(200);
    const appointment = (await createAppt.json()) as { id: string };

    const diag = attachPageDiagnostics(page);
    const apiErrors = trackApiErrors(page, env.apiBaseURL);

    try {
      await loginViaSpa(page);

      // Log time: the work type select must list the seeded work type.
      await page.goto('/time/new');
      await expect(
        page.getByLabel('Work Type').locator('option', { hasText: wtName }),
      ).toHaveCount(1);

      // Rate cards: "Add Rate" opens a dialog whose work-type select must
      // list the same work type.
      await page.goto(`/rate-cards/${rateCard.id}`);
      await page.getByRole('button', { name: 'Add Rate' }).click();
      const rateDialog = page.getByRole('dialog');
      await expect(
        rateDialog.getByLabel('Work type').locator('option', { hasText: wtName }),
      ).toHaveCount(1);
      await rateDialog.getByRole('button', { name: 'Cancel' }).click();

      // Appointment scheduling: the technician picker must list the signed-in
      // user, and the dispatch board must show their name, not "Unknown".
      await page.goto('/calendar');
      await page.getByRole('button', { name: 'New Appointment' }).click();
      const apptDialog = page.getByRole('dialog');
      await expect(
        apptDialog.getByLabel('Assigned to').locator('option', { hasText: self.full_name }),
      ).toHaveCount(1);
      await apptDialog.getByRole('button', { name: 'Cancel' }).click();

      // The per-technician board lives on /dispatch, a separate route from
      // /calendar: #calendar-dispatch-scroll is rendered by DispatchBoardPage
      // only (mokosh-apps src/pages/calendar.rs), not by the calendar page
      // above, so the assertion has to navigate there first.
      await page.goto('/dispatch');
      await page.getByRole('button', { name: 'Today' }).click();
      await page.getByRole('button', { name: 'Day', exact: true }).click();
      const dispatchBoard = page.locator('#calendar-dispatch-scroll');
      await expect(dispatchBoard.getByText(self.full_name).first()).toBeVisible();
      await expect(dispatchBoard.getByText('Unknown')).toHaveCount(0);

      // Project tasks: "Add Task" opens a dialog whose status select must
      // list the seeded task status.
      await page.goto(`/projects/${project.id}`);
      await page.getByRole('button', { name: 'Add Task' }).click();
      const taskDialog = page.getByRole('dialog');
      await expect(
        taskDialog.getByLabel('Status').locator('option', { hasText: tsName }),
      ).toHaveCount(1);
      await taskDialog.getByRole('button', { name: 'Cancel' }).click();

      expect(apiErrors.errors(), `API errors seen by the page: ${apiErrors.errors().join('; ')}`).toEqual(
        [],
      );
    } catch (err) {
      throw new Error(diag.snapshot('ui-selectors diagnostic'), { cause: err });
    } finally {
      const cleanup = [
        await api.delete(routes.appointment(appointment.id)),
        await api.delete(routes.taskStatus(taskStatus.id)),
        await api.delete(routes.project(project.id)),
        await api.delete(routes.rateCard(rateCard.id)),
        await api.delete(routes.workType(workType.id)),
      ];
      for (const res of cleanup) {
        expect(res.ok(), `cleanup delete -> ${res.status()}`).toBeTruthy();
      }
      await api.dispose();
    }
  });
});
