import { expect, test } from '../lib/fixtures';
import { routes } from '../lib/api';
import { enableModule } from '../lib/factories';
import { runSuffix } from '../lib/run';

// Projects CRUD (PMS-155): project -> phase -> task, plus the task-status
// lookup a task needs. No company is created - company_id is optional on a
// project, so the spec stays self-contained.
//
// The module is tenant-gated (RequireProjects, default-disabled), enabled
// first via the admin settings route. Records are run-suffixed and deleted
// inline in reverse-dependency order (task, phase, task-status, project);
// teardown sweeps residue from a failed run.
test.describe('projects CRUD', () => {
  test('project + phase + task lifecycle', async ({ request }) => {
    await enableModule(request, 'projects');

    // Project.
    const pName = runSuffix();
    const createP = await request.post(routes.projects, { data: { name: pName } });
    expect(createP.status(), `create project failed: ${await createP.text()}`).toBe(200);
    const project = (await createP.json()) as { id: string; name: string };
    expect(project.id).toBeTruthy();

    const getP = await request.get(routes.project(project.id));
    expect(getP.status()).toBe(200);

    const updP = await request.put(routes.project(project.id), {
      data: { name: `${pName}-upd`, status: 'active' },
    });
    expect(updP.status(), `update project failed: ${await updP.text()}`).toBe(200);

    const listP = await request.get(`${routes.projects}?per_page=200`);
    expect(listP.status()).toBe(200);
    expect(((await listP.json()) as { data: Array<{ id: string }> }).data.map((p) => p.id)).toContain(
      project.id,
    );

    // Phase under the project.
    const phName = runSuffix();
    const createPh = await request.post(routes.projectPhases(project.id), { data: { name: phName } });
    expect(createPh.status(), `create phase failed: ${await createPh.text()}`).toBe(200);
    const phase = (await createPh.json()) as { id: string };
    expect(phase.id).toBeTruthy();

    const listPh = await request.get(routes.projectPhases(project.id));
    expect(listPh.status()).toBe(200);

    const updPh = await request.put(routes.phase(phase.id), { data: { name: `${phName}-upd` } });
    expect(updPh.status(), `update phase failed: ${await updPh.text()}`).toBe(200);

    // Task status (admin-gated) required as a task's status_id.
    const tsName = runSuffix();
    const createTs = await request.post(routes.taskStatuses, {
      data: { name: tsName, color: '#3366cc' },
    });
    expect(createTs.status(), `create task-status failed: ${await createTs.text()}`).toBe(200);
    const status = (await createTs.json()) as { id: string };
    expect(status.id).toBeTruthy();

    // Task under the project.
    const taskTitle = runSuffix();
    const createT = await request.post(routes.projectTasks(project.id), {
      data: { title: taskTitle, status_id: status.id, phase_id: phase.id },
    });
    expect(createT.status(), `create task failed: ${await createT.text()}`).toBe(200);
    const task = (await createT.json()) as { id: string };
    expect(task.id).toBeTruthy();

    const getT = await request.get(routes.task(task.id));
    expect(getT.status()).toBe(200);

    const updT = await request.put(routes.task(task.id), {
      data: { title: `${taskTitle}-upd`, priority: 'high' },
    });
    expect(updT.status(), `update task failed: ${await updT.text()}`).toBe(200);

    const listT = await request.get(routes.projectTasks(project.id));
    expect(listT.status()).toBe(200);
    expect(((await listT.json()) as { data: Array<{ id: string }> }).data.map((t) => t.id)).toContain(
      task.id,
    );

    // Cleanup, reverse-dependency order: task, phase, task-status, project. Run
    // every delete before asserting so one failure does not abort the rest and
    // orphan the others (the task has no run-suffixed name teardown can sweep).
    const cleanup = [
      await request.delete(routes.task(task.id)),
      await request.delete(routes.phase(phase.id)),
      await request.delete(routes.taskStatus(status.id)),
      await request.delete(routes.project(project.id)),
    ];
    for (const res of cleanup) {
      expect(res.ok(), `cleanup delete -> ${res.status()}`).toBeTruthy();
    }
  });
});
