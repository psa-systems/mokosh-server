import { expect, test } from '../lib/fixtures';
import { routes } from '../lib/api';
import { runSuffix } from '../lib/run';

// Notifications CRUD (PMS-155): templates and channels. The module is NOT
// tenant-gated, but writes are admin-only; the E2E admin satisfies that.
// Templates and channels are create/list/delete only (no update or get-by-id),
// so the lifecycle is create -> list -> delete.
//
// channel_type is a CHECK-constrained enum; 'email' (template) and 'in_app'
// (channel, needs no external config) are accepted values.
test.describe('notifications CRUD', () => {
  test('template + channel lifecycle', async ({ request }) => {
    // Template.
    const tplName = runSuffix();
    const createTpl = await request.post(routes.notificationTemplates, {
      data: {
        name: tplName,
        event_type: 'ticket.created',
        channel_type: 'email',
        body_text: 'e2e template body',
      },
    });
    expect(createTpl.status(), `create template failed: ${await createTpl.text()}`).toBe(200);
    const template = (await createTpl.json()) as { id: string };
    expect(template.id).toBeTruthy();

    const listTpl = await request.get(`${routes.notificationTemplates}?per_page=200`);
    expect(listTpl.status()).toBe(200);
    expect(((await listTpl.json()) as { data: Array<{ id: string }> }).data.map((t) => t.id)).toContain(
      template.id,
    );

    // Channel (in_app needs no external config).
    const chName = runSuffix();
    const createCh = await request.post(routes.notificationChannels, {
      data: { name: chName, channel_type: 'in_app', config: {} },
    });
    expect(createCh.status(), `create channel failed: ${await createCh.text()}`).toBe(200);
    const channel = (await createCh.json()) as { id: string };
    expect(channel.id).toBeTruthy();

    const listCh = await request.get(`${routes.notificationChannels}?per_page=200`);
    expect(listCh.status()).toBe(200);
    expect(((await listCh.json()) as { data: Array<{ id: string }> }).data.map((c) => c.id)).toContain(
      channel.id,
    );

    // Cleanup; run every delete before asserting. The two are independent.
    const cleanup = [
      await request.delete(routes.notificationTemplate(template.id)),
      await request.delete(routes.notificationChannel(channel.id)),
    ];
    for (const res of cleanup) {
      expect(res.ok(), `cleanup delete -> ${res.status()}`).toBeTruthy();
    }
  });
});
