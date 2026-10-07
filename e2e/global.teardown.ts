import { request, type APIRequestContext } from '@playwright/test';
import { existsSync } from 'node:fs';
import { TOKEN_FILE, readToken } from './lib/auth-state';
import { env } from './lib/env';
import { MAX_PER_PAGE, routes } from './lib/api';
import { isOwnedByThisRun, isStale } from './lib/run';

// Global teardown: remove everything THIS run created, then sweep e2e-prefixed
// residue older than 24h left by earlier failed runs. A teardown that cannot
// clean up is a failure: a list or delete that fails is collected rather than
// swallowed, and the run throws after the full sweep so the cause lands in the
// log instead of a silent "nothing to sweep".
//
// Auth: reuses the bearer token the setup project wrote to TOKEN_FILE; the
// auth middleware reads Bearer only, so cookie-based reuse is not an option
// (see e2e/lib/auth-state.ts and src/modules/auth/middleware.rs:67).
//
// Coverage note: tickets ARE hard-deletable via DELETE /tickets/{id}
// (src/modules/tickets/routes.rs, added in PMS-149). They carry run-suffixed
// titles and are swept before companies, since delete_company refuses while a
// ticket still references the company. See e2e/README.md.

interface Named {
  id: string;
  name?: string;
  title?: string;
  full_name?: string;
  first_name?: string;
  last_name?: string;
}

async function listAll(api: APIRequestContext, path: string): Promise<Named[]> {
  const out: Named[] = [];
  for (let page = 1; page <= 50; page += 1) {
    const url = `${path}?page=${page}&per_page=${MAX_PER_PAGE}`;
    const res = await api.get(url);
    if (res.status() === 404) {
      // A disabled module's list route 404s (RequireModuleEnabled,
      // src/modules/auth/middleware.rs); a disabled module created no
      // records, so an empty list here is correct, not a failure to report.
      return out;
    }
    if (!res.ok()) {
      throw new Error(`GET ${url} -> ${res.status()}: ${await res.text()}`);
    }
    const body = (await res.json()) as { data?: Named[]; meta?: { total?: number } };
    const rows = body.data ?? [];
    out.push(...rows);
    if (rows.length < MAX_PER_PAGE) break;
  }
  return out;
}

function label(row: Named): string {
  return (
    row.name ??
    row.title ??
    row.full_name ??
    [row.first_name, row.last_name].filter(Boolean).join(' ') ??
    ''
  );
}

function shouldRemove(name: string, now: number): boolean {
  return isOwnedByThisRun(name) || isStale(name, now);
}

async function sweep(
  api: APIRequestContext,
  listPath: string,
  del: (id: string) => string,
  now: number,
): Promise<{ removed: number; failed: number; errors: string[] }> {
  let removed = 0;
  let failed = 0;
  const errors: string[] = [];
  let rows: Named[];
  try {
    rows = await listAll(api, listPath);
  } catch (err) {
    errors.push(`list ${listPath}: ${String(err)}`);
    return { removed, failed, errors };
  }
  for (const row of rows) {
    if (!shouldRemove(label(row), now)) continue;
    const path = del(row.id);
    try {
      const res = await api.delete(path);
      if (res.ok()) {
        removed += 1;
      } else {
        failed += 1;
        errors.push(`delete ${path} -> ${res.status()}: ${await res.text()}`);
      }
    } catch (err) {
      failed += 1;
      errors.push(`delete ${path} threw: ${String(err)}`);
    }
  }
  return { removed, failed, errors };
}

export default async function globalTeardown(): Promise<void> {
  if (!existsSync(TOKEN_FILE)) {
    throw new Error('[teardown] no bearer token on disk; setup failed, so cleanup did not run');
  }
  const token = readToken();
  const api = await request.newContext({
    baseURL: env.apiBaseURL,
    extraHTTPHeaders: { Authorization: `Bearer ${token}` },
  });
  const now = Date.now();
  const allErrors: string[] = [];
  try {
    // Order matters: a parent refuses deletion while a child still references
    // it. Sweep children before parents, and the company (referenced by almost
    // everything) dead last.
    //
    // Several modules (time_tracking, projects, billing, contracts, calendar,
    // assets, knowledge_base) are tenant-gated: when a module is disabled its
    // list route 404s, `listAll` returns [], and that sweep is a silent no-op -
    // fine, a disabled module created no records. Records without a
    // run-suffixed name (time entries, tasks, contract items, invoices,
    // payments, time-off, config items) cannot be matched by the name sweep;
    // specs delete those inline, and this backstop only mops up the top-level
    // named residue a failed run leaves behind.
    const targets: Array<{ name: string; list: string; del: (id: string) => string }> = [
      { name: 'appointments', list: routes.appointments, del: routes.appointment },
      { name: 'kbArticles', list: routes.kbArticles, del: routes.kbArticle },
      { name: 'kbCategories', list: routes.kbCategories, del: routes.kbCategory },
      {
        name: 'notificationTemplates',
        list: routes.notificationTemplates,
        del: routes.notificationTemplate,
      },
      {
        name: 'notificationChannels',
        list: routes.notificationChannels,
        del: routes.notificationChannel,
      },
      { name: 'tickets', list: routes.tickets, del: routes.ticket },
      { name: 'projects', list: routes.projects, del: routes.project },
      { name: 'contracts', list: routes.contracts, del: routes.contract },
      { name: 'rmmAlertRules', list: routes.rmmAlertRules, del: routes.rmmAlertRule },
      { name: 'rmmDeviceMappings', list: routes.rmmDeviceMappings, del: routes.rmmDeviceMapping },
      { name: 'rmmConnections', list: routes.rmmConnections, del: routes.rmmConnection },
      { name: 'assets', list: routes.assets, del: routes.asset },
      { name: 'assetTypes', list: routes.assetTypes, del: routes.assetType },
      { name: 'onCallSchedules', list: routes.onCallSchedules, del: routes.onCallSchedule },
      { name: 'slaPolicies', list: routes.slaPolicies, del: routes.slaPolicy },
      { name: 'slaBusinessHours', list: routes.slaBusinessHours, del: routes.slaBusinessHour },
      { name: 'slaHolidayCalendars', list: routes.slaHolidayCalendars, del: routes.slaHolidayCalendar },
      { name: 'workTypes', list: routes.workTypes, del: routes.workType },
      { name: 'roundingRules', list: routes.roundingRules, del: routes.roundingRule },
      { name: 'taskStatuses', list: routes.taskStatuses, del: routes.taskStatus },
      { name: 'rateCards', list: routes.rateCards, del: routes.rateCard },
      { name: 'taxRates', list: routes.taxRates, del: routes.taxRate },
      { name: 'contacts', list: routes.contacts, del: routes.contact },
      { name: 'companies', list: routes.companies, del: routes.company },
    ];
    const summary: string[] = [];
    for (const t of targets) {
      const r = await sweep(api, t.list, t.del, now);
      if (r.removed || r.failed) summary.push(`${t.name} removed=${r.removed} failed=${r.failed}`);
      allErrors.push(...r.errors.map((e) => `${t.name}: ${e}`));
    }
    console.log(`[teardown] ${summary.length ? summary.join('; ') : 'nothing to sweep'}`);
  } finally {
    await api.dispose();
  }
  if (allErrors.length > 0) {
    throw new Error(`[teardown] ${allErrors.length} failure(s):\n${allErrors.join('\n')}`);
  }
}
