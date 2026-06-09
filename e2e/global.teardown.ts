import { request, type APIRequestContext } from '@playwright/test';
import { existsSync } from 'node:fs';
import { TOKEN_FILE, readToken } from './lib/auth-state';
import { env } from './lib/env';
import { routes } from './lib/api';
import { isOwnedByThisRun, isStale } from './lib/run';

// Global teardown: remove everything THIS run created, then sweep e2e-prefixed
// residue older than 24h left by earlier failed runs. Best-effort by design -
// a teardown failure must not mask a green/red test result, so every deletion
// is wrapped and we never throw.
//
// Auth: reuses the bearer token the setup project wrote to TOKEN_FILE; the
// auth middleware reads Bearer only, so cookie-based reuse is not an option
// (see e2e/lib/auth-state.ts and src/modules/auth/middleware.rs:67).
//
// Coverage note: tickets ARE hard-deletable via DELETE /tickets/{id}
// (src/modules/tickets/routes.rs, added in PMS-149). They carry run-suffixed
// titles and are swept before companies, since delete_company refuses while a
// ticket still references the company. See e2e/README.md.

const PER_PAGE = 200;

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
    const res = await api.get(`${path}?page=${page}&per_page=${PER_PAGE}`);
    if (!res.ok()) break;
    const body = (await res.json()) as { data?: Named[]; meta?: { total?: number } };
    const rows = body.data ?? [];
    out.push(...rows);
    if (rows.length < PER_PAGE) break;
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
): Promise<{ removed: number; failed: number }> {
  let removed = 0;
  let failed = 0;
  let rows: Named[] = [];
  try {
    rows = await listAll(api, listPath);
  } catch (err) {
    console.warn(`[teardown] could not list ${listPath}: ${String(err)}`);
    return { removed, failed };
  }
  for (const row of rows) {
    if (!shouldRemove(label(row), now)) continue;
    try {
      const res = await api.delete(del(row.id));
      if (res.ok()) removed += 1;
      else {
        failed += 1;
        console.warn(`[teardown] DELETE ${del(row.id)} -> ${res.status()}`);
      }
    } catch (err) {
      failed += 1;
      console.warn(`[teardown] DELETE ${del(row.id)} threw: ${String(err)}`);
    }
  }
  return { removed, failed };
}

export default async function globalTeardown(): Promise<void> {
  if (!existsSync(TOKEN_FILE)) {
    console.warn('[teardown] no bearer token on disk; skipping cleanup (setup likely failed)');
    return;
  }
  let token: string;
  try {
    token = readToken();
  } catch (err) {
    console.warn(`[teardown] cannot read token: ${String(err)}`);
    return;
  }
  const api = await request.newContext({
    baseURL: env.apiBaseURL,
    extraHTTPHeaders: { Authorization: `Bearer ${token}` },
  });
  const now = Date.now();
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
      { name: 'tickets', list: routes.tickets, del: routes.ticket },
      { name: 'projects', list: routes.projects, del: routes.project },
      { name: 'contracts', list: routes.contracts, del: routes.contract },
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
    }
    console.log(`[teardown] ${summary.length ? summary.join('; ') : 'nothing to sweep'}`);
  } finally {
    await api.dispose();
  }
}
