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
    // PMS-155 modules (time_tracking, projects, billing, contracts) are
    // tenant-gated: when a module is disabled its list route 404s, `listAll`
    // returns [], and that sweep is a silent no-op - which is fine, a disabled
    // module created no records. Records without a run-suffixed name (time
    // entries, tasks, contract items, invoices, payments) cannot be matched by
    // the name sweep; specs delete those inline, and this backstop only mops up
    // the top-level named residue a failed run leaves behind.
    const tickets = await sweep(api, routes.tickets, routes.ticket, now);
    const projects = await sweep(api, routes.projects, routes.project, now);
    const contracts = await sweep(api, routes.contracts, routes.contract, now);
    const workTypes = await sweep(api, routes.workTypes, routes.workType, now);
    const roundingRules = await sweep(api, routes.roundingRules, routes.roundingRule, now);
    const taskStatuses = await sweep(api, routes.taskStatuses, routes.taskStatus, now);
    const rateCards = await sweep(api, routes.rateCards, routes.rateCard, now);
    const taxRates = await sweep(api, routes.taxRates, routes.taxRate, now);
    const contacts = await sweep(api, routes.contacts, routes.contact, now);
    const companies = await sweep(api, routes.companies, routes.company, now);
    console.log(
      `[teardown] tickets removed=${tickets.removed} failed=${tickets.failed}; ` +
        `projects removed=${projects.removed} failed=${projects.failed}; ` +
        `contracts removed=${contracts.removed} failed=${contracts.failed}; ` +
        `workTypes removed=${workTypes.removed} failed=${workTypes.failed}; ` +
        `roundingRules removed=${roundingRules.removed} failed=${roundingRules.failed}; ` +
        `taskStatuses removed=${taskStatuses.removed} failed=${taskStatuses.failed}; ` +
        `rateCards removed=${rateCards.removed} failed=${rateCards.failed}; ` +
        `taxRates removed=${taxRates.removed} failed=${taxRates.failed}; ` +
        `contacts removed=${contacts.removed} failed=${contacts.failed}; ` +
        `companies removed=${companies.removed} failed=${companies.failed}`,
    );
  } finally {
    await api.dispose();
  }
}
