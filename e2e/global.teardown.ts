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
// Coverage note: the tickets module exposes no DELETE route
// (src/modules/tickets/routes.rs), so test-created tickets cannot be hard
// deleted via the API. They live in the dedicated E2E tenant with run-suffixed
// titles; their parent companies ARE deleted here. See e2e/README.md.

const PER_PAGE = 200;

interface Named {
  id: string;
  name?: string;
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
    // Contacts first: a company with contacts attached may refuse deletion.
    const contacts = await sweep(api, routes.contacts, routes.contact, now);
    const companies = await sweep(api, routes.companies, routes.company, now);
    console.log(
      `[teardown] contacts removed=${contacts.removed} failed=${contacts.failed}; ` +
        `companies removed=${companies.removed} failed=${companies.failed}`,
    );
  } finally {
    await api.dispose();
  }
}
