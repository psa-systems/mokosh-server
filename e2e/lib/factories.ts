import { expect, type APIRequestContext } from '@playwright/test';
import { routes } from './api';
import { runSuffix } from './run';

// Create a run-tagged company in the E2E tenant. The tenant scope is implied by
// the authenticated session (every service method scopes to the caller's
// tenant), so no tenant id is sent in the body. Returns the created id + name.
export async function createCompany(
  request: APIRequestContext,
): Promise<{ id: string; name: string }> {
  const name = runSuffix();
  const res = await request.post(routes.companies, { data: { name } });
  expect(res.status(), `create company failed: ${await res.text()}`).toBe(200);
  const body = (await res.json()) as { id: string; name: string };
  expect(body.id).toBeTruthy();
  return body;
}

// Create a run-tagged contact under `companyId`. last_name carries the suffix
// so teardown's name-based sweep can identify it.
export async function createContact(
  request: APIRequestContext,
  companyId: string,
): Promise<{ id: string }> {
  const suffix = runSuffix();
  const res = await request.post(routes.contacts, {
    data: { company_id: companyId, first_name: 'E2E', last_name: suffix },
  });
  expect(res.status(), `create contact failed: ${await res.text()}`).toBe(200);
  const body = (await res.json()) as { id: string };
  expect(body.id).toBeTruthy();
  return body;
}

// Enable a gated module for the E2E tenant. Gated modules
// (time_tracking, projects, billing, contracts, ...) default to DISABLED:
// `is_module_enabled` COALESCEs a missing module_config row to FALSE, so
// every route behind a `RequireModuleEnabled` extractor 404s until the
// module is turned on. The settings upsert route is admin-gated and
// idempotent. A 403 here means the E2E account is not an admin, which is a
// real environment problem the assertion should surface, not swallow.
export async function enableModule(
  request: APIRequestContext,
  module: string,
): Promise<void> {
  const res = await request.put(routes.settingsModule(module), {
    data: { is_enabled: true },
  });
  expect(
    res.ok(),
    `enable module '${module}' -> ${res.status()}: ${await res.text()}`,
  ).toBeTruthy();
}

// The authenticated user's own id + role, read from /auth/me. Time entries
// take an explicit user_id (admins may log for anyone), so a spec needs its
// own id to create one.
export async function getSelf(
  request: APIRequestContext,
): Promise<{ id: string; role: string }> {
  const res = await request.get(routes.authMe);
  expect(res.ok(), `GET /auth/me -> ${res.status()}`).toBeTruthy();
  const body = (await res.json()) as { id: string; role: string };
  expect(body.id).toBeTruthy();
  return body;
}

// Today's date as a YYYY-MM-DD string (NaiveDate wire format the API expects
// for date-only fields like time-entry `date`, invoice/contract dates).
export function today(): string {
  return new Date().toISOString().slice(0, 10);
}
