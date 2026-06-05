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
