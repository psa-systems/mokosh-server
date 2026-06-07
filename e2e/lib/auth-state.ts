// Persisted bearer token + OP cookies from the setup project, consumed by
// API tests and global teardown.
//
// Two artifacts live in `.auth/`:
//
// - `token.txt`: the bunyip-issued access_token captured during SPA login.
//   The `api` project's request fixture (`lib/fixtures.ts`) injects it as
//   `Authorization: Bearer`. We cannot reuse Playwright's `storageState`
//   for this because the mokosh-clients SPA keeps the token in WASM
//   memory (`mokosh-clients/src/hooks/fetch.rs:189`), not in cookies or
//   localStorage, so cookie replay does not authenticate the API context.
//   Direct `POST /api/v1/auth/login` is also not an option: the OP
//   advertises only authorization_code + refresh_token grants, and SPA
//   accounts created via the bunyip hub do not exist in mokosh's local
//   `users` table.
//
// - `op-state.json`: a Playwright `storageState`-shaped JSON containing
//   the cookies the OP needs to recognise the user's session. The OIDC
//   test (`tests/oidc.spec.ts`) replays these via
//   `request.newContext({ storageState })` so that `/oauth2/authorize`
//   sees a server-validated OP session (bunyip PR #67) and 302s straight
//   to the registered redirect_uri with a `code`, instead of bouncing to
//   the hub login screen. Per-request bearer is NOT attached here on
//   purpose: bunyip's authorize handler treats an inbound bearer as a
//   foreign-audience token and ignores it; the cookie is the session
//   signal, the bearer is the resource credential, and the OIDC fixture
//   speaks only the former.
//
// Setup writes both files in one pass after a successful login; the
// teardown reads `token.txt` only.

import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync, existsSync } from 'node:fs';

const here = dirname(fileURLToPath(import.meta.url));

export const TOKEN_FILE = resolve(here, '..', '.auth', 'token.txt');
export const OP_STORAGE_STATE_FILE = resolve(here, '..', '.auth', 'op-state.json');

export function readToken(): string {
  if (!existsSync(TOKEN_FILE)) {
    throw new Error(
      `Missing ${TOKEN_FILE}. The setup project must run before tests that read ` +
        `the token; check that this project declares dependencies: ['setup'].`,
    );
  }
  const token = readFileSync(TOKEN_FILE, 'utf-8').trim();
  if (!token) {
    throw new Error(`Empty token in ${TOKEN_FILE}; setup project probably failed`);
  }
  return token;
}

// Shape Playwright's `request.newContext({ storageState })` expects when
// passed as an object literal. We only populate `cookies`; `origins` (which
// would carry localStorage entries) is left empty because the OP session
// lives entirely in cookies. Re-declared here rather than imported from
// Playwright so the file type-checks under a `node` lib without pulling
// the `@playwright/test` typings into shared code.
export interface OpStorageState {
  cookies: Array<{
    name: string;
    value: string;
    domain: string;
    path: string;
    expires: number;
    httpOnly: boolean;
    secure: boolean;
    sameSite: 'Strict' | 'Lax' | 'None';
  }>;
  origins: never[];
}

export function readOpStorageState(): OpStorageState {
  if (!existsSync(OP_STORAGE_STATE_FILE)) {
    throw new Error(
      `Missing ${OP_STORAGE_STATE_FILE}. The setup project must run before ` +
        `tests that read OP cookies; check that this project declares ` +
        `dependencies: ['setup'].`,
    );
  }
  const raw = readFileSync(OP_STORAGE_STATE_FILE, 'utf-8');
  const parsed = JSON.parse(raw) as OpStorageState;
  if (!Array.isArray(parsed.cookies) || parsed.cookies.length === 0) {
    throw new Error(
      `${OP_STORAGE_STATE_FILE} has no cookies; setup probably ran before ` +
        `the SPA established an OP session, or the OP hostname filter ` +
        `excluded everything. Check setup's diagnostic output.`,
    );
  }
  return parsed;
}
