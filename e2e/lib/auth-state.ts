// Persisted bearer token from the setup project, consumed by API tests and
// global teardown. We cannot reuse Playwright's `storageState` for auth
// because the mokosh-clients SPA keeps the access token in WASM memory
// (`mokosh-clients/src/hooks/fetch.rs:189`), not in cookies or localStorage,
// so cookie replay does not authenticate the API context. Direct
// `POST /api/v1/auth/login` is also not an option: the OP advertises only
// authorization_code + refresh_token grants, and SPA accounts created via
// the bunyip hub do not exist in mokosh's local `users` table. Instead the
// setup project drives the SPA login in a real browser and intercepts the
// first `/api/v1` request's `Authorization: Bearer` header (see
// e2e/tests/global.setup.ts), writing the captured token here for the
// `api` project's request fixture and teardown to read.

import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readFileSync, existsSync } from 'node:fs';

const here = dirname(fileURLToPath(import.meta.url));

export const TOKEN_FILE = resolve(here, '..', '.auth', 'token.txt');

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
