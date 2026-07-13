#!/usr/bin/env node
// PMS-656: readiness gate for the E2E suite. After a staging data wipe the
// shared bunyip E2E account may not exist, so every login fails and the whole
// suite hard-fails with an opaque "could not get past the credentials step"
// error that reads like a code regression. Bunyip exposes
// `GET /e2e-bootstrapped` -> {bootstrapped: bool}; when it reports the accounts
// are absent, set the step output `skip=true` so the workflow skips the suite
// (the job stays green) with a notice pointing at the re-seed recipe, instead of
// running into a misleading login failure.
//
// Fail-open ON PURPOSE: ONLY an explicit `{bootstrapped: false}` skips. A missing
// endpoint (production never enables it), a non-2xx response, a JSON parse error,
// or any network error all fall through to RUNNING the suite. This gate must
// never hide a real failure - only the known "staging not seeded" one.

import { appendFileSync } from 'node:fs';

function pick(...values) {
  for (const v of values) {
    if (typeof v === 'string' && v.trim() !== '') return v.trim();
  }
  return '';
}

function setSkip(reason) {
  console.log(`::warning::E2E suite skipped: ${reason}`);
  const out = process.env.GITHUB_OUTPUT;
  if (out) appendFileSync(out, 'skip=true\n');
}

// The readiness endpoint lives on the OP host (bunyip), e.g.
// `https://api.a8n.systems`, which is `E2E_OP_BASE_URL` in CI.
const opBaseURL = pick(process.env.E2E_OP_BASE_URL, process.env.E2E_API_BASE_URL).replace(/\/+$/, '');
if (!opBaseURL) {
  console.log('E2E_OP_BASE_URL unset; cannot probe /e2e-bootstrapped. Running the suite.');
  process.exit(0);
}

const url = `${opBaseURL}/e2e-bootstrapped`;
const TIMEOUT_MS = 15_000;
const controller = new AbortController();
const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

console.log(`Checking staging is E2E-seeded: ${url} (timeout ${TIMEOUT_MS / 1000}s)...`);
try {
  const res = await fetch(url, { headers: { accept: 'application/json' }, signal: controller.signal });
  if (!res.ok) {
    console.log(`${url} -> HTTP ${res.status} (no readiness signal); running the suite.`);
    process.exit(0);
  }
  const body = await res.json();
  if (body && body.bootstrapped === false) {
    setSkip(
      'staging reports {bootstrapped:false} - the shared E2E account is not provisioned. ' +
        'Re-seed it (docker repo: `just e2e-bootstrap`), then re-capture E2E_STAGING_TENANT_ID. See e2e/README.md.',
    );
    process.exit(0);
  }
  console.log(`${url} -> bootstrapped=${body?.bootstrapped}; running the suite.`);
} catch (err) {
  console.log(`Could not reach ${url} (${String(err)}); running the suite.`);
} finally {
  clearTimeout(timer);
}
process.exit(0);
