#!/usr/bin/env node
// PR-mode reachability check (PMS-141): a PR's SHA never deploys to staging,
// so the wait-for-deploy.mjs `/version` SHA gate would always time out for
// PRs. Replace it with a one-shot `GET /api/v1/health` that just confirms
// staging is up and the suite has something to talk to. The actual coverage
// gate is the Playwright suite that runs after this script.

function pick(...values) {
  for (const v of values) {
    if (typeof v === 'string' && v.trim() !== '') return v.trim();
  }
  return '';
}

function deriveApiBase(spaUrl) {
  try {
    const u = new URL(spaUrl);
    if (u.hostname.startsWith('api.')) return '';
    return `${u.protocol}//api.${u.hostname}`;
  } catch {
    return '';
  }
}

const spaBaseURL = pick(process.env.E2E_BASE_URL, 'https://mokosh.systems');
const apiBaseURL = pick(
  process.env.E2E_API_BASE_URL,
  deriveApiBase(spaBaseURL),
  spaBaseURL,
).replace(/\/+$/, '');

const healthUrl = `${apiBaseURL}/api/v1/health`;
const TIMEOUT_MS = 30_000;

console.log(`PR mode: probing ${healthUrl} (timeout ${TIMEOUT_MS / 1000}s)...`);

const controller = new AbortController();
const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

try {
  const res = await fetch(healthUrl, {
    headers: { accept: 'application/json' },
    signal: controller.signal,
  });
  if (!res.ok) {
    console.error(`Staging /api/v1/health returned HTTP ${res.status}.`);
    process.exit(1);
  }
  console.log(`Staging /api/v1/health -> ${res.status} ok. Proceeding.`);
} catch (err) {
  console.error(`Could not reach ${healthUrl}: ${String(err)}`);
  process.exit(1);
} finally {
  clearTimeout(timer);
}
