#!/usr/bin/env node
// Deploy-sync gate (PMS-140): block the E2E run until staging actually serves
// the commit that triggered this workflow.
//
// Polls <api>/api/v1/version every 15s for up to 10 minutes and compares the
// reported git_hash (a 12-char short hash, see src/version.rs) against the
// full GITHUB_SHA. On timeout it exits non-zero with a clear "staging never
// picked up <sha>" message so the job fails loudly instead of testing a
// stale deployment.
//
// The API lives at a separate host from the SPA on the canonical deploy
// (`msp.a8n.systems` SPA -> `api.msp.a8n.systems` API). Prefer an explicit
// E2E_API_BASE_URL; otherwise prepend `api.` to E2E_BASE_URL; otherwise fall
// back to the SPA host (which only works for same-origin deployments).
//
// When the separate deploy workflow lands, chain this workflow off its
// completion and drop the polling.

// Forgejo Actions passes the literal empty string for secrets that are not
// configured, so `??` alone would not fall back. Treat empty/whitespace as
// missing, matching e2e/lib/env.ts.
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

const spaBaseURL = pick(process.env.E2E_BASE_URL, 'https://msp.a8n.systems');
const apiBaseURL = pick(
  process.env.E2E_API_BASE_URL,
  deriveApiBase(spaBaseURL),
  spaBaseURL,
).replace(/\/+$/, '');
const expectedSha = pick(process.env.GITHUB_SHA, process.env.E2E_EXPECT_SHA);

const INTERVAL_MS = 15_000;
const TIMEOUT_MS = 10 * 60 * 1000;
const versionUrl = `${apiBaseURL}/api/v1/version`;

if (!expectedSha) {
  console.error('GITHUB_SHA is unset; cannot verify the deployed commit. Aborting.');
  process.exit(1);
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchGitHash() {
  try {
    const res = await fetch(versionUrl, { headers: { accept: 'application/json' } });
    if (!res.ok) return { ok: false, detail: `HTTP ${res.status}` };
    const body = await res.json();
    return { ok: true, gitHash: String(body.git_hash ?? '') };
  } catch (err) {
    return { ok: false, detail: String(err) };
  }
}

const deadline = Date.now() + TIMEOUT_MS;
console.log(`Waiting for ${versionUrl} to report ${expectedSha} (timeout 10m)...`);

let lastSeen = '';
while (Date.now() < deadline) {
  const result = await fetchGitHash();
  if (result.ok && result.gitHash && expectedSha.startsWith(result.gitHash)) {
    console.log(`Staging is serving ${result.gitHash} (matches ${expectedSha}). Proceeding.`);
    process.exit(0);
  }
  const seen = result.ok ? `git_hash=${result.gitHash || '(empty)'}` : result.detail;
  if (seen !== lastSeen) {
    console.log(`  not yet (${seen}); polling every ${INTERVAL_MS / 1000}s`);
    lastSeen = seen;
  }
  await sleep(INTERVAL_MS);
}

console.error(`Timed out after 10m: staging never picked up ${expectedSha}.`);
process.exit(1);
