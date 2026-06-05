#!/usr/bin/env node
// Deploy-sync gate (PMS-140): block the E2E run until staging actually serves
// the commit that triggered this workflow.
//
// Polls <E2E_BASE_URL>/api/v1/version every 15s for up to 10 minutes and
// compares the reported git_hash (a 12-char short hash, see src/version.rs)
// against the full GITHUB_SHA. On timeout it exits non-zero with a clear
// "staging never picked up <sha>" message so the job fails loudly instead of
// testing a stale deployment.
//
// When the separate deploy workflow lands, chain this workflow off its
// completion and drop the polling.

const baseURL = (process.env.E2E_BASE_URL ?? 'https://msp.a8n.systems').replace(/\/+$/, '');
const expectedSha = (process.env.GITHUB_SHA ?? process.env.E2E_EXPECT_SHA ?? '').trim();

const INTERVAL_MS = 15_000;
const TIMEOUT_MS = 10 * 60 * 1000;
const versionUrl = `${baseURL}/api/v1/version`;

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
