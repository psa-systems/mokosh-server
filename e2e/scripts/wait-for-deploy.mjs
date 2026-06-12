#!/usr/bin/env node
// Deploy-sync gate (PMS-140): block the E2E run until staging actually serves
// a commit at-or-newer than the most recent one that would have produced an
// OCI image.
//
// The build-oci-image.yml workflow only fires when one of a fixed set of
// paths changes (src/, crates/, migrations/, .cargo/, Cargo.toml,
// Cargo.lock, oci-build/, build-oci-image.yml itself). A commit to main
// that touches only docs/tests/CI never republishes :latest, so staging
// keeps serving the PREVIOUS build. Polling for GITHUB_SHA in that case
// times out on a hash staging can never report.
//
// Resolve the expected SHA the same way the build trigger does: walk
// `git log` from GITHUB_SHA backwards, find the most recent commit that
// touched a build-trigger path, and poll for THAT hash. When the current
// commit IS build-relevant, the result equals GITHUB_SHA. When it isn't,
// the result is the latest commit that actually produced an image, which
// is exactly what staging is running.
//
// The script polls <api>/api/v1/version every 15s for up to 10 minutes
// and compares the reported git_hash (12-char short hash, src/version.rs)
// against the resolved expected SHA. On timeout it exits non-zero with a
// clear message so the job fails loudly instead of testing a stale deploy.
//
// The API lives at a separate host from the SPA on the canonical deploy
// (`mokosh.systems` SPA -> `api.mokosh.systems` API). Prefer an explicit
// E2E_API_BASE_URL; otherwise prepend `api.` to E2E_BASE_URL; otherwise
// fall back to the SPA host (same-origin deploys only).
//
// When the separate deploy workflow lands, chain this workflow off its
// completion and drop the polling.

import { execFileSync } from 'node:child_process';

// Keep in lock-step with `on.push.paths` in .forgejo/workflows/build-oci-image.yml.
// A path here that the build workflow does not list will make the gate poll
// for a SHA staging never serves; a path the build lists that this misses
// will make the gate accept a stale deploy. Audit both together.
const BUILD_TRIGGER_PATHS = [
  'src',
  'crates',
  'migrations',
  '.cargo',
  'Cargo.toml',
  'Cargo.lock',
  'oci-build',
  '.forgejo/workflows/build-oci-image.yml',
];

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

function git(args) {
  return execFileSync('git', args, { encoding: 'utf8' }).trim();
}

function isShallow() {
  try {
    return git(['rev-parse', '--is-shallow-repository']) === 'true';
  } catch {
    return false;
  }
}

function tryUnshallow() {
  try {
    console.log('  clone is shallow; running `git fetch --unshallow origin` ...');
    execFileSync('git', ['fetch', '--unshallow', 'origin'], { stdio: 'inherit' });
    return true;
  } catch (err) {
    console.warn(`  unshallow attempt failed: ${String(err)}`);
    return false;
  }
}

// Forgejo's actions/checkout has been observed to clone with --filter=blob:none
// or --filter=tree:0 even when fetch-depth: 0 is set, leaving the local clone
// without the tree objects `git log -- <path>` needs to test path membership.
// The query then silently returns zero matches even though the commits are
// present. `git fetch --refetch origin` repopulates the missing objects.
function tryRefetch() {
  try {
    console.log('  refetching objects without filter (`git fetch --refetch origin`) ...');
    execFileSync('git', ['fetch', '--refetch', 'origin'], { stdio: 'inherit' });
    return true;
  } catch (err) {
    console.warn(`  refetch attempt failed: ${String(err)}`);
    return false;
  }
}

function buildShaQuery(headSha) {
  return git(['log', '-1', '--format=%H', headSha, '--', ...BUILD_TRIGGER_PATHS]);
}

// Return the most recent commit at-or-before `headSha` that touched any
// BUILD_TRIGGER_PATHS entry. The Forgejo runner's actions/checkout has been
// observed to honour fetch-depth: 0 inconsistently AND to apply object
// filters that strip the trees `git log -- <path>` needs, so self-heal in
// two stages: unshallow first if the clone is shallow, then refetch
// without filter if the path query still finds nothing.
function resolveBuildSha(headSha) {
  let sha = buildShaQuery(headSha);
  if (sha) return sha;

  if (isShallow() && tryUnshallow()) {
    sha = buildShaQuery(headSha);
    if (sha) return sha;
  }

  if (tryRefetch()) {
    sha = buildShaQuery(headSha);
    if (sha) return sha;
  }

  const depth = (() => {
    try {
      return git(['rev-list', '--count', headSha]);
    } catch {
      return '?';
    }
  })();
  throw new Error(
    `No commit at-or-before ${headSha} touches any build-trigger path ` +
      `(clone depth=${depth}, shallow=${isShallow()}). Check that ` +
      `BUILD_TRIGGER_PATHS in this script matches ` +
      `.forgejo/workflows/build-oci-image.yml's on.push.paths.`,
  );
}

const spaBaseURL = pick(process.env.E2E_BASE_URL, 'https://mokosh.systems');
const apiBaseURL = pick(
  process.env.E2E_API_BASE_URL,
  deriveApiBase(spaBaseURL),
  spaBaseURL,
).replace(/\/+$/, '');
const headSha = pick(process.env.GITHUB_SHA, process.env.E2E_EXPECT_SHA);

const INTERVAL_MS = 15_000;
const TIMEOUT_MS = 10 * 60 * 1000;
const versionUrl = `${apiBaseURL}/api/v1/version`;

if (!headSha) {
  console.error('GITHUB_SHA is unset; cannot verify the deployed commit. Aborting.');
  process.exit(1);
}

let expectedSha;
try {
  expectedSha = resolveBuildSha(headSha);
} catch (err) {
  // All self-heal attempts failed (probably a runner clone we cannot fix
  // from inside the job). Falling back to GITHUB_SHA on a doc/test-only
  // commit re-creates the very problem this gate is meant to avoid -
  // polling for 10m on a SHA staging never serves. Phase 1 of PMS-140 is
  // informational, not a merge gate, so skip the gate entirely with a
  // loud warning and let the suite run against whatever staging is
  // currently serving.
  console.warn('============================================================');
  console.warn(`SKIPPING deploy-sync gate: ${String(err)}`);
  console.warn('Tests will run against whatever commit staging is currently serving.');
  console.warn('============================================================');
  process.exit(0);
}

if (expectedSha === headSha) {
  console.log(`Head commit ${headSha} is build-relevant; expecting staging to serve it.`);
} else {
  console.log(
    `Head commit ${headSha} did not touch any build-trigger path; ` +
      `expecting staging to serve ${expectedSha} instead (last build-relevant commit).`,
  );
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
