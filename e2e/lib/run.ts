// Run-scoped identifiers and naming for test-created records.
//
// Test data policy (PMS-140): every record a test creates carries a unique
// suffix tied to this run and an embedded creation timestamp. Global teardown
// deletes everything THIS run created, then sweeps any e2e-prefixed residue
// older than STALE_MS left behind by earlier failed runs.

// Prefix shared by every record the suite ever creates. Teardown's stale sweep
// keys off this.
export const E2E_PREFIX = 'e2e';

// Records older than this are considered abandoned residue and swept.
export const STALE_MS = 24 * 60 * 60 * 1000; // 24h

// Epoch millis captured once at module load == effectively run start.
const RUN_STARTED_AT = Date.now();

// Stable, filesystem/url-safe run id. Prefer the CI run id; fall back to the
// run-start timestamp for local runs.
export const RUN_ID = (
  process.env.GITHUB_RUN_ID ??
  process.env.E2E_RUN_ID ??
  String(RUN_STARTED_AT)
)
  .replace(/[^a-zA-Z0-9]/g, '')
  .slice(0, 24);

let counter = 0;

// Unique suffix for a single record, e.g. `e2e-1717545600000-1234567890-3`.
// Shape: <prefix>-<epochMs>-<runId>-<n>. The epoch is what the stale sweep
// parses; the runId is what same-run teardown matches on.
export function runSuffix(): string {
  counter += 1;
  return `${E2E_PREFIX}-${RUN_STARTED_AT}-${RUN_ID}-${counter}`;
}

// Matches an embedded tag `e2e-<epochMs>-<runId>-<n>` anywhere in a string
// (record names may be prefixed by other text, e.g. a contact full_name).
const TAG_RE = new RegExp(`${E2E_PREFIX}-(\\d{10,})-([a-zA-Z0-9]+)-(\\d+)`);

// True when `name` carries a tag created by THIS run.
export function isOwnedByThisRun(name: string | null | undefined): boolean {
  if (!name) return false;
  const m = TAG_RE.exec(name);
  return !!m && m[2] === RUN_ID;
}

// Parsed creation epoch from an embedded e2e tag, or null when absent.
export function createdAtMs(name: string | null | undefined): number | null {
  if (!name) return null;
  const m = TAG_RE.exec(name);
  if (!m) return null;
  const epoch = Number(m[1]);
  return Number.isFinite(epoch) && epoch > 0 ? epoch : null;
}

// True for e2e residue older than STALE_MS (swept regardless of which run made it).
export function isStale(name: string | null | undefined, now = Date.now()): boolean {
  const created = createdAtMs(name);
  return created !== null && now - created > STALE_MS;
}
