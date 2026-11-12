import { test as setup } from '@playwright/test';
import { preflightRequiredEnv } from '../lib/env';

// Runs once before every project. Aggregates ALL missing required env vars
// into a single error so the first failed CI run names every gap, instead
// of dying at the first missing key and forcing the operator to fix-rerun
// one var at a time.
// SPEC-10.216
setup('verify required env vars are present', async () => {
  preflightRequiredEnv();
});
