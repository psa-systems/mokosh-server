// Shared on-failure diagnostic capture for browser-driven tests. The setup
// project pioneered this pattern (e2e/tests/global.setup.ts): track every
// top-frame URL transition and every request URL, dump them on failure so
// the next iteration is precise instead of speculative. This module
// generalises it so auth.spec.ts can use the same shape.

import type { Page } from '@playwright/test';

// Cap on URL samples included in the diagnostic. High enough to see the
// actual SPA traffic pattern, low enough to keep the error readable.
const URL_SAMPLE_CAP = 30;

/// Attach request + framenavigated listeners to `page` and return a
/// `snapshot(label)` that renders the accumulated trail as a multi-line
/// string suitable for folding into a thrown error message. The page is
/// captured at attach time so callers cannot accidentally hand in a stale
/// or different one at snapshot time.
export function attachPageDiagnostics(page: Page): {
  snapshot(label: string): string;
} {
  const urlTrail: string[] = [];
  const allRequestUrls: string[] = [];
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) urlTrail.push(frame.url());
  });
  page.on('request', (req) => {
    allRequestUrls.push(req.url());
  });

  return {
    snapshot(label: string): string {
      const sample = (arr: string[]) =>
        arr.length === 0 ? '(none)' : arr.slice(-URL_SAMPLE_CAP).join('\n    ');
      return [
        `${label}:`,
        `  currentUrl=${page.url()}`,
        `  urlTrail (last ${URL_SAMPLE_CAP}):\n    ${sample(urlTrail)}`,
        `  requests (last ${URL_SAMPLE_CAP}):\n    ${sample(allRequestUrls)}`,
      ].join('\n');
    },
  };
}
