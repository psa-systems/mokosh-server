// Shared on-failure diagnostic capture for browser-driven tests. The setup
// project pioneered this pattern (e2e/tests/global.setup.ts): track every
// top-frame URL transition and every request URL, dump them on failure so
// the next iteration is precise instead of speculative. This module
// generalises it so auth.spec.ts can use the same shape.

import type { Page, Response } from '@playwright/test';

// Cap on URL samples included in the diagnostic. High enough to see the
// actual SPA traffic pattern, low enough to keep the error readable.
const URL_SAMPLE_CAP = 30;

// Chars of a non-2xx main-frame body kept in the diagnostic. Enough for a
// framework error line (bunyip's authorize returns a one-line plain-text
// deserialize error) without pasting a whole HTML error page into the log.
const RESPONSE_BODY_CAP = 500;

export type MainFrameResponse = {
  status: number;
  url: string;
  // First RESPONSE_BODY_CAP chars, captured for non-2xx only and filled in
  // asynchronously (best-effort: a redirect or a torn-down context has no
  // readable body).
  body?: string;
};

export type MainFrameResponseLog = {
  entries(): MainFrameResponse[];
  last(): MainFrameResponse | null;
  // One-line "status url" for the most recent main-frame document response,
  // for folding into a thrown error.
  describeLast(): string;
};

// One log per page: both attachPageDiagnostics and the login helper want the
// main-frame response trail, and registering the listener twice would double
// every entry.
const logs = new WeakMap<Page, MainFrameResponseLog>();

/// Record every main-frame document response (status + URL, plus a truncated
/// body for non-2xx) on `page`. Idempotent per page. Attach before the
/// navigation you care about; responses that arrive earlier are not replayed.
///
/// PMS-721: without this, a login that parks on `/oauth2/authorize` is
/// indistinguishable in the CI log from a redirect that was never followed or
/// a selector that drifted, because fj cannot download the Playwright trace.
export function mainFrameResponseLog(page: Page): MainFrameResponseLog {
  const existing = logs.get(page);
  if (existing) return existing;

  const entries: MainFrameResponse[] = [];
  page.on('response', (res: Response) => {
    if (!isMainFrameDocument(page, res)) return;
    const entry: MainFrameResponse = { status: res.status(), url: res.url() };
    entries.push(entry);
    if (res.status() < 200 || res.status() >= 300) {
      res.text().then(
        (text) => {
          entry.body = truncate(text.replace(/\s+/g, ' ').trim(), RESPONSE_BODY_CAP);
        },
        () => {
          // Redirects and responses whose context is gone have no body. The
          // status + URL already carry the signal.
        },
      );
    }
  });

  const log: MainFrameResponseLog = {
    entries: () => entries.slice(),
    last: () => entries[entries.length - 1] ?? null,
    describeLast: () => {
      const entry = entries[entries.length - 1];
      if (!entry) return '(none recorded)';
      return `${entry.status} ${entry.url}${entry.body ? ` body="${entry.body}"` : ''}`;
    },
  };
  logs.set(page, log);
  return log;
}

// `request.frame()` throws for service-worker-initiated requests, which have no
// frame; those are never the navigation we are diagnosing.
function isMainFrameDocument(page: Page, res: Response): boolean {
  const req = res.request();
  if (req.resourceType() !== 'document') return false;
  try {
    return req.frame() === page.mainFrame();
  } catch {
    return false;
  }
}

function truncate(text: string, cap: number): string {
  return text.length > cap ? `${text.slice(0, cap)}... (truncated)` : text;
}

/// Attach request + framenavigated + response listeners to `page` and return a
/// `snapshot(label)` that renders the accumulated trail as a multi-line
/// string suitable for folding into a thrown error message. The page is
/// captured at attach time so callers cannot accidentally hand in a stale
/// or different one at snapshot time.
export function attachPageDiagnostics(page: Page): {
  snapshot(label: string): string;
} {
  const urlTrail: string[] = [];
  const allRequestUrls: string[] = [];
  const responses = mainFrameResponseLog(page);
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
      const mainFrameResponses = responses
        .entries()
        .map((r) => `${r.status} ${r.url}${r.body ? `\n      body="${r.body}"` : ''}`);
      return [
        `${label}:`,
        `  currentUrl=${page.url()}`,
        `  urlTrail (last ${URL_SAMPLE_CAP}):\n    ${sample(urlTrail)}`,
        `  mainFrameResponses (last ${URL_SAMPLE_CAP}):\n    ${sample(mainFrameResponses)}`,
        `  requests (last ${URL_SAMPLE_CAP}):\n    ${sample(allRequestUrls)}`,
      ].join('\n');
    },
  };
}
