# Mokosh-server developer docs

Internal reference for developers working on `mokosh-server`. This
directory is a set of independent documents, not one snapshot. They
have different vintages and different obligations: some are kept in
step with the code, some are records of a single investigation, and
one is explicitly frozen. The table below says which is which, and
that is the first thing to read.

Nothing here is the source of truth for what the server currently
does. The code is, and the repo [`CLAUDE.md`](../../CLAUDE.md) is the
maintained prose summary of it.

## Contents

| Document | Kind | Purpose |
| --- | --- | --- |
| [`quickstart.md`](../quickstart.md) | maintained | Get a fresh clone running on a Linux host. Covers user-level toolchain install, generating the gitignored `.env` from `.env.example`, the Infisical bootstrap, and known footguns. |
| [`local-vs-ci-checks.md`](local-vs-ci-checks.md) | maintained, updated with every check change (PMS-851) | Step-by-step mapping of `.forgejo/workflows/check.yml` onto `just check` and `just pre-commit`, plus the local-only gates (`check-docker`, `test-integration`, `verify-demo`, `test-e2e`) and why each is not in the umbrella recipe. Read before adding a check to either side. |
| [`architecture-seams.md`](architecture-seams.md) | maintained, a section dies when its seam is collapsed | Subsystems that could plausibly own the same job, and which side is canonical: the three identity planes, the dual billing surfaces, the subscription-state and dual-users schema divergences (PMS-198), and what became of the seams PMS-295 retired. Read before touching auth, the portal, billing, or the `tenants` / `users` tables. |
| [`sla-jsonb-vs-normalized.md`](sla-jsonb-vs-normalized.md) | decision record, PMS-585 | Why `business_hours.schedule` and `holiday_calendars.holidays` stay JSONB instead of being normalized into child tables. |
| [`qa-test-plan.md`](qa-test-plan.md) | reusable prompt | The no-shortcuts QA agent prompt for driving the app end to end through a browser plus the API, and the rules that exist because an earlier pass took each of those shortcuts. |
| [`security/`](security/) | point-in-time records, each named for its issue | One-off audits and sweeps kept for their reasoning, not for their status: the auth / login / 2FA / session review (PMS-625) and the map of where a portal request path touches `users` (PMS-820). Findings were dispositioned on those issues; the tracker, not the file, says what is still open. |
| [`pms-263-verify-no-comingled-business-rows.sql`](pms-263-verify-no-comingled-business-rows.sql) | runnable query | Human-runnable form of the PMS-263 assertion that no user-created row is left in the shared default tenant. |
| [`CHANGELOG.md`](CHANGELOG.md) | historical narrative, newest-first | Distilled history of retired point-in-time docs, so the tree keeps only forward-useful reference material. |
| [`codebase-state.md`](codebase-state.md) | **frozen 2026-05-06 snapshot** (PMS-849) | The 2026-05-06 audit: per-module route catalog, cross-cutting issues, and the `F1..F14` fix list. Not maintained and not current. Useful for the `F` ids and the numbered cross-cutting issues that source comments cite; every count, line number and status claim in it is from 2026-05-06. |

## Where current state actually lives

1. [`src/api/router.rs`](../../src/api/router.rs) for what is mounted,
   and the "Routing model" section of the repo
   [`CLAUDE.md`](../../CLAUDE.md) for what authenticates a request to
   each top-level nest under `/api/v1`, including the unauthenticated
   `/api/v1/public/*` subtree, the portal router, and the bunyip and
   Stripe webhook receivers.
2. [`architecture-seams.md`](architecture-seams.md) when the change
   touches a subsystem that has a parallel twin.
3. The tree for any count. Every metric that used to sit in a table in
   [`codebase-state.md`](codebase-state.md) is one command against
   `migrations/`, `tests/` or `src/modules/`, which is why the table is
   gone rather than corrected.

## Conventions

- File paths are relative to the repo root (e.g.
  [`src/api/router.rs`](../../src/api/router.rs)).
- "F1..F14" identifiers reference the 2026-05-06 proposed fixes in
  [`codebase-state.md`](codebase-state.md#proposed-fixes). Several
  shipped; the ids survive because source comments and YouTrack issues
  cite them.
- Endpoint paths are full (`/api/v1/auth/login`) unless inside a
  per-module section that has already established the prefix.

## Keeping these docs honest

- Do not append to [`codebase-state.md`](codebase-state.md). It is
  frozen at its snapshot date. A new route group is recorded in the
  "Routing model" list in the repo [`CLAUDE.md`](../../CLAUDE.md),
  which is the list that is maintained.
- Never write a derivable count into prose here. It will be wrong
  within a month and a reader cannot tell. Name the command instead.
- A document that records one point in time carries that date in its
  first lines, and a document that stops being maintained says so in
  the same change that stops maintaining it. The defect these files
  kept shipping was not being out of date; it was claiming to be
  current while out of date.
- Add a file here, add its row above. A document nobody can classify
  from the table is the next `codebase-state.md`.
- These files are versioned with the source, so the project history is
  the change log.
