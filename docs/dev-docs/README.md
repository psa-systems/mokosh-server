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

The user-facing pages (quickstart, architecture, binaries,
configuration, recipes and the rest) are indexed one directory up in
[`docs/README.md`](../README.md). The table below covers this
directory, plus the quickstart that developers reach from here.

## Contents

| Document | Kind | Purpose |
| --- | --- | --- |
| [`quickstart.md`](../quickstart.md) | maintained | Get a fresh clone running on a Linux host. Covers user-level toolchain install, generating the gitignored `.env` from `.env.example`, the Infisical bootstrap, and known footguns. |
| [`local-vs-ci-checks.md`](local-vs-ci-checks.md) | maintained, updated with every check change (PMS-851) | Step-by-step mapping of `.forgejo/workflows/check.yml` onto `just check` and `just pre-commit`, plus the local-only gates (`check-docker`, `test-integration`, `verify-demo`, `test-e2e`) and why each is not in the umbrella recipe. Read before adding a check to either side. |
| [`architecture-seams.md`](architecture-seams.md) | maintained, a section dies when its seam is collapsed | Subsystems that could plausibly own the same job, and which side is canonical: the three identity planes, the dual billing surfaces, the subscription-state and dual-users schema divergences (PMS-198), and what became of the seams PMS-295 retired. Read before touching auth, the portal, billing, or the `tenants` / `users` tables. |
| [`request-body-entry-points.md`](request-body-entry-points.md) | maintained, a row per body extractor (PMS-924) | Every way a request body enters the server, and whether the invisible-character sanitizer covers it, exempts it, or does not apply. Carries the greps that regenerate the set. Read before adding a route that reads a body, especially one that verifies a signature over the raw bytes. |
| [`readme-template.md`](readme-template.md) | maintained convention, applies to every repo in the estate | The eight-section README structure, the rule that detail belongs in `docs/`, and the three mechanical constraints that bite when applying it: the GIF stays commented until its asset is committed, a page that gains a `just` command joins the doc-recipe guard, and the security section invents no disclosure address. |
| [`sla-jsonb-vs-normalized.md`](sla-jsonb-vs-normalized.md) | decision record, PMS-585 | Why `business_hours.schedule` and `holiday_calendars.holidays` stay JSONB instead of being normalized into child tables. |
| [`carddav-contact-sync.md`](carddav-contact-sync.md) | design record, PMS-1292, stale once its first build issue lands | How live CardDAV contact sync (iCloud, Fastmail, Nextcloud) fits the PSA-70 contact-sync pipeline: what needs no change, the one CHECK and one column the schema needs, discovery, `sync-collection` deltas, groups, app-password credentials, the SSRF gate on a tenant-supplied server, and the build breakdown. Read before starting CardDAV. |
| [`teams.md`](teams.md) | decision record, PMS-1162 | The two-axis role model: team member roles versus the app-level RBAC vocabulary, and how they reconcile. |
| [`self-hosted-vs-saas.md`](self-hosted-vs-saas.md) | maintained, one row per capability | The `MOKOSH_DEPLOYMENT_MODE` profile table: what `self-hosted` and `saas` differ on (platform identity, login, password reset, account mail) and what they share (portal identity, business notifications). Read before adding a capability that behaves differently between the two shapes. |
| [`contact-scope-audit.md`](contact-scope-audit.md) | audit record, MAPPS-633 | Cross-Company scope audit for the contact plane: which handlers a portal contact reaches and which two regression suites (`tests/contact_scope.rs`, `tests/contact_scope_expanded.rs`) pin the response scoping. Extend one of those files when adding a contact-reachable endpoint. |
| [`portal-single-host-cutover.md`](portal-single-host-cutover.md) | operator runbook, MAPPS-649 / PMS-945 | The one-host portal migration: what to email each MSP, which env keys to retire, and the DNS + Traefik cutover. Read only if operating a deployment that still runs the pre-MAPPS-649 per-MSP subdomain shape. |
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
