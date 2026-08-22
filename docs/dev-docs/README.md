# Mokosh-server developer docs

Internal reference for developers working on `mokosh-server`. The
content here is derived from a 2026-05-06 codebase audit; treat it
as a living snapshot and update it alongside the code changes that
invalidate any of its claims. The same audit produced matching
documentation in
[`mokosh-clients/dev-docs/`](../../mokosh-clients/dev-docs/).

## Contents

| Document | Purpose |
| --- | --- |
| [`quickstart.md`](../quickstart.md) | Get a fresh clone running on a Linux host. Covers user-level toolchain install, generating the gitignored `.env` from `.env.example`, the Infisical bootstrap, and known footguns. |
| [`codebase-state.md`](codebase-state.md) | Per-module route catalog, cross-cutting issues, and proposed fixes (`F1..F14`). Sections dated 2026-05-06 carry a historical banner; read the 2026-07-24 correction at the top first. |
| [`local-vs-ci-checks.md`](local-vs-ci-checks.md) | Step-by-step mapping of `.forgejo/workflows/check.yml` onto `just check` and `just pre-commit`, plus the local-only gates (`check-docker`, `test-integration`, `verify-demo`, `test-e2e`) and why each is not in the umbrella recipe. Read before adding a check to either side. |
| [`architecture-seams.md`](architecture-seams.md) | Duplicated subsystems that intentionally still coexist (dual auth surfaces, dual billing subsystems) and the canonical-store decisions for the subscription-state and dual-users schema divergences (PMS-198). Read before touching auth, billing, or the `tenants`/`users` tables. |

## Recommended reading order

1. **[`codebase-state.md`](codebase-state.md)** first if you are
   touching server code: it catalogues the route groups and the
   known bugs. Read its 2026-07-24 correction first; the sections
   dated 2026-05-06 are kept for history, not as current state.
2. The **"Routing model"** section of the repo
   [`CLAUDE.md`](../../CLAUDE.md) when planning a new feature
   module: it names every top-level nest under `/api/v1` and what
   authenticates a request to each one.

## Conventions

- File paths are relative to the repo root (e.g.
  [`src/api/router.rs`](../src/api/router.rs)).
- "F1..F14" identifiers reference proposed fixes in
  [`codebase-state.md`](codebase-state.md#proposed-fixes).
- Endpoint paths are full (`/api/v1/auth/login`) unless inside a
  per-module section that has already established the prefix.

## Keeping these docs honest

If you land a change that:

- adds a route group, **append it to**
  [`codebase-state.md`](codebase-state.md#per-module-status) and to
  the "Routing model" list in the repo
  [`CLAUDE.md`](../../CLAUDE.md);
- closes a TODO, **strike it from the per-module entry**;
- introduces a new cross-cutting bug, **add it to** the
  [Cross-cutting issues](codebase-state.md#cross-cutting-issues)
  list with a stable numeric id.

These files are versioned with the source so the project history is
the change log.
