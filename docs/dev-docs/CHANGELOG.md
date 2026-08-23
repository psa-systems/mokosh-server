# Changelog

Internal, name-free history for mokosh-server. Retired point-in-time docs (milestone handoffs, audit reports) are distilled here so the tree keeps only forward-useful reference material. Entries are newest-first and vary in depth.

## 2026-08-22 - `codebase-state.md` frozen at its snapshot date (PMS-849)

- `codebase-state.md` is now titled and dated as the 2026-05-06 snapshot it always was, and is no longer described anywhere as living, authoritative or current. Three consecutive doc audits (2026-08-08, 2026-08-10, 2026-08-15) found it stale while it claimed to be current, after PMS-684 had already corrected it once; the claim was the defect, not any single wrong cell. It stays in place, and stays worth reading, for the `F1..F14` ids and the numbered cross-cutting issues that source comments and YouTrack issues cite.
- Its "At a glance" metrics table was deleted rather than corrected. Every row was derivable from the tree in one command (it still read `Tests | 0`, and counted schema tables in the pre-PMS-128 migration monolith), so the section now names the commands instead of carrying the numbers.
- `dev-docs/README.md` stopped calling the directory a living snapshot of one 2026-05-06 audit. It now lists every file in the set with what kind of document it is, since most of them are topical decision records with nothing to do with that audit.

## 2026-07-01 - Docs reorganization and history sanitization

- Markdown consolidated under `docs/` (public / how-to) and `docs/dev-docs/` (internal working notes); `README.md` and `CLAUDE.md` stay at the repo root, README files stay colocated with their code. References in `CLAUDE.md`, source comments, migration comments, and the e2e specs were repointed.
- Retired audits and the 2026-05 milestone-1 handoff were removed and distilled into the entries below. `codebase-state.md` was kept (it was then treated as the authoritative per-module status and F1..F14 tracker) and moved to `docs/dev-docs/`.
- Test fixtures that used a real person's name now use a fictitious one. The local-only `For AI/` scratch directory is now gitignored. Contributor names were stripped from commit-message text in a companion history rewrite; git author/committer fields were left unchanged.

## 2026-06-25 - Security audit (distilled)

An internal security audit reviewed mokosh-server; medium / low / info findings were triaged under a single tracking issue with per-finding dispositions (fixed / risk-accepted / follow-up), and the criticals/highs were filed as their own issues. Specifics are intentionally omitted from this public-tree changelog; the tracked issues carry the detail.

## 2026-06-14 - URL field validation sweep (distilled)

An external review found the New Company form accepted an invalid website value with no error while the sibling phone field rejected bad input. A sweep audited every URL-shaped request field on `Deserialize + Validate` DTOs and recorded a validation decision for each, closing the inconsistent-validation gap.

## 2026-06 - RLS GUC routing (distilled)

Step toward fail-closed row-level security: every tenant-scoped read and write in `src/modules/` was routed through `Database::begin_with_tenant` (`src/db/pool.rs`), which runs the statement inside a transaction that has set the `app.current_tenant` GUC. The RLS policy stayed fail-open at the time (behavior-neutral change), so the GUC is guaranteed present for a later fail-closed flip.

## 2026-06-06 - Multi-repo platform audit (distilled)

A file-granularity audit read every source file across bunyip, mokosh-apps, and mokosh-server (~580 files) with git-forensic reconstruction and a cross-repo contract check on the apps-to-server boundary. High and critical findings were adversarially verified against live source before scoring. Nothing was modified by the audit; findings were filed as remediation issues.

Baseline: 409 total findings (3 critical, 37 high, 197 medium, 172 low; 11 rejected on verification), spanning 146 correctness, 19 cross-repo contract-drift, 82 "too many cooks", 131 dead/unused, and 31 infra/CI.

Headline findings that concerned mokosh-server:

- Zero-key credential vault (critical): the assets service was constructed without its encryption key, so credential-vault and configuration-item secrets were encrypted under an all-zeros key. Fix: pass the real key and re-encrypt existing rows.
- Mutable `:latest` production image (critical): the image-build push trigger plus the tag script let any feature branch overwrite the `:latest` production image. Fix: gate the push job to main and tags only.
- MFA bypass via federated login (high): the Google login path created a session and issued tokens without the MFA gate the password path enforces. Fix: apply the same MFA check on the federated path.
- Refresh token accepted as access (high): the legacy HS256 middleware path decoded tokens without asserting the token type and accepted a refresh token as a Bearer access credential. Fix: assert `typ == "access"` after decode.
- Count-query / WHERE-placeholder family: filtered-list COUNT statements bound fewer placeholders than the shared WHERE clause used, so filtered lists could 500. Recurred wherever the SELECT-plus-COUNT idiom was copied without a filtered-list test.

Cross-cutting themes and the full per-finding detail lived in the audit tree that this entry replaces; the remediation issues carry the actionable items forward.

## 2026-05 - Milestone 1: foundation (distilled)

Milestone 1 stood up mokosh-server as the PSA backend (multi-module Axum service, SQLx migrations embedded at compile time, tenant-scoped services taking `tenant_id` explicitly with no middleware-level scoping). At the milestone the schema was well ahead of the handler layer: only a few module groups (auth, contacts, tenants, tickets) had real handlers while the rest returned HTTP 501. Per-module status and the running fix list (`F1..F14`) were recorded in `docs/dev-docs/codebase-state.md`, frozen at its 2026-05-06 snapshot since PMS-849.
