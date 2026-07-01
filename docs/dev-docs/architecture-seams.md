# Architecture seams: duplicated subsystems and their canonical owners

Parallel development left `mokosh-server` with two of several things in a single binary. PMS-198 converged the cheap-to-merge seams (error type, super-admin extractor, `build.rs`, settings upsert, worker lifecycle, RMM filter) in code, and recorded an explicit owner / decision for the seams that are too large or too risky to merge in one change. This document is that record. Read it before touching auth, billing, the `tenants`/`users` tables, or the subscription columns so you modify the canonical side, not the parallel one.

This file is the home for "two of these exist, here is which one wins". When you collapse a seam, strike its row here and move the note into the relevant module.

## Dual auth surfaces

Two authentication systems coexist; both are intentional today.

| Surface | Code | Routes | Identity / token | Session store |
| --- | --- | --- | --- | --- |
| Legacy PSA auth | `src/modules/auth/` | `/api/v1/auth/*` | HS256 JWT in cookie, Argon2 passwords | `public.user_sessions` |
| SSO / OIDC IdP | `crates/mokosh-auth*` | `/v1/auth/*` and the OIDC endpoints | EdDSA `at+jwt` access tokens | `mokosh_auth.*` (sessions, refresh, codes) |

**Shared contract.** The single point where the two meet is `AuthMiddleware` in `src/modules/auth/middleware.rs`: `main.rs` passes the SSO key set into `AuthMiddleware::with_at_jwt(...)`, so the one middleware accepts *either* a legacy HS256 cookie *or* an SSO-issued `at+jwt` and populates the same `AuthState`. Everything downstream (the `RequireAuth` / `RequireRole` / `RequireSuperAdmin` extractors) is token-agnostic by design.

**Ownership rule.** New first-party login / token-issuance work belongs in the SSO subsystem (`crates/mokosh-auth*`); the legacy `src/modules/auth/` surface is in maintenance mode and exists for the original PSA endpoints plus the shared middleware and extractors. Do **not** add a new token format or a third session table. If a change touches "how a request is authenticated", it changes `AuthMiddleware`; if it touches "how a token is minted", it changes `mokosh-auth-oidc`. The legacy flow still owns TOTP verification only because it reuses the `mokosh-auth-crypto` primitive directly (see `CLAUDE.md` "Auth: two systems coexist").

## Dual billing subsystems

Two unrelated subsystems share the word "billing". They are different domains and must not be merged.

| Subsystem | Code | Model | Domain |
| --- | --- | --- | --- |
| SaaS subscription billing | `crates/mokosh-auth-http` (`BillingRepository`, `BillingTier`) | tiers / subscriptions for the platform itself | "what does this tenant pay **us**" |
| MSP invoicing | `src/modules/billing/` (`BillingService`, `Invoice`) | invoices, recurring contract runs, payment-gateway configs | "what does the MSP bill **its own customers**" |

**Ownership rule.** They share only a name, never a type or a table. A change about platform subscription tiers goes to the auth-http crate; a change about MSP-customer invoices, recurring invoicing, or gateway secrets goes to `src/modules/billing/`. When in doubt, the prefix tells you: `BillingTier`/`BillingRepository` = SaaS, `BillingService`/`Invoice`/`RecurringInvoicingWorker` = MSP. Do not introduce a shared `billing` module that tries to host both.

## Subscription state in two schemas (decision recorded)

Subscription state lives in two places with no foreign key or sync:

- `public.tenants.subscription_plan` / `subscription_status` / `trial_ends_at` (`migrations/002_tenants.sql`).
- `mokosh_auth.subscriptions` (the SSO subsystem's own table).

**Decision (PMS-198): `mokosh_auth.subscriptions` is the canonical source of subscription truth; the `public.tenants.subscription_*` columns are a denormalized read cache, not an independent writer.** No cross-schema foreign key is added: a hard FK from `public.tenants` into `mokosh_auth` couples the PSA schema to the optional SSO subsystem (SSO mounts only when its env vars are present), and would block tenant creation when SSO is disabled. Instead the columns stay nullable and advisory. Until a sync path exists, treat the `public.tenants.subscription_*` columns as best-effort display only: never gate access or billing logic on them; read `mokosh_auth.subscriptions` for any decision. A follow-up issue owns writing the one-way `mokosh_auth.subscriptions` -> `public.tenants` projection (a trigger or a small reconciler on the Scheduler); this note records the canonical-store choice so that work does not re-litigate it.

## Dual users tables (decision recorded)

Two user tables are both written today, with different security postures:

- `public.users` (`migrations/003_auth.sql`): legacy PSA users, `mfa_secret` stored as **plaintext** `VARCHAR(100)`.
- `mokosh_auth.users` + `mokosh_auth.user_totp`: SSO users, TOTP secret stored under **AES-256-GCM**.

**Decision (PMS-198): `mokosh_auth.users` is the canonical user store going forward; `public.users` is retained only for the legacy PSA endpoints and is frozen for new identity features.** The two are NOT merged in this change: collapsing them touches every PSA service method (each takes a `tenant_id` and joins `public.users`) and the live RLS policies, which is too large and too risky for one PR. The immediate security divergence (plaintext `public.users.mfa_secret`) is tracked as its own follow-up: either migrate legacy MFA enrolment onto `mokosh_auth.user_totp` or encrypt the column in place; no new code may read or write `public.users.mfa_secret` in plaintext. Recording the canonical store here is the prerequisite the issue called out ("decide the canonical store first") before the migration is scheduled.
