# Architecture seams: parallel subsystems and their canonical owners

`mokosh-server` has several places where two subsystems could plausibly own the same job. This file is the record of which one wins, so a change lands on the canonical side instead of the parallel one. Read it before touching auth, the portal, billing, or the `tenants` / `users` tables.

PMS-198 merged the cheap duplications in code (one `AppError` in `src/utils/error.rs`, one `RequireSuperAdmin` extractor in `src/modules/auth/middleware.rs`, one root `build.rs`, one settings upsert, one worker lifecycle, one RMM filter) and recorded the rest here. PMS-295 then deleted the `crates/mokosh-auth*` subsystem outright, which collapsed three of the four seams this file used to describe; "Retired seams" at the end says what became of them.

When you collapse a seam, delete its section here and move whatever is still true into the module it belongs to.

## Three identity planes

Three credential systems coexist and all three are intentional. They share extractors and error shapes, never identities.

| Plane | Code | Routes | Credential | Server-side state |
| --- | --- | --- | --- | --- |
| Platform, bunyip-as-OP | `src/modules/auth/oidc_rs.rs`, wired by `AuthMiddleware::with_bunyip` in `src/api/router.rs` | every `/api/v1/*` route that takes `RequireAuth` and friends | bunyip-issued RFC 9068 `at+jwt` Bearer, verified against bunyip's JWKS (`OIDC_ISSUER` + `OIDC_AUDIENCE`) | none in mokosh; bunyip owns the session. `place_bunyip_user` JIT-provisions a local `public.users` shadow row |
| Platform, legacy password | `src/modules/auth/service.rs` + `middleware.rs` | `/api/v1/auth/*` | HS256 JWT in a cookie, Argon2 password, TOTP (`src/utils/totp.rs`) and recovery codes (`src/utils/recovery.rs`) | `public.user_sessions`, plus the credential columns on `public.users` |
| Customer portal | `src/modules/portal/` | `/api/v1/portal/*` | HS256 Bearer JWT tagged `typ = "portal_access"`, minted from a `contacts` row (`is_portal_user`, `portal_password_hash`, `migrations/004_contacts.sql`) | none for the session; setup and reset links live in `portal_setup_tokens` |

**Shared contract.** `auth_middleware` (`src/modules/auth/middleware.rs`) is the single point where the two platform planes meet: it accepts either a bunyip `at+jwt` or a legacy cookie and populates the same `AuthState`, so every downstream extractor (`RequireAuth`, `RequireRole`, `RequireAdmin`, `RequireSuperAdmin`, `RequireModuleEnabled`, ...) is credential-agnostic. Both platform planes then run the same `AuthService::ensure_principal_usable` gate (PMS-698), so a deactivated user or a suspended tenant is refused on the next request whichever credential it carried. The portal plane has its own `portal_auth_middleware` and never produces an `AuthState`.

**Ownership rule.** mokosh mints no platform access token. bunyip is the sole OP since PMS-295 and this repo hosts no `/oauth2/*` surface, so new first-party login or token-issuance work belongs in bunyip, not here. What mokosh still owns is two credential lifecycles, and they are separate on purpose:

- The legacy password path (`src/modules/auth/service.rs`) is in maintenance mode and exists for the original PSA endpoints. Fix its bugs; do not build new identity features on it, and do not add a third platform token format or a second platform session table.
- The portal path (`src/modules/portal/service.rs`) owns its whole credential lifecycle: login, setup-password, forgot-password, reset-password. A portal identity is a `contacts` row, so one email address can hold a platform account and a portal identity in several tenants at once. Never point a portal user at `/api/v1/auth/*`: that is the PMS-820 defect, where a customer resetting a portal password reset a staff login instead.

Where a change lands: "how is this request authenticated" is `AuthMiddleware`; "how is a bunyip token validated" is `oidc_rs.rs`; "how does a portal customer sign in" is `src/modules/portal/`.

## "Billing" means two unrelated domains

Two things in this repo answer to the word "billing". They are different domains and must not be merged.

| Subsystem | Code | Domain |
| --- | --- | --- |
| MSP invoicing | `src/modules/billing/` (`BillingService`, `Invoice`, `RecurringInvoicingWorker`, `stripe_webhook.rs`) | what the MSP bills **its own customers** |
| Platform subscription state | `public.tenants.subscription_plan` / `subscription_status` / `trial_ends_at` (`migrations/002_tenants.sql:24`) | what a tenant would pay **us** |

**Ownership rule.** They share a word, never a type and never a table. Invoices, recurring contract runs, payment-gateway configs and the per-tenant Stripe webhook receiver (`/api/v1/stripe/webhooks/{tenant_id}`, PMS-711) are MSP-side and live in `src/modules/billing/`. Nothing else in the tree implements platform subscription billing: the repository that did (`BillingRepository` / `BillingTier` in `crates/mokosh-auth-http`) left with PMS-295.

**The three `tenants.subscription_*` columns are inert.** `TenantService::create` writes them once at tenant creation (`src/modules/tenants/service.rs:175`, with a 14-day `trial_ends_at`) and the read DTOs echo them back; nothing in `src/` reads them for a decision. They are display fields with no ongoing writer and no subscription system behind them, so do not gate access, module enablement or billing logic on them. Tenant-level access control is `tenants.status` plus `ensure_principal_usable`; feature access is `RequireModuleEnabled` over `module_config`.

## Three name-shaped values that are not each other

A change that "unifies the name" will hit all three of these. They answer different questions and none is derivable from another.

| Value | Owner | Scope | Answers |
| --- | --- | --- | --- |
| App name | `tenant_settings` `('system', 'app_name')` on the default tenant, cached by `src/utils/app_name.rs` | one per deployment | "which product is this" - psa.systems vs staging. Renders in invitation and test mail, the TOTP issuer, the workflow-automation fallback subject, and the catch-all 404 page (PMS-789) |
| `branding.company_name` | `tenants.branding` / `tenant_settings` `('branding', ...)`, validated by `src/modules/tenants/branding.rs` | one per tenant | "which MSP is this" - the customer-facing name one tenant puts on its own portal |
| SMTP `from` display name | the `from` field of the system email setting, `src/modules/settings/email.rs` (PMS-638) | one per deployment | which mailbox outbound mail is sent AS. A `lettre` Mailbox, so it carries an address and must stay parseable; it is not a free-text label |

The app name is cached in-process rather than queried per read because two of its consumers cannot make a query: the 404 fallback handler takes no `State` and must render when the database is down, and the invitation mail builds its subject inside an already-open tenant transaction. `settings::app_name::resolve_and_cache` is the only writer of that cache, called at boot and after each admin write.

## Retired seams

Recorded so a reader does not go hunting for a subsystem that was deleted, and so the next audit does not re-derive it.

- **SSO / OIDC IdP (`crates/mokosh-auth*`).** Removed by PMS-295. mokosh no longer runs an OP, holds no signing key and exposes no `/oauth2/*` endpoints; the `MOKOSH_AUTH_*` env vars are gone. The TOTP and recovery-code primitives the legacy path borrowed from `mokosh-auth-crypto` were relocated into `src/utils/totp.rs` and `src/utils/recovery.rs`.
- **SaaS subscription billing (`crates/mokosh-auth-http`).** Left in the same removal; the billing section above covers what remains.
- **The `mokosh_auth.*` schema.** Its `subscriptions`, `users` and `user_totp` tables were created by the removed subsystem's own migrations, never by `migrations/` in this repo, so no mokosh database has that schema today. The PMS-198 decisions naming `mokosh_auth.subscriptions` the canonical subscription store and `mokosh_auth.users` the canonical user store are void: `public.tenants` and `public.users` are the only stores there are.
- **Dual users tables.** Collapsed to `public.users` by the above. One divergence the old entry flagged is still real and is now tracked as PMS-871: `users.mfa_secret` (`migrations/003_auth.sql:25`) holds the TOTP shared secret in plaintext, written at `src/modules/auth/service.rs:1569`.
- **Google OAuth popup sign-in.** Removed by PMS-837 along with the `google-oauth-flow` crate; the `google_oauth_routes_stay_unmounted` test in `src/modules/auth/routes.rs` fails if either mount comes back. The `user_oauth_identities` table stays because migrations are immutable.
