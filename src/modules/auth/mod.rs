//! Authentication and Authorization Module
//!
//! Handles user authentication, session management, and authorization.
//!
//! # Retired: Google OAuth (PMS-837)
//!
//! The `/google` and `/google/callback` mounts under `/api/v1/auth` (the
//! popup + `postMessage` sign-in flow, its `google_login` glue module, the
//! `google-oauth-flow` workspace crate, `AuthService::login_with_google`, and
//! the Google client id/secret/redirect-uri and super-admin-allowlist env
//! vars) were removed.
//! No client ever called them: three parity audits between 2026-07-30 and
//! 2026-08-14 found the routes unconsumed, and `mokosh-apps` still has no
//! reference to them. The absence is deliberate, not an oversight: an auth
//! entry point nothing exercises is one nobody reviews when this middleware
//! changes. `google_oauth_routes_stay_unmounted` in `routes.rs` fails if
//! either mount comes back.
//!
//! The `user_oauth_identities` table stays (migrations are immutable, and it
//! is the natural home for any future federated identity).

#[cfg(feature = "server")]
pub mod bootstrap;
// mokosh-contact-login prompt 008: `CallerContext` + `RequireCallerContext`.
// Dual-plane extractor for routes a staff user OR a portal contact may
// reach; contact branches gate on `require_capability` (DB-loaded).
#[cfg(feature = "server")]
pub mod caller_context;
// PMS-591: receiver for Bunyip's `account_deleted` webhook. Wired outside
// the JWT auth chain in `create_api_router`.
#[cfg(feature = "server")]
pub mod bunyip_webhook;
#[cfg(feature = "server")]
pub mod middleware;
// PMS-871: at-rest encryption of `users.mfa_secret`, plus the classification
// that lets a pre-PMS-871 plaintext row upgrade itself on next use.
#[cfg(feature = "server")]
mod mfa_secret;
mod models;
// Resource-Server OIDC verifier for the bunyip-as-OP cutover. Wired into
// AuthMiddleware via `with_bunyip` in `create_api_router`.
// See docs/new-auth/mokosh/03-mokosh-server-rs-cutover.md.
#[cfg(feature = "server")]
pub mod oidc_rs;
#[cfg(feature = "server")]
pub mod rate_limit;
#[cfg(feature = "server")]
mod routes;
mod service;
pub mod tenant;

#[cfg(feature = "server")]
pub use caller_context::{load_contact_capabilities, CallerContext, RequireCallerContext};
#[cfg(feature = "server")]
pub use middleware::{
    AdminRoles, AuthMiddleware, FinanceRoles, ManagerRoles, ModuleGate, RequireAdmin,
    RequireAdminUser, RequireAssets, RequireAuth, RequireAuthState, RequireBilling,
    RequireCalendar, RequireContracts, RequireFinance, RequireKnowledgeBase, RequireManager,
    RequireModuleEnabled, RequireProjects, RequireReports, RequireRmm, RequireRole,
    RequireSuperAdmin, RequireTimeTracking, RequireTimesheets, RoleRequirement, SuperAdminRoles,
    TenantScope,
};
pub use models::*;
#[cfg(feature = "server")]
pub use routes::auth_routes;
#[cfg(feature = "server")]
pub use service::AuthService;
// PMS-693: exported for the parity test that pins the SQL lockout schedule
// against the Rust one.
#[cfg(feature = "server")]
pub use service::{mfa_lock_seconds_sql, mfa_lockout_until};
// PMS-729 finalize (MAPPS-334 parity): re-exported so the portal-side
// JWT mint stamps the same `iss` / `aud` values as the agent side does.
pub use service::{MOKOSH_JWT_AUDIENCE, MOKOSH_JWT_ISSUER};
// PMS-743: tenant naming derives a personal tenant's display name from the
// same email-to-name logic the JIT user insert uses, rather than growing a
// second copy of the UUID / placeholder rejection rules.
#[cfg(feature = "server")]
pub(crate) use service::{synthetic_name_from_email, SYNTHETIC_NAME_FALLBACK};
pub use tenant::{TenantId, TenantScoped};
