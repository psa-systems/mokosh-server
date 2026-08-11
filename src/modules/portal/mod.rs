//! Customer portal module
//!
//! Implements the contact-side (customer-facing) surface of the PSA.
//! Portal identity is the `contacts` row, not the `users` row, so the
//! auth path is independent of the agent SSO/legacy paths. See
//! [`PortalAuthService`] for the contact-side credential check and
//! [`portal_auth_middleware`] / [`RequirePortalAuth`] for the session
//! plumbing.
//!
//! # Session model (PMS-729 phase 2 H11)
//!
//! Portal auth uses **Bearer tokens**, never cookies. The rationale:
//!
//! - **Portal is a WASM SPA.** `mokosh-clients/src/hooks/fetch.rs`
//!   holds the access + refresh tokens in a `thread_local!` `RefCell`
//!   (WASM is single-threaded so this is safe) and NEVER writes them
//!   to `localStorage` or a cookie. A tab reload wipes the tokens and
//!   returns the visitor to `/portal/login`; that is the design.
//! - **A cookie-scoped session would need `Secure` + `SameSite=Lax` /
//!   `HttpOnly` + a CSRF token layer.** Bearer sidesteps all of that:
//!   the SPA never issues a cross-site form POST, and any cross-origin
//!   fetch attaches the Bearer explicitly via `Authorization:`.
//! - **CORS is easier with Bearer.** The portal SPA on
//!   `{slug}.client.<apex>` and the API on `api.msp.<apex>` are
//!   different origins; a credentialed cookie would need
//!   `Access-Control-Allow-Credentials: true` + a matching cookie
//!   domain, and the browser rejects credentialed CORS against a
//!   wildcard `Origin`. Bearer needs neither.
//! - **Server-side revocation is via `portal_refresh_tokens`** (PMS-729
//!   phase 2 H1 + H2). A stolen access token expires on its own within
//!   15 minutes; a logout revokes the refresh chain so the customer's
//!   ability to renew is cut immediately. This is documented at the
//!   `POST /portal/auth/logout` handler.
//!
//! **Do NOT add cookie handling to the portal surface** without
//! reopening this decision. The design doc §14.2 mentioned a
//! `PORTAL_COOKIE_SECURE` env; that suggestion predates the SPA-side
//! implementation choice and does not apply.

pub mod captcha;
pub mod export_worker;
pub mod host_tenant;
pub mod middleware;
pub mod models;
pub mod rate_limit;
pub mod routes;
pub mod service;

pub use captcha::{TurnstileConfig, TurnstileError, TurnstileGate};
pub use host_tenant::PortalHostConfig;
pub use middleware::{
    portal_auth_middleware, PortalAuthMiddleware, RequirePortalAuth, RequirePortalSession,
};
pub use models::*;
pub use routes::portal_routes;
pub use service::PortalAuthService;
// PMS-693: exported for the parity test that pins the SQL lockout schedule
// against the Rust one.
pub use service::{lock_seconds_sql, lockout_until};
