//! Customer portal module
//!
//! Implements the contact-side (customer-facing) surface of the PSA.
//! Portal identity is the `contacts` row, not the `users` row, so the
//! auth path is independent of the agent SSO/legacy paths. See
//! [`PortalAuthService`] for the contact-side credential check and
//! [`portal_auth_middleware`] / [`RequirePortalAuth`] for the session
//! plumbing.

pub mod middleware;
pub mod models;
pub mod rate_limit;
pub mod routes;
pub mod service;

pub use middleware::{portal_auth_middleware, PortalAuthMiddleware, RequirePortalAuth};
pub use models::*;
pub use routes::portal_routes;
pub use service::PortalAuthService;
