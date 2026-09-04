//! Contact-portal auth + capability plane.
//!
//! mokosh-contact-login prompt 002 skeleton. The `capabilities` module
//! carries the stable string constants every gated route + UI element
//! checks. The auth service, middleware, routes, and RBAC service land
//! in prompts 004 / 007.
//!
//! Distinct from the retired `crate::modules::portal` (prompt 001):
//! that surface treated each mokosh tenant as a client. This one keeps
//! mokosh tenants as internal Bunyip workspaces and lets a tenant's
//! own contacts sign in to a per-Company portal-slug URL with a
//! configurable capability set.

pub mod capabilities;
pub mod middleware;
pub mod models;
pub mod routes;
pub mod service;

pub use middleware::{ContactAuthMiddleware, ContactAuthState, RequireContactAuth};
pub use routes::contact_routes;
pub use service::ContactAuthService;
