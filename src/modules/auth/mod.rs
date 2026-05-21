//! Authentication and Authorization Module
//!
//! Handles user authentication, session management, and authorization.

#[cfg(feature = "server")]
pub mod at_jwt;
#[cfg(feature = "server")]
pub mod bootstrap;
#[cfg(feature = "server")]
pub mod google_login;
#[cfg(feature = "server")]
pub mod middleware;
mod models;
#[cfg(feature = "server")]
pub mod rate_limit;
#[cfg(feature = "server")]
mod routes;
mod service;

#[cfg(feature = "server")]
pub use middleware::{
    AdminRoles, AuthMiddleware, FinanceRoles, ManagerRoles, RequireAdmin, RequireAuth,
    RequireFinance, RequireManager, RequireRole, RoleRequirement, TenantScope,
};
pub use models::*;
#[cfg(feature = "server")]
pub use routes::auth_routes;
#[cfg(feature = "server")]
pub use service::AuthService;
