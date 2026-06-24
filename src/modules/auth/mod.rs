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
pub use middleware::{
    AdminRoles, AuthMiddleware, FinanceRoles, ManagerRoles, ModuleGate, RequireAdmin,
    RequireAdminUser, RequireAssets, RequireAuth, RequireBilling, RequireCalendar,
    RequireContracts, RequireFinance, RequireKnowledgeBase, RequireManager, RequireModuleEnabled,
    RequireProjects, RequireReports, RequireRmm, RequireRole, RequireSuperAdmin,
    RequireTimeTracking, RoleRequirement, SuperAdminRoles, TenantScope,
};
pub use models::*;
#[cfg(feature = "server")]
pub use routes::auth_routes;
#[cfg(feature = "server")]
pub use service::AuthService;
pub use tenant::{TenantId, TenantScoped};
