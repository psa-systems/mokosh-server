//! Tenant Management Module (Multi-tenant mode only)
//!
//! Handles tenant provisioning, configuration, and management.

mod models;
#[cfg(feature = "server")]
mod routes;
#[cfg(feature = "server")]
mod service;

pub use models::*;
#[cfg(feature = "server")]
pub use routes::tenant_routes;
#[cfg(feature = "server")]
pub use service::TenantService;
