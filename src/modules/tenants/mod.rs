//! Tenant Management Module (Multi-tenant mode only)
//!
//! Handles tenant provisioning, configuration, and management.

mod models;

// PMS-21 AC3: `routes` and `service` only need to exist when this
// build actually exposes tenant management. The router gates the
// `/tenants` mount on `multi-tenant` already; tightening the module
// gate to match drops the unused-code compilation in single-tenant
// builds (previously the modules compiled as dead code under the
// looser `feature = "server"` gate).
#[cfg(all(feature = "server", feature = "multi-tenant"))]
mod routes;
#[cfg(all(feature = "server", feature = "multi-tenant"))]
mod service;

pub use models::*;
#[cfg(all(feature = "server", feature = "multi-tenant"))]
pub use routes::tenant_routes;
#[cfg(all(feature = "server", feature = "multi-tenant"))]
pub use service::TenantService;
