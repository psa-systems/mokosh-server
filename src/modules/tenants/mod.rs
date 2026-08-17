//! Tenant Management Module (Multi-tenant mode only)
//!
//! Handles tenant provisioning, configuration, and management.

// PMS-761: the organisation identity every client-facing email renders.
// Deliberately outside the `multi-tenant` gate below: its callers (quotes,
// billing, tickets, forms) are unconditional, and a single-tenant build still
// has an organisation with a name.
pub mod identity;
// PMS-776: the shape table for a branding value a client is shown. Ungated for
// the same reason, and one gate looser than the rest of the tenant surface
// because the settings validator that shares it is ungated.
pub mod branding;
mod models;

// PMS-21 AC3: `routes` and `service` only need to exist when this
// build actually exposes tenant management. The router gates the
// `/tenants` mount on `multi-tenant` already; tightening the module
// gate to match drops the unused-code compilation in single-tenant
// builds (previously the modules compiled as dead code under the
// looser `feature = "server"` gate).
// MAPPS-429: tenant logo storage. Ungated since PMS-776: `branding` validates
// `logo_mime` and `logo_url` against the same set the upload and the public
// route use, and `branding` is reachable from the ungated settings validator.
pub mod logo;
#[cfg(all(feature = "server", feature = "multi-tenant"))]
mod routes;
#[cfg(all(feature = "server", feature = "multi-tenant"))]
mod service;

pub use identity::OrgIdentity;
pub use models::*;
#[cfg(all(feature = "server", feature = "multi-tenant"))]
pub use routes::{public_tenant_routes, tenant_routes};
#[cfg(all(feature = "server", feature = "multi-tenant"))]
pub use service::TenantService;
