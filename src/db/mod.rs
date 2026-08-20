//! Database module for PostgreSQL connection and operations

#[cfg(feature = "server")]
mod pool;

#[cfg(feature = "server")]
pub use pool::{Database, TenantTransaction};

// PMS-489: self-provision the split DB roles at server startup. Called from
// `main` before `Database::new` and migrations.
#[cfg(feature = "server")]
pub mod provision;

// MAPPS-475 (MAPPS-474 phase 1): read helpers over `identities` and
// `tenant_memberships`. Not wired into any handler yet; phase 2 consumes them.
#[cfg(feature = "server")]
pub mod identity;

// MAPPS-513 (MAPPS-474 stage A follow-up): read + write helpers for
// `platform_admins`. Distinct credential store for the platform
// super-admin persona (see migrations 131 + 132).
#[cfg(feature = "server")]
pub mod platform_admin;
