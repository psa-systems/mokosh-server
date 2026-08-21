//! MAPPS-513 (MAPPS-474 stage A follow-up): platform super-admin
//! module. Distinct credential store (see `crate::db::platform_admin`)
//! + login + password-change endpoints under `/api/v1/platform`.

pub mod models;
#[cfg(feature = "server")]
pub mod routes;
#[cfg(feature = "server")]
pub mod service;

#[cfg(feature = "server")]
pub use routes::{platform_routes, RequirePlatformAdmin};
#[cfg(feature = "server")]
pub use service::PlatformAdminService;
