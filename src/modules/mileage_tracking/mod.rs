//! Mileage tracking module (PMS-315): mileage entries logged from the Log
//! Time form's "Mileage" mode. Schema lives in `051_mileage_entries.sql`.
//!
//! Shared module: the client (mokosh-apps) carries the model types via
//! `mokosh-types`. Routes + service are gated behind the `server` feature so
//! the WASM build omits the axum/sqlx code. Endpoints reuse the time-tracking
//! module gate (`RequireTimeTracking`); mileage is part of time tracking.

mod models;
#[cfg(feature = "server")]
mod routes;
#[cfg(feature = "server")]
mod service;

pub use models::*;
#[cfg(feature = "server")]
pub use routes::mileage_tracking_routes;
#[cfg(feature = "server")]
pub use service::MileageTrackingService;
