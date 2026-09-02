//! Time tracking module: time entries, timesheets, active timers,
//! rounding rules, work types. Schema lives in
//! `migrations/006_time_tracking.sql` (timesheets are aggregated from
//! `time_entries`, not a table). Endpoints land incrementally across PMS-42.
//!
//! Shared module: the client (mokosh-apps) carries a byte-identical copy and
//! compiles only the model types. Routes + service are gated behind the
//! `server` feature so the WASM build omits the axum/sqlx code.

mod models;
#[cfg(feature = "server")]
mod routes;
#[cfg(feature = "server")]
mod service;

pub use models::*;
#[cfg(feature = "server")]
pub use routes::time_tracking_routes;
#[cfg(feature = "server")]
pub use service::TimeTrackingService;
