//! Time tracking module: time entries, timesheets, active timers,
//! rounding rules, work types. Schema for all five lives in
//! `001_initial_schema.sql`. Endpoints land incrementally across PMS-42.

pub mod models;
pub mod routes;
pub mod service;

pub use models::*;
pub use routes::time_tracking_routes;
pub use service::TimeTrackingService;
