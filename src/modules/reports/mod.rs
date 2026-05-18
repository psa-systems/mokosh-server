//! Reports module: aggregate dashboards over tickets, time, billing,
//! plus CSV export.

pub mod routes;
pub mod service;

pub use routes::reports_routes;
pub use service::ReportsService;
