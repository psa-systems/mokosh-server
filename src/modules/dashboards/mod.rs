//! PMS-453 (Phase 1): saved dashboards.
//!
//! Per-user dashboard definitions: a name + a JSONB `layout` blob the
//! SPA reads to know which widgets to mount and in what positions.
//! Phase 2 (scheduled report delivery) is parked as a follow-up under
//! the same ticket; it needs a separate `scheduled_reports` table plus
//! a worker, and the work doesn't need to land in the same PR.

mod models;
mod routes;
mod service;

pub use routes::{dashboard_routes, DashboardsRouterState};
pub use service::DashboardsService;
