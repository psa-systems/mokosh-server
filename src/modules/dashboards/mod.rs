//! PMS-453: saved dashboards + scheduled delivery.
//!
//! Phase 1 shipped per-user dashboard definitions (`saved_dashboards`).
//! Phase 2b (PMS-471) adds the scheduled-delivery surface: a user can
//! mark a saved dashboard "deliver this weekly to my email" and a
//! background worker materialises a snapshot at the cron tick,
//! handing an `email` row to the existing notifications
//! DispatcherWorker for SMTP send + retry. The SPA widget render
//! (phase 2a) is in flight separately; the worker's "materialise"
//! step today is a text summary that gets richer once 2a lands.

mod models;
mod routes;
mod service;
pub mod worker;

pub use routes::{dashboard_routes, DashboardsRouterState};
pub use service::DashboardsService;
pub use worker::ScheduledDashboardsWorker;
