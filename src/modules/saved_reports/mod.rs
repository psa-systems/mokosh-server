//! PMS-457: saved custom-report definitions + execution runtime
//! + scheduled delivery.
//!
//! Phase 1 ships the tenant-scoped CRUD over `saved_reports`.
//! Phase 2 (PMS-477) ships the execution runtime via
//! `POST /reports/saved/{id}/execute`. Phase 3 (PMS-478) ships
//! scheduled delivery: a user can mark a saved report "deliver this
//! weekly to my email", a background worker materialises it on the
//! cron tick and hands an `email` row to the existing notifications
//! DispatcherWorker for SMTP send + retry.

mod compiler;
mod models;
mod routes;
mod service;
pub mod worker;

pub use routes::{saved_reports_routes, SavedReportsRouterState};
pub use service::SavedReportsService;
pub use worker::ScheduledReportsWorker;
