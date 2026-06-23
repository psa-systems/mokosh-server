//! PMS-457 phase 1: saved custom-report definitions.
//!
//! Tenant-scoped CRUD over `saved_reports`. The report DEFINITION
//! (entity, filters, columns, group/sort) is persisted; the
//! execution runtime that compiles a row into a SELECT and streams
//! results ships separately as Phase 2.

mod models;
mod routes;
mod service;

pub use routes::{saved_reports_routes, SavedReportsRouterState};
pub use service::SavedReportsService;
