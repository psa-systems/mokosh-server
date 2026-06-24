//! PMS-457: saved custom-report definitions + execution runtime.
//!
//! Phase 1 ships the tenant-scoped CRUD over `saved_reports` (the
//! report DEFINITION: entity, filters, columns, group/sort). Phase 2
//! (PMS-477) ships the execution runtime: `POST /reports/saved/{id}/execute`
//! compiles the row's JSONB into a parameterised SELECT against the
//! chosen entity table and streams the materialised rows. Tickets is
//! the only supported entity in this cut; time_entries / invoices /
//! assets follow in phase 2c.

mod compiler;
mod models;
mod routes;
mod service;

pub use routes::{saved_reports_routes, SavedReportsRouterState};
pub use service::SavedReportsService;
