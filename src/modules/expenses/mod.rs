//! MAPPS-1100 scaffold: the Bills and Expenses subsystem.
//!
//! An MSP tracks what IT is billed for (vendor bills) and what its own
//! people spend (employee expenses), with the same tenant-isolation
//! posture and audit shape as the rest of the server. The customer-
//! facing invoicing plane (`billing/`) exists end-to-end today; this
//! module is the inbound plane the `Capability::BillsAndExpenses`
//! registry entry promises but could not deliver until MAPPS-1100.
//!
//! # What ships in Phase 0
//!
//! - Migration 279 creating `vendors`, `expense_categories`, `bills`,
//!   `bill_lines`, `expenses`, `expense_lines` with tenant isolation and
//!   `mokosh_app` grants.
//! - [`models`]: the Rust types that mirror the schema, derivable to and
//!   from a sqlx row.
//!
//! # What ships in Phase A
//!
//! - [`service::ExpensesService`]: the one writer. Vendors and expense
//!   categories CRUD, admin+finance gated, tenant-isolated through
//!   `begin_with_tenant`, every mutation writing an `audit_log` row in
//!   the same transaction as the change.
//! - [`routes::expenses_routes`]: `/api/v1/vendors` and
//!   `/api/v1/expense-categories` CRUD, merged into the staff plane.
//!
//! Only the leaf lookups land in Phase A because they are prerequisites
//! for the bill/expense headers themselves. Mounting empty
//! `/api/v1/bills` and `/api/v1/expenses` endpoints that return
//! `NotImplemented` is the "advertises what the build cannot deliver"
//! anti-pattern MAPPS-1098 and MAPPS-1102 enforce against.
//!
//! # What ships in Phase B
//!
//! - [`service::ExpensesService`] gains the bill and expense headers,
//!   each atomic with its lines in one transaction: bills
//!   (`draft -> approved -> paid`, `void`) and expenses
//!   (`draft -> submitted -> approved -> reimbursed`, `rejected`).
//! - [`routes::expenses_routes`] mounts `/api/v1/bills`,
//!   `/api/v1/bills/{id}`, `/api/v1/bills/{id}/approve`,
//!   `/api/v1/bills/{id}/void`, `/api/v1/expenses`,
//!   `/api/v1/expenses/{id}`, `/api/v1/expenses/{id}/submit`,
//!   `/api/v1/expenses/{id}/approve`, `/api/v1/expenses/{id}/reject`,
//!   and `/api/v1/expenses/{id}/reimburse`.
//!
//! # What does NOT ship
//!
//! - **worker**: due-date reminders and reimbursement batching are a
//!   later phase.
//! - **delegation to Xero / QuickBooks**: builds on the OAuth + webhook
//!   infrastructure MAPPS-1099 shipped; not yet started.
//!
//! # Why six tables and not fewer
//!
//! `bills` and `expenses` are different ledgers in two directions: a
//! bill is an obligation to a vendor (needs vendor + bill number + due
//! date), an expense is a claim from an employee (needs user + approval
//! flow + reimbursement). Folding them into one `payable` table would
//! leave half the columns NULL per row and force the service to carry a
//! discriminator for every read. The two "lines" tables mirror the two
//! headers; `vendors` and `expense_categories` are shared lookup rows.

pub mod models;
pub mod routes;
pub mod service;

pub use routes::expenses_routes;
pub use service::ExpensesService;
