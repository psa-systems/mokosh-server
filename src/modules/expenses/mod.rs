//! The Bills and Expenses subsystem.
//!
//! An MSP tracks what IT is billed for (vendor bills) and what its own
//! people spend (employee expenses), with the same tenant-isolation
//! posture and audit shape as the rest of the server. This is the inbound
//! plane that the `Capability::BillsAndExpenses` registry entry promises;
//! the customer-facing invoicing plane lives in `billing/`.
//!
//! # What this module holds
//!
//! - The [`models`] module holds the Rust types that mirror the schema and the endpoint
//!   shapes.
//! - [`service::ExpensesService`] is the one writer. Vendors and expense
//!   categories CRUD, bills (`draft -> approved -> paid`, `void`) and
//!   expenses (`draft -> submitted -> approved -> reimbursed`,
//!   `rejected`), each header atomic with its lines in one transaction,
//!   tenant-isolated through `begin_with_tenant`, every mutation writing
//!   an `audit_log` row in the same transaction as the change.
//! - The router [`routes::expenses_routes`] mounts `/api/v1/vendors`,
//!   `/api/v1/expense-categories`, `/api/v1/bills` and `/api/v1/expenses`
//!   with their transition sub-routes, merged into the staff plane.
//!
//! # Delegated issuing
//!
//! - Bills: [`service::ExpensesService::create_bill`] raises the bill in
//!   Xero or QuickBooks when the tenant has delegated `BillsAndExpenses`
//!   and the deployment has `Feature::DelegatedBills` on, and records
//!   `external_provider` / `external_bill_id` on the local row. The push
//!   runs before the write transaction, so a provider that refuses leaves
//!   nothing behind.
//! - Expenses: [`service::ExpensesService::reimburse_expense`] records a
//!   reimbursed claim in the provider under the same gate. An expense is
//!   a claim from a person, not an obligation to a vendor, so it is a
//!   different document in both providers: a Xero `SPEND` bank
//!   transaction, or a QuickBooks purchase, never a bill.
//!
//! # What does NOT ship
//!
//! - **worker**: due-date reminders and reimbursement batching.
//! - **vendor payments read back**: the receivers report what a customer
//!   paid; none reads a vendor payment, so a bill paid in the provider
//!   stays open here until somebody records it.
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
