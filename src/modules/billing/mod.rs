//! Billing module: invoices, payments, payment gateway configs, tax rates.
//!
//! Schema for all four tables already exists in `001_initial_schema.sql`;
//! this module wires the HTTP + service layer on top. Endpoints land
//! incrementally across the PMS-33 story.

pub mod models;
pub mod routes;
pub mod service;

pub use models::*;
pub use routes::billing_routes;
pub use service::BillingService;
