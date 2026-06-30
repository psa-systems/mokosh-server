//! Contact Management Module
//!
//! Handles companies (clients), contacts, and sites.

#[cfg(feature = "server")]
mod industry_backfill;
mod models;
#[cfg(feature = "server")]
mod routes;
#[cfg(feature = "server")]
mod service;

#[cfg(feature = "server")]
pub use industry_backfill::{normalize_company_industries, IndustryBackfillReport};
pub use models::*;
#[cfg(feature = "server")]
pub use routes::contact_routes;
#[cfg(feature = "server")]
pub use service::ContactService;
