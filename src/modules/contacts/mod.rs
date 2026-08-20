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
// PMS-805: resolve a company website on demand (`GET /companies/website-probe`).
#[cfg(feature = "server")]
mod website_probe;

#[cfg(feature = "server")]
pub use industry_backfill::{normalize_company_industries, IndustryBackfillReport};
pub use models::*;
#[cfg(feature = "server")]
pub use routes::contact_routes;
#[cfg(feature = "server")]
pub use service::ContactService;
#[cfg(feature = "server")]
pub use website_probe::{
    UnreachableReason, WebsiteProbe, WebsiteProbeLimiter, WebsiteProbeService, WwwChange,
};
