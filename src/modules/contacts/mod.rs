//! Contact Management Module
//!
//! Handles companies (clients), contacts, and sites.

mod models;
#[cfg(feature = "server")]
mod routes;
#[cfg(feature = "server")]
mod service;

pub use models::*;
#[cfg(feature = "server")]
pub use routes::contact_routes;
#[cfg(feature = "server")]
pub use service::ContactService;
