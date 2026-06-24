//! Ticketing Module
//!
//! Core service desk functionality for issue tracking and resolution.

#[cfg(feature = "server")]
mod automation;
mod models;
#[cfg(feature = "server")]
mod routes;
#[cfg(feature = "server")]
mod service;

#[cfg(feature = "server")]
pub use automation::AutomationEngine;
pub use models::*;
#[cfg(feature = "server")]
pub use routes::{contact_notes_routes, ticket_routes};
#[cfg(feature = "server")]
pub use service::TicketService;
