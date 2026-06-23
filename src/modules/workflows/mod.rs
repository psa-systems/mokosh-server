//! PMS-448 phase 1: ticket.created workflow rules.
//!
//! A focused executor that runs operator-defined rules against
//! freshly-created tickets in-transaction. Rules carry structured
//! `conditions` (priority / queue / company / source / type) and
//! structured `actions` (assign, reprioritise, tag, add internal
//! note). Phase 2 will generalise to additional triggers; the
//! data model is already shaped to support it.

mod executor;
mod models;
mod routes;
mod service;

pub use executor::{TicketCreateContext, WorkflowExecutor};
pub use routes::{workflow_routes, WorkflowsRouterState};
pub use service::WorkflowsService;
