//! PMS-448: workflow rules.
//!
//! Operator-defined rules that fire in-transaction on ticket
//! lifecycle events. Phase 1 ships `ticket.created` (with mutating
//! actions: assign, reprioritise, tag, add internal note). Phase 2
//! adds `ticket.status_changed` and `ticket.priority_changed`
//! triggers; both LOG matching rules to `workflow_rule_runs` so the
//! operator audit trail captures the firings. Mutating actions on
//! transitions are scoped for Phase 3 once the SPA rule builder
//! matures.

mod executor;
mod models;
mod routes;
mod service;

pub use executor::{
    TicketCreateContext, TicketPriorityChangedContext, TicketStatusChangedContext, WorkflowExecutor,
};
pub use routes::{workflow_routes, WorkflowsRouterState};
pub use service::WorkflowsService;
