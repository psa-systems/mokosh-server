//! PMS-448: workflow rules.
//!
//! Operator-defined rules that fire in-transaction on ticket
//! lifecycle events. Phase 1 ships `ticket.created` (with mutating
//! actions: assign, reprioritise, tag, add internal note). Phase 2
//! adds `ticket.status_changed` and `ticket.priority_changed`
//! triggers, log-only at first. PMS-467 / phase 3 promotes the
//! transition triggers to mutating: `set_status_id` / `set_priority_id`
//! actions cascade into the matching transition trigger at the next
//! depth level, bounded by the per-tenant `workflows/rule_max_depth`
//! cap (default 3).

mod executor;
mod models;
mod routes;
mod service;

pub use executor::{
    TicketCreateContext, TicketPriorityChangedContext, TicketStatusChangedContext, WorkflowExecutor,
};
pub use routes::{workflow_routes, WorkflowsRouterState};
pub use service::WorkflowsService;
