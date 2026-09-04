//! PMS-451 phase 1: ticket approval requests.
//!
//! A reusable approval-request primitive scoped to tickets in phase 1.
//! An agent on a ticket can `request_approval` (assign-by-user or
//! assign-by-role); the chosen approver decides. The SPA renders the
//! per-ticket approval timeline plus a top-bar "pending approvals" badge
//! when the signed-in user has decisions queued for them.
//!
//! Phase 2 will generalise to polymorphic approvals across change
//! requests / quotes / time entries; tickets fold in as a special case
//! once the second consumer is real.

mod models;
mod routes;
mod service;

pub use models::ApprovalResponse;
pub use routes::{approval_routes, ApprovalsRouterState};
pub use service::ApprovalsService;
