//! Unified members list (MAPPS-877 phase 1).
//!
//! One reader (`GET /api/v1/members`) that returns the merged list of native
//! `users` + cross-account grantees (`mokosh_bunyip_grants`) so the SPA can
//! render "who has access to this workspace" without a second feed to
//! reconcile. See `src/modules/members/service.rs` for the merge rules and
//! `src/modules/members/routes.rs` for the route surface.

pub mod routes;
pub mod service;

pub use routes::{members_routes, MembersRouterState};
pub use service::{MembersFilter, MembersService};
