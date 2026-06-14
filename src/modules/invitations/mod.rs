//! Invitations module (PMS-244): Mokosh-owned org membership.
//!
//! A tenant admin invites a person by email into their tenant; acceptance is
//! login-driven (the bunyip auth path resolves a pending invite into a tenant
//! placement on the invitee's next login - see `auth::middleware`). Orgs live
//! in Mokosh, not Bunyip.

pub mod models;
pub mod routes;
pub mod service;

pub use models::*;
pub use routes::invitations_routes;
pub use service::InvitationsService;
