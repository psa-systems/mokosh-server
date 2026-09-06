//! Teams module (PMS-791 / MAPPS-461).
//!
//! Team CRUD + membership on top of the pre-existing `teams` and
//! `team_members` tables (migration 003_auth.sql, unused until this
//! ticket). See docs/mokosh-orgs/00-blueprint.md for the full design.

pub mod models;

#[cfg(all(feature = "server", feature = "multi-tenant"))]
mod routes;
#[cfg(all(feature = "server", feature = "multi-tenant"))]
mod service;

pub use models::*;
#[cfg(all(feature = "server", feature = "multi-tenant"))]
pub use routes::{me_teams_routes, teams_routes};
#[cfg(all(feature = "server", feature = "multi-tenant"))]
pub use service::{TeamListFilters, TeamsService};
