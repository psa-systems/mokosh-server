//! MAPPS-877: unified members surface.
//!
//! `GET /api/v1/members` returns natives + placed guests + unplaced
//! guests as one paginated, filterable list. Fans out to the existing
//! `users` reader (for native + placed rows) and, in SaaS mode, to
//! `BunyipUserDirectory::list_owner_grants` for the owner outbox; a
//! placed row is the intersection of the two.
//!
//! Manager-gated read (matches the /users reader). Writes stay where
//! they lived (`PUT /users/{id}`, `PATCH /grants/{id}`, `DELETE
//! /grants/{id}`); the SPA picks the endpoint by row kind, this
//! module does not duplicate a write path.

#[cfg(feature = "server")]
mod routes;
#[cfg(feature = "server")]
mod service;

#[cfg(feature = "server")]
pub use routes::members_routes;
#[cfg(feature = "server")]
pub use service::{MembersFilter, MembersService};
