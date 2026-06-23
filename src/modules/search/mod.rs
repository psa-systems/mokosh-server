//! MAPPS-298: cross-entity tenant-scoped search.
//!
//! A single `GET /search?q=<text>` endpoint that fans out across the
//! principal entity tables (tickets, contacts, companies, assets,
//! projects), running an ILIKE per table inside the caller's tenant
//! scope, and returns a grouped envelope of the top N matches per
//! kind. The mokosh-apps SPA mounts a top-bar `<GlobalSearch>` against
//! this endpoint so a user can jump to any entity by keyword.

mod routes;
mod service;

pub use routes::{search_routes, SearchRouterState};
pub use service::SearchService;
