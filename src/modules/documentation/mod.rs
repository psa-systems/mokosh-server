//! PMS-800 / PSA-13: one surface that answers "what do we have for this
//! client". Composition over `AssetsService`, `KbService` and the asset
//! credential vault; no new store, no secrets on the wire, no second
//! source of truth for any of the three.
//!
//! The read is a single `GET /api/v1/companies/{company_id}/documentation`
//! that returns:
//!   - assets with their typed custom fields,
//!   - credential REFERENCES for the company's assets AND the
//!     company-scoped vault (no secret_data, no password, no notes; the
//!     reveal path stays the audited single-credential endpoint at
//!     `src/modules/assets/routes.rs:70-75`),
//!   - KB articles scoped to the company (`company_id = ANY(company_ids)`
//!     in the server-side filter the KB service already owns).
//!
//! Scope: this ships the aggregate endpoint. The client-scoped search +
//! "client-specific records outrank generic" ranking (also in PMS-800)
//! lands in a follow-up PR on this ticket so the aggregate's shape can
//! stabilise before search picks over it.
//!
//! Tenant guard: every service call takes a `TenantId` whose constructor
//! is reachable only through `CurrentUser::tenant()`, so a cross-company
//! read from another tenant cannot compile; a request for a company that
//! belongs to another tenant answers 404 via the shared company-scoping
//! queries each child service enforces.

pub mod routes;
pub mod service;

pub use routes::documentation_routes;
