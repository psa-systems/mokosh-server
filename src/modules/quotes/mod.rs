//! Quotes module: the sales document that precedes a Project.
//!
//! PMS-672 (phase 2 of the PMS-670 Quotes epic) wires the HTTP + service
//! layer on top of the schema PMS-671 landed in
//! `092_quotes_entity.sql`. Before this module the only code touching
//! `quotes` was `modules::approvals`, which existence-checks the parent
//! row so `/quotes/{id}/approvals` can hang off it; the entity had no
//! CRUD of its own.
//!
//! Two rules drive most of the design and are enforced in `service`:
//!
//! 1. **Totals are computed server-side** from `quote_lines`. A
//!    client-supplied total is never read, so a caller cannot quote one
//!    price to the customer and store another.
//! 2. **A quote freezes once issued.** After it reaches `sent` the
//!    customer has seen the figures, so header and line edits are
//!    rejected with 409 rather than silently changing what was signed
//!    off. See [`models::QuoteStatus::is_frozen`].

pub mod models;
pub mod routes;
pub mod service;

pub use models::*;
pub use routes::quotes_routes;
pub use service::QuotesService;
