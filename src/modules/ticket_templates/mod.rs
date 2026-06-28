//! PMS-448 AC4: ticket templates.
//!
//! Named, tenant-scoped pre-fills for the new-ticket form. An admin
//! authors a template ("Server is down") that seeds a ticket's
//! subject / description / category (plus optional priority + type
//! defaults); the SPA lists active templates on the create screen and
//! copies the chosen one onto the form. The server stores and serves
//! the definitions only - creating a ticket from a template is a plain
//! ticket create with the operator-edited values, so the existing
//! create path (audit + SLA + `ticket.created` workflow rules) runs
//! unchanged.

mod models;
#[cfg(feature = "server")]
mod routes;
#[cfg(feature = "server")]
mod service;

pub use models::*;
#[cfg(feature = "server")]
pub use routes::ticket_template_routes;
#[cfg(feature = "server")]
pub use service::TicketTemplatesService;
