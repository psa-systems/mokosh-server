//! Opportunities and leads: the pipeline half of CRM basics.
//!
//! Companies, contacts, sites and quotes already ship, but the interest
//! that PRECEDES a quote had no home. This module records a lead against
//! a company, moves it through a small set of stages and closes it won
//! or lost, linking to the quote raised from it so the quote flow
//! becomes the closing step rather than a parallel record.
//!
//! Two rules the CHECK constraint on the table pins:
//! - a stage is one of the six named values, no free-text pipeline
//!   customisation for the first pass;
//! - `outcome` and a closed stage move together: an opportunity is either
//!   open (stage in `lead|qualified|proposal|negotiation`, outcome NULL)
//!   or closed (stage in `won|lost`, outcome set). The service moves
//!   both in one write.

#[cfg(feature = "server")]
pub mod models;
#[cfg(feature = "server")]
pub mod routes;
#[cfg(feature = "server")]
pub mod service;

#[cfg(feature = "server")]
pub use models::*;
#[cfg(feature = "server")]
pub use routes::opportunities_routes;
#[cfg(feature = "server")]
pub use service::OpportunitiesService;
