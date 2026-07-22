//! New-account demo-data seeding (PMS-157).
//!
//! See [`service::SeedService`] for the trigger model and guards.

#[cfg(feature = "server")]
mod data;
#[cfg(feature = "server")]
mod middleware;
#[cfg(feature = "server")]
pub mod qa;
#[cfg(feature = "server")]
mod service;
#[cfg(feature = "server")]
pub mod showcase;

#[cfg(feature = "server")]
pub use middleware::{seed_middleware, SeedMiddlewareState};
#[cfg(feature = "server")]
pub use qa::{confirm_qa_tenant, qa_seed, qa_teardown, QaReport};
#[cfg(feature = "server")]
pub use service::{LoadDemoOutcome, SeedService};
#[cfg(feature = "server")]
pub use showcase::{
    confirm_showcase_tenant, showcase_refresh, showcase_seed, showcase_teardown, ShowcaseReport,
};
