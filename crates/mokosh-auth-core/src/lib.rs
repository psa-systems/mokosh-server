//! Mokosh auth core: pure domain types, repository traits, errors, policy.
//!
//! This crate has no I/O. It defines the shapes that the rest of the auth
//! stack composes against. Every persistent operation goes through a trait
//! defined here so that the OIDC engine can be tested with in-memory fakes.

pub mod error;
pub mod ids;
pub mod model;
pub mod policy;
pub mod repository;
pub mod time;

pub use error::AuthError;
pub use ids::*;
pub use model::*;
pub use repository::*;
pub use time::Clock;
