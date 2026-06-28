//! Database module for PostgreSQL connection and operations

#[cfg(feature = "server")]
mod pool;

#[cfg(feature = "server")]
pub use pool::Database;

// PMS-489: self-provision the split DB roles at server startup. Called from
// `main` before `Database::new` and migrations.
#[cfg(feature = "server")]
pub mod provision;
