//! Database module for PostgreSQL connection and operations

#[cfg(feature = "server")]
mod pool;

#[cfg(feature = "server")]
pub use pool::Database;
