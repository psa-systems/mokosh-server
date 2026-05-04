//! Database module for PostgreSQL connection and operations

#[cfg(feature = "server")]
mod pool;
#[cfg(feature = "server")]
mod tenant;

#[cfg(feature = "server")]
pub use pool::Database;
#[cfg(feature = "server")]
pub use tenant::TenantContext;
