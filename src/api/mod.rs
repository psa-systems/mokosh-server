//! API module - combines all API routes

#[cfg(feature = "server")]
mod router;

#[cfg(feature = "server")]
pub use router::create_api_router;
