//! Knowledge base module: categories, articles, versions, portal visibility.
pub mod attachments;

pub mod models;
pub mod routes;
pub mod service;

pub use models::*;
pub use routes::kb_routes;
pub use service::KbService;
