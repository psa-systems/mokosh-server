//! Knowledge base module: categories, articles, versions, portal visibility.
pub mod anchor;
pub mod attachment_move;
pub mod attachments;

pub mod mentions;
pub mod models;
pub mod routes;
pub mod service;

pub use attachment_move::KbAttachmentMover;
pub use models::*;
pub use routes::kb_routes;
pub use service::KbService;
