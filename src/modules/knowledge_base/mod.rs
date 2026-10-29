//! Knowledge base module: categories, articles, versions, portal visibility.
pub mod anchor;
pub mod attachment_move;
pub mod attachments;

pub mod execution_routes;
pub mod execution_service;
pub mod execution_steps;
pub mod mentions;
pub mod models;
pub mod render;
pub mod routes;
pub mod service;

pub use attachment_move::KbAttachmentMover;
pub use execution_routes::kb_execution_routes;
pub use execution_service::KbExecutionService;
pub use models::*;
pub use routes::kb_routes;
pub use service::KbService;
