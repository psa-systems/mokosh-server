//! Notifications module: channels, templates, user preferences,
//! in-app inbox, rules engine, dispatcher.

pub mod models;
pub mod routes;
pub mod service;

pub use models::*;
pub use routes::notifications_routes;
pub use service::NotificationsService;
