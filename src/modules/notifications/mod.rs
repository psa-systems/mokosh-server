//! Notifications module: channels, templates, user preferences,
//! in-app inbox, rules engine, dispatcher, worker.

pub mod models;
pub mod routes;
pub mod service;
pub mod worker;

pub use models::*;
pub use routes::notifications_routes;
pub use service::{render_template, NotificationsService, RENDER_TRACE_TARGET};
pub use worker::DispatcherWorker;
