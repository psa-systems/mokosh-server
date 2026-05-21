//! Settings module: tenant settings + per-module config.

pub mod models;
pub mod routes;
pub mod service;

pub use models::*;
pub use routes::settings_routes;
pub use service::SettingsService;
