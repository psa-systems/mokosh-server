//! Mokosh Server - library
//!
//! Axum-based REST API for Mokosh Server.

pub mod api;
pub mod db;
pub mod infisical;
pub mod modules;
pub mod scheduler;
pub mod utils;
pub mod version;
pub mod version_check;

pub use db::Database;
pub use modules::auth::{AuthState, CurrentUser};
pub use utils::error::{AppError, AppResult};
pub use version::VersionInfo;
