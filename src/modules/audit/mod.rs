//! Audit log module: middleware-driven request log + admin read.

pub mod middleware;
pub mod models;
pub mod routes;
pub mod service;

pub use middleware::audit_log_middleware;
pub use models::*;
pub use routes::audit_routes;
pub use service::AuditService;
