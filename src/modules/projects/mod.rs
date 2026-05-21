//! Projects module: projects, phases, tasks, task statuses, dependencies.

pub mod models;
pub mod routes;
pub mod service;

pub use models::*;
pub use routes::projects_routes;
pub use service::ProjectsService;
