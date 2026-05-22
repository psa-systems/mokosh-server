//! RMM integration module: connections, device mappings, alert rules,
//! alert ingestion. Provider variants (Tactical RMM, MeshCentral)
//! share the same data model.

pub mod models;
pub mod routes;
pub mod service;

pub use models::*;
pub use routes::rmm_routes;
pub use service::RmmService;
