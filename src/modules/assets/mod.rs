//! Assets / CMDB module: asset types, assets, relationships, configuration
//! items, credential vault, audit log.

pub mod models;
pub mod routes;
pub mod service;

pub use models::*;
pub use routes::assets_routes;
pub use service::AssetsService;
