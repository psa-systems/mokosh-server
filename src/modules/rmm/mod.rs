//! RMM integration module: connections, device mappings, alert rules,
//! alert ingestion, provider abstraction, sync worker. Provider
//! variants (Tactical RMM, MeshCentral, Datto, ConnectWise, NinjaRMM)
//! share the same data model and plug in behind the `RmmProvider`
//! trait in `provider`.

pub mod models;
pub mod provider;
pub mod routes;
pub mod service;
pub mod worker;

pub use models::*;
pub use provider::{build_provider, ProviderAlert, ProviderConfig, ProviderDevice, RmmProvider};
pub use routes::rmm_routes;
pub use service::RmmService;
pub use worker::RmmSyncWorker;
