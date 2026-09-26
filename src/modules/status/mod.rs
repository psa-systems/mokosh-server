//! Client service status: monitored systems and their observed check outcomes.
//!
//! The record-keeping half of CRM already covers who the client is (companies),
//! who to talk to (contacts) and what they own (assets). This module holds
//! WHAT STATE their services are in: the systems an external monitor tracks
//! and the observations it makes against them.
//!
//! Two tables (see the migration): `monitored_systems` is a durable record
//! per system, `status_observations` is an append-only log. The current
//! status resolves to "the latest observation for this system and check
//! kind" and the trend queries live on the same log.
//!
//! Ingest is HMAC-authenticated and reuses the same connection secret
//! Tactical RMM alerts already carry, so no new inbound credential is
//! introduced. The handler that verifies the signature lives in
//! `crate::modules::rmm::routes` where the auth logic already sits; this
//! module owns the DTOs, the store and the read endpoints.

#[cfg(feature = "server")]
pub mod models;
#[cfg(feature = "server")]
pub mod retention;
#[cfg(feature = "server")]
pub mod routes;
#[cfg(feature = "server")]
pub mod service;

#[cfg(feature = "server")]
pub use models::*;
#[cfg(feature = "server")]
pub use retention::{StatusRetentionWorker, DEFAULT_RETENTION_DAYS};
#[cfg(feature = "server")]
pub use routes::status_routes;
#[cfg(feature = "server")]
pub use service::StatusService;
