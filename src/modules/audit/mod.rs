//! Audit log module: middleware-driven request log + admin read, plus the
//! in-transaction `audit_write` path (PMS-117) for entity mutations.
//!
//! # Immutability and retention (PMS-117 AC4)
//!
//! The audit trail is **append-only via the API**: the read route
//! ([`routes::audit_routes`]) exposes only `GET /api/v1/audit-log`; there is no
//! update or delete endpoint, and `audit_write` only ever INSERTs. Tampering
//! therefore requires direct database access, which is outside the application
//! trust boundary.
//!
//! **Retention policy.** Rows are retained for **24 months** to satisfy MSP
//! compliance and incident-investigation needs, then pruned by an out-of-band
//! scheduled job (operations-owned; e.g. a nightly
//! `DELETE FROM audit_log WHERE timestamp < now() - interval '24 months'`).
//! Pruning is deliberately NOT exposed through the API so the application can
//! never delete audit history. If stronger tamper-evidence is required later, a
//! per-row hash chain can be layered on without changing this interface.

pub mod context;
pub mod middleware;
pub mod models;
pub mod routes;
pub mod service;

pub use context::{audit_auth_event, audit_write, AuditAction, AuditCtx};
pub use middleware::audit_log_middleware;
pub use models::*;
pub use routes::audit_routes;
pub use service::AuditService;
