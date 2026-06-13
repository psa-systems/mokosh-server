//! Audit log module: in-transaction `audit_write` path (PMS-117) for entity
//! mutations, plus the admin read endpoint.
//!
//! The coarse per-request middleware (PMS-119) was removed in PMS-275: it ran
//! post-response with only the HTTP method + URL, so it could never record the
//! `entity_id` or old/new value payload, and the nested router stripped the
//! `/api/v1` prefix before it ran, tagging every row entity_type "unknown".
//! `audit_write` is now the sole writer.
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
pub mod models;
pub mod routes;
pub mod service;

pub use context::{audit_auth_event, audit_write, AuditAction, AuditCtx};
pub use models::*;
pub use routes::audit_routes;
pub use service::{field_changes, AuditService};
