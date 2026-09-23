//! Wire types for the status module.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::Validate;

/// The four check kinds recognised on the wire. Open enum: unknown kinds
/// arriving at the ingest handler are refused with 422 rather than mapped
/// to a bucket, and the schema CHECK constraint is the ultimate guard.
pub const CHECK_KINDS: &[&str] = &["backup", "disk", "patch", "antivirus"];

/// The four outcomes recognised on the wire.
pub const OUTCOMES: &[&str] = &["success", "warning", "failure", "unknown"];

/// Body for the RMM status ingest.
///
/// Same authentication as the RMM alerts ingest: the caller signs the raw
/// bytes with the connection's `api_secret` and puts the HMAC in
/// `X-Signature`. The rmm-side handler verifies the signature and only
/// then calls the service.
#[derive(Debug, Clone, Serialize, Deserialize, Validate)]
pub struct IngestStatusRequest {
    /// The `rmm_connections` row whose secret signed this payload. Also
    /// scopes which mapping table the device lookup runs against.
    pub rmm_connection_id: Uuid,
    /// The identifier the source uses for the system this observation is
    /// about. Combined with the connection's source name to resolve or
    /// create the `monitored_systems` row.
    pub rmm_device_id: String,
    /// A friendly name for the system as the source knows it. Used only
    /// on first sight; a rename later does not rewrite historical
    /// observations.
    #[validate(length(min = 1, max = 255))]
    pub system_name: String,
    /// One of [`CHECK_KINDS`]. Refused at the handler if not.
    pub check_kind: String,
    /// One of [`OUTCOMES`]. Refused at the handler if not.
    pub outcome: String,
    /// When the source observed the outcome. The third leg of the
    /// idempotency triple; a replay with the same triple is a no-op.
    pub observed_at: DateTime<Utc>,
    /// Whatever the source carries about the check. Stored as-is so a
    /// future kind can surface details without a schema change.
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// One monitored system, plus the latest observation per check kind.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatusResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub company_id: Uuid,
    pub external_source: String,
    pub external_id: String,
    pub name: String,
    pub first_seen_at: DateTime<Utc>,
    pub last_seen_at: DateTime<Utc>,
    pub observations: Vec<CurrentObservation>,
}

/// The most recent observation for one (system, check_kind). Fields align
/// with the row on disk minus the internal audit columns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentObservation {
    pub check_kind: String,
    pub outcome: String,
    pub observed_at: DateTime<Utc>,
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// A per-company rollup of the CURRENT backup outcome per system. The
/// system list holds every system on the company; `latest` is `None`
/// when the system has never carried a backup observation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyBackupStatusResponse {
    pub company_id: Uuid,
    pub systems: Vec<CompanySystemBackup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanySystemBackup {
    pub monitored_system_id: Uuid,
    pub system_name: String,
    pub latest: Option<CurrentObservation>,
}
