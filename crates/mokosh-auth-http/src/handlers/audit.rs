//! `/v1/auth/audit-logs` - admin-only paginated reader.

use axum::extract::{Query, State};
use axum::Json;
use mokosh_auth_core::{AuthError, UserId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::errors::HttpError;
use crate::extractors::BearerUser;
use crate::router::AuthHttpState;

#[derive(Debug, Deserialize)]
pub struct ListParams {
    #[serde(default)]
    pub limit: Option<i64>,
    #[serde(default)]
    pub offset: Option<i64>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub actor_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
pub struct AuditView {
    pub id: String,
    pub tenant_id: Option<String>,
    pub actor_id: Option<String>,
    pub event_kind: String,
    pub severity: String,
    pub ip: Option<String>,
    pub metadata: serde_json::Value,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Serialize)]
pub struct ListResponse {
    pub entries: Vec<AuditView>,
    pub limit: i64,
    pub offset: i64,
}

pub async fn list(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
    Query(params): Query<ListParams>,
) -> Result<Json<ListResponse>, HttpError> {
    if !matches!(admin.role, mokosh_auth_core::UserRole::Admin) {
        return Err(HttpError(AuthError::Forbidden("admin role required".into())));
    }
    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    let offset = params.offset.unwrap_or(0).max(0);
    let rows = st
        .provider
        .audit
        .list_recent(
            admin.tenant_id,
            params.kind.as_deref(),
            params.actor_id.map(UserId),
            limit,
            offset,
        )
        .await?;
    Ok(Json(ListResponse {
        entries: rows
            .into_iter()
            .map(|r| AuditView {
                id: r.id.to_string(),
                tenant_id: r.tenant_id.map(|t| t.0.to_string()),
                actor_id: r.actor_id.map(|a| a.0.to_string()),
                event_kind: r.event_kind,
                severity: r.severity,
                ip: r.ip.map(|i| i.to_string()),
                metadata: r.metadata,
                created_at: r.created_at,
            })
            .collect(),
        limit,
        offset,
    }))
}
