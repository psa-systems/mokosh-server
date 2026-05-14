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
        return Err(HttpError(AuthError::Forbidden(
            "admin role required".into(),
        )));
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

#[derive(Debug, Deserialize)]
pub struct LaunchedAppBody {
    pub client_id: String,
}

/// `POST /v1/auth/audit/launched-app`
///
/// Records the user's click on a launcher tile so the audit log
/// reflects the cross-app hand-off. Doc 07 nice-to-have #9. Best-effort
/// from the SPA's side: the call fires just before the browser
/// navigates to the target app's origin; the row may not land if the
/// network drops mid-flight, but the loss is bounded to one click.
pub async fn launched_app(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(caller): BearerUser,
    Json(body): Json<LaunchedAppBody>,
) -> Result<axum::http::StatusCode, HttpError> {
    use mokosh_auth_core::{AuditEvent, ClientId};

    let client_id = body.client_id.trim().to_string();
    if client_id.is_empty() {
        return Err(HttpError(AuthError::InvalidRequest(
            "client_id required".into(),
        )));
    }
    let client_uuid = Uuid::parse_str(&client_id)
        .map_err(|_| HttpError(AuthError::InvalidRequest("client_id must be a uuid".into())))?;
    let client_label = st
        .provider
        .clients
        .find_by_client_id(ClientId(client_uuid))
        .await
        .ok()
        .flatten()
        .map(|c| c.name)
        .unwrap_or_else(|| client_id.clone());
    let _ = st
        .provider
        .audit
        .record(
            Some(caller.tenant_id),
            Some(caller.id),
            None,
            AuditEvent::AdminAction {
                admin_id: caller.id,
                action: format!("app.launched:{client_label}"),
                target: client_id,
            },
        )
        .await;
    Ok(axum::http::StatusCode::NO_CONTENT)
}
