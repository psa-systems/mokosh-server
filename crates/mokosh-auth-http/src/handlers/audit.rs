//! `/v1/auth/audit-logs` - admin-only paginated reader.

use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use chrono::{DateTime, Utc};
use mokosh_auth_core::{AuditListFilter, AuthError, UserId};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use uuid::Uuid;

use crate::errors::HttpError;
use crate::extractors::BearerUser;
use crate::handlers::shared::require_admin;
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
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub severity: Option<String>,
    /// RFC 3339 timestamps. Inclusive bounds.
    #[serde(default)]
    pub from: Option<DateTime<Utc>>,
    #[serde(default)]
    pub to: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
pub struct AuditView {
    pub id: String,
    pub tenant_id: Option<String>,
    pub actor_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_email: Option<String>,
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

fn build_filter(params: &ListParams, limit_cap: i64) -> AuditListFilter {
    AuditListFilter {
        kind: params.kind.clone(),
        actor_id: params.actor_id.map(UserId),
        search: params.search.clone(),
        severity: params.severity.clone(),
        date_from: params.from,
        date_to: params.to,
        limit: params.limit.unwrap_or(50).clamp(1, limit_cap),
        offset: params.offset.unwrap_or(0).max(0),
    }
}

pub async fn list(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
    Query(params): Query<ListParams>,
) -> Result<Json<ListResponse>, HttpError> {
    require_admin(admin.role)?;
    let filter = build_filter(&params, 200);
    let limit = filter.limit;
    let offset = filter.offset;
    let rows = st
        .provider
        .audit
        .list_filtered(admin.tenant_id, filter)
        .await?;
    Ok(Json(ListResponse {
        entries: rows
            .into_iter()
            .map(|r| AuditView {
                id: r.id.to_string(),
                tenant_id: r.tenant_id.map(|t| t.0.to_string()),
                actor_id: r.actor_id.map(|a| a.0.to_string()),
                actor_email: r.actor_email,
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

/// `GET /v1/auth/audit-logs.csv`
///
/// Same filters as `list`, but streams the matched rows as CSV with
/// the columns: created_at, severity, event_kind, actor_email, actor_id,
/// ip, metadata. Capped at 10,000 rows to keep memory bounded; if you
/// need a wider export, narrow the date range.
pub async fn list_csv(
    State(st): State<Arc<AuthHttpState>>,
    BearerUser(admin): BearerUser,
    Query(params): Query<ListParams>,
) -> Result<Response, HttpError> {
    require_admin(admin.role)?;
    let mut filter = build_filter(&params, 10_000);
    // CSV path defaults to the cap if no explicit limit given, so a
    // bare /audit-logs.csv returns a meaningful dump rather than 50 rows.
    if params.limit.is_none() {
        filter.limit = 10_000;
    }
    let rows = st
        .provider
        .audit
        .list_filtered(admin.tenant_id, filter)
        .await?;

    // Hand-roll CSV to avoid pulling in another dep. Standard rules:
    // - Quote any field containing comma, quote, CR, or LF
    // - Escape embedded quotes by doubling them
    fn csv_field(s: &str) -> String {
        let needs_quote = s.chars().any(|c| matches!(c, ',' | '"' | '\n' | '\r'));
        if needs_quote {
            let escaped = s.replace('"', "\"\"");
            format!("\"{escaped}\"")
        } else {
            s.to_string()
        }
    }

    let mut body = String::with_capacity(rows.len() * 200);
    body.push_str("created_at,severity,event_kind,actor_email,actor_id,ip,metadata\n");
    for r in rows {
        let metadata = serde_json::to_string(&r.metadata).unwrap_or_default();
        let cols = [
            r.created_at.to_rfc3339(),
            r.severity,
            r.event_kind,
            r.actor_email.unwrap_or_default(),
            r.actor_id.map(|a| a.0.to_string()).unwrap_or_default(),
            r.ip.map(|i| i.to_string()).unwrap_or_default(),
            metadata,
        ];
        let line: Vec<String> = cols.iter().map(|c| csv_field(c)).collect();
        body.push_str(&line.join(","));
        body.push('\n');
    }

    let filename = format!("audit-logs-{}.csv", Utc::now().format("%Y%m%d-%H%M%S"));
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{filename}\""),
            ),
        ],
        body,
    )
        .into_response())
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
