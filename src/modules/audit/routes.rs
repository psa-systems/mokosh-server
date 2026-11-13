//! Audit log HTTP routes.

use std::sync::Arc;

use crate::utils::json::Json;
use axum::{
    extract::{Path, Query, State},
    routing::get,
    Router,
};
use uuid::Uuid;
use validator::Validate;

use super::models::*;
use super::service::{AuditService, HISTORY_ENTITY_TYPES};
use crate::modules::auth::{RequireAdmin, RequireAuth, TenantScoped};
use crate::utils::error::{AppError, AppResult};
use crate::utils::pagination::{PaginatedResponse, PaginationParams};

#[derive(Clone)]
pub struct AuditRouterState {
    pub service: Arc<AuditService>,
}

pub fn audit_routes(service: AuditService) -> Router {
    let state = AuditRouterState {
        service: Arc::new(service),
    };
    // SPEC-5.508: GET-only surface; the API has no audit update or delete.
    Router::new()
        .route("/audit-log", get(list_audit_log))
        .route("/audit-log/export.csv", get(export_audit_log_csv))
        .route(
            "/audit-log/entity/{entity_type}/{entity_id}",
            get(list_entity_history),
        )
        .with_state(state)
}

/// Per-record change history. Unlike `/audit-log` this is open to any
/// authenticated tenant member (not just admins) but is tenant-scoped and
/// limited to the whitelisted entity types, so a user can review the edit
/// history of a record they can already see (PMS-182/184/185) without gaining
/// the full tenant audit trail. An unknown entity type is a 404.
// SPEC-5.519, SPEC-5.520: any member, whitelisted types only, tenant-scoped.
async fn list_entity_history(
    State(s): State<AuditRouterState>,
    RequireAuth(u): RequireAuth,
    Path((entity_type, entity_id)): Path<(String, Uuid)>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<EntityHistoryEntry>>> {
    pagination.reject_unsupported_sort()?;
    if !HISTORY_ENTITY_TYPES.contains(&entity_type.as_str()) {
        return Err(AppError::NotFound("history".to_string()));
    }
    let (items, total) = s
        .service
        .list_entity_history(u.tenant(), &entity_type, entity_id, &pagination)
        .await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

// SPEC-5.508, SPEC-5.509: admin gate, own tenant, 422 on sort or over-long filters.
async fn list_audit_log(
    State(s): State<AuditRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Query(filter): Query<AuditLogFilter>,
    Query(pagination): Query<PaginationParams>,
) -> AppResult<Json<PaginatedResponse<AuditLogEntryResponse>>> {
    pagination.reject_unsupported_sort()?;
    filter.validate()?;
    // Super-admins can cross tenants by setting the special X-Tenant-Id
    // header (read by a future middleware); for now everyone reads
    // their own tenant.
    let scope = Some(u.tenant());
    let (items, total) = s.service.list(scope, &filter, &pagination).await?;
    Ok(Json(PaginatedResponse::from_params(
        items,
        &pagination,
        total,
    )))
}

/// PMS-455: tenant-scoped CSV export of the audit log. Same admin gate
/// and same filter envelope as `list_audit_log`, but instead of a
/// paginated JSON page we stream every matching row as CSV with a
/// `text/csv` content-type and a `Content-Disposition: attachment`
/// header so the browser triggers a download. The hard 50k row cap is
/// a defensive ceiling - a tenant with that many privileged actions
/// inside a single filter scope is large enough that the operator
/// should narrow the date range, and the cap keeps a runaway request
/// from holding a DB connection for minutes.
// SPEC-5.508, SPEC-5.515, SPEC-5.518: admin gate, same filters, attachment response.
async fn export_audit_log_csv(
    State(s): State<AuditRouterState>,
    RequireAuth(u): RequireAuth,
    _a: RequireAdmin,
    Query(filter): Query<AuditLogFilter>,
) -> AppResult<axum::response::Response> {
    filter.validate()?;
    // SPEC-5.518: intended 50,000-row ceiling.
    let pagination = PaginationParams {
        page: 1,
        per_page: 50_000,
        sort: None,
        sort_dir: "desc".to_string(),
    };
    let scope = Some(u.tenant());
    let (items, _total) = s.service.list(scope, &filter, &pagination).await?;

    let mut buf = String::new();
    // Header row. Matches the column order an operator typically wants
    // when reviewing the export in a spreadsheet (when -> who -> what
    // -> target -> network metadata).
    // SPEC-5.516: fixed header then one row per entry.
    buf.push_str(
        "timestamp,actor,actor_id,action,entity_type,entity_id,entity_name,ip_address,user_agent\n",
    );
    for row in items.iter() {
        push_csv_field(&mut buf, &row.timestamp.to_rfc3339());
        buf.push(',');
        push_csv_field(&mut buf, row.user_name.as_deref().unwrap_or("System"));
        buf.push(',');
        push_csv_field(
            &mut buf,
            row.user_id
                .map(|u| u.to_string())
                .unwrap_or_default()
                .as_str(),
        );
        buf.push(',');
        push_csv_field(&mut buf, &row.action);
        buf.push(',');
        push_csv_field(&mut buf, &row.entity_type);
        buf.push(',');
        push_csv_field(
            &mut buf,
            row.entity_id
                .map(|id| id.to_string())
                .unwrap_or_default()
                .as_str(),
        );
        buf.push(',');
        push_csv_field(&mut buf, row.entity_name.as_deref().unwrap_or(""));
        buf.push(',');
        push_csv_field(&mut buf, row.ip_address.as_deref().unwrap_or(""));
        buf.push(',');
        push_csv_field(&mut buf, row.user_agent.as_deref().unwrap_or(""));
        buf.push('\n');
    }

    let body = axum::body::Body::from(buf.into_bytes());
    let response = axum::response::Response::builder()
        .header(axum::http::header::CONTENT_TYPE, "text/csv; charset=utf-8")
        .header(
            axum::http::header::CONTENT_DISPOSITION,
            crate::utils::content_disposition::content_disposition("audit-log.csv"),
        )
        .body(body)
        .map_err(|e| AppError::Internal(format!("failed to build CSV response: {e}")))?;
    Ok(response)
}

/// Append `value` to the CSV buffer, quoting it when it contains a
/// comma, quote, or newline. The doubled-quote convention is the
/// standard CSV escape (RFC 4180).
// SPEC-5.517: RFC 4180 quoting.
fn push_csv_field(buf: &mut String, value: &str) {
    let needs_quoting = value.contains([',', '"', '\n', '\r']);
    if needs_quoting {
        buf.push('"');
        for c in value.chars() {
            if c == '"' {
                buf.push('"');
                buf.push('"');
            } else {
                buf.push(c);
            }
        }
        buf.push('"');
    } else {
        buf.push_str(value);
    }
}
