//! Audit log middleware.
//!
//! Fires on every mutating request (POST / PUT / PATCH / DELETE) on
//! `/api/v1`. Reads the AuthState (set by `auth_middleware`) for actor
//! identity, classifies the request by method into one of the
//! audit_log CHECK-constraint actions, and records a row tagged with
//! `entity_type` derived from the URL's second path segment (e.g.
//! `tickets`, `invoices`). Failures are swallowed so a misbehaving log
//! write never causes the request itself to fail.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::Response;

use super::service::AuditService;
use crate::modules::auth::AuthState;

#[derive(Clone)]
pub struct AuditMiddlewareState {
    pub service: Arc<AuditService>,
}

pub async fn audit_log_middleware(
    State(state): State<AuditMiddlewareState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let action = match method.as_str() {
        "POST" => Some("create"),
        "PUT" | "PATCH" => Some("update"),
        "DELETE" => Some("delete"),
        _ => None,
    };
    let path = request.uri().path().to_string();
    let entity_type = path
        .strip_prefix("/api/v1/")
        .and_then(|p| p.split('/').next())
        .unwrap_or("unknown")
        .to_string();
    let user_agent = request
        .headers()
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let auth_state = request
        .extensions()
        .get::<AuthState>()
        .cloned()
        .unwrap_or_default();

    let response = next.run(request).await;

    // Only audit successful mutating requests.
    if let Some(action) = action {
        if response.status().is_success() {
            if let (Some(_), Some(user)) = (auth_state.tenant_id, auth_state.user.as_ref()) {
                let _ = state
                    .service
                    .append(
                        crate::modules::auth::TenantScoped::tenant(user),
                        Some(user.id),
                        action,
                        &entity_type,
                        None,
                        None,
                        Some(addr.ip().to_string()),
                        user_agent,
                    )
                    .await;
            }
        }
    }
    response
}
