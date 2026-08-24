//! Portal-side auth middleware + extractor.
//!
//! The agent `auth_middleware` ignores portal tokens; this one only
//! accepts portal-tagged JWTs. Mounting it on the `/api/v1/portal` tree
//! gives the two surfaces independent session lifecycles.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use super::models::*;
use super::service::PortalAuthService;
use crate::utils::error::AppError;

/// Holder injected into the portal sub-router via
/// `axum::middleware::from_fn_with_state` so the middleware can decode
/// the Bearer token without pulling in the full router state.
#[derive(Clone)]
pub struct PortalAuthMiddleware {
    pub service: Arc<PortalAuthService>,
}

impl PortalAuthMiddleware {
    pub fn new(service: PortalAuthService) -> Self {
        Self {
            service: Arc::new(service),
        }
    }
}

pub async fn portal_auth_middleware(
    State(state): State<PortalAuthMiddleware>,
    mut request: Request,
    next: Next,
) -> Response {
    let auth_state = match bearer(&request) {
        Some(token) => match state.service.decode_token(token) {
            Ok(claims) => {
                // MAPPS-557: gate on tenant status BEFORE trusting the
                // JWT further. A suspended tenant's live portal
                // sessions must die on the next request, not after
                // the 15-min access token TTL. `ensure_tenant_active`
                // 403s for anything other than status='active'; here
                // we degrade that to unauthenticated so the downstream
                // extractors (`RequirePortalAuth` /
                // `RequirePortalAdmin`) return 401 in the standard
                // shape rather than 403 mid-chain.
                if state
                    .service
                    .ensure_tenant_active(claims.tid)
                    .await
                    .is_err()
                {
                    tracing::info!(
                        tenant_id = %claims.tid,
                        contact_id = %claims.sub,
                        "portal request rejected: owning tenant is not active",
                    );
                    request.extensions_mut().insert(PortalAuthState::default());
                    request.extensions_mut().insert(state.clone());
                    return next.run(request).await;
                }
                // Names are not minted into the JWT (PII minimisation), so
                // hydrate them from the contacts row (PMS-195). A missing
                // row or read error degrades to empty names rather than
                // failing the request.
                let (first_name, last_name) = state
                    .service
                    .contact_names(claims.tid, claims.sub)
                    .await
                    .ok()
                    .flatten()
                    .unwrap_or_default();
                PortalAuthState::authenticated(
                    CurrentContact {
                        id: claims.sub,
                        tenant_id: claims.tid,
                        company_id: claims.cid,
                        email: claims.email,
                        first_name,
                        last_name,
                    },
                    claims.sid,
                )
            }
            Err(_) => PortalAuthState::default(),
        },
        None => PortalAuthState::default(),
    };

    request.extensions_mut().insert(auth_state);
    // MAPPS-556: also carry the middleware itself into extensions so
    // downstream extractors (`RequirePortalAdmin`) can reach the
    // shared `PortalAuthService` for a portal_role lookup. Cheap
    // (arc clone); the middleware value is already a State handle.
    request.extensions_mut().insert(state.clone());
    next.run(request).await
}

fn bearer(req: &Request) -> Option<&str> {
    req.headers()
        .get("Authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

/// Portal-side `RequireAuth`. Yields the authenticated contact or 401.
#[derive(Clone)]
pub struct RequirePortalAuth(pub CurrentContact);

impl<S> axum::extract::FromRequestParts<S> for RequirePortalAuth
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let auth_state = parts
            .extensions
            .get::<PortalAuthState>()
            .cloned()
            .unwrap_or_default();
        match auth_state.contact {
            Some(c) => Ok(RequirePortalAuth(c)),
            None => Err(AppError::Unauthorized),
        }
    }
}

/// MAPPS-556: extractor that yields the authenticated portal contact
/// ONLY when they hold `contacts.portal_role = 'admin'` (or a NULL
/// row, treated as admin-equivalent for pre-554 backwards compat).
/// 401 when there is no portal session; 403 when the session belongs
/// to a `portal_role = 'user'` contact.
///
/// Used to gate the sub-user management endpoints under
/// `/portal/company/contacts` (invite, resend, deactivate) so
/// non-admin portal users cannot mint / evict colleagues.
///
/// Runs one DB round-trip per gated call. The gated endpoints are
/// low-frequency (invite / resend / remove), so the cost is fine.
/// A future extension can cache the role on the JWT if that changes.
#[derive(Clone)]
pub struct RequirePortalAdmin(pub CurrentContact);

impl<S> axum::extract::FromRequestParts<S> for RequirePortalAdmin
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let auth_state = parts
            .extensions
            .get::<PortalAuthState>()
            .cloned()
            .unwrap_or_default();
        let Some(contact) = auth_state.contact else {
            return Err(AppError::Unauthorized);
        };
        let mw = parts
            .extensions
            .get::<PortalAuthMiddleware>()
            .cloned()
            .ok_or_else(|| {
                AppError::Internal(
                    "PortalAuthMiddleware not present in request extensions".to_string(),
                )
            })?;
        let role = mw
            .service
            .contact_portal_role(contact.tenant_id, contact.id)
            .await?;
        match role.as_deref() {
            Some("admin") | None => Ok(RequirePortalAdmin(contact)),
            _ => Err(AppError::Forbidden(
                "Only your account admin can perform this action.".to_string(),
            )),
        }
    }
}

/// PMS-729 phase 2 H6: extractor that yields the authenticated
/// contact + the session id (JWT `sid` claim). Used by
/// `/portal/auth/me/sessions` (mark current) and
/// `DELETE /me/sessions/{id}` (refuse self-revoke). 401 when the
/// request has no valid portal session OR the token lacks `sid`
/// (pre-H6 tokens still verify but do not carry the claim; they
/// cannot use the session-management routes until they refresh).
#[derive(Clone)]
pub struct RequirePortalSession {
    pub contact: CurrentContact,
    pub sid: uuid::Uuid,
}

impl<S> axum::extract::FromRequestParts<S> for RequirePortalSession
where
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let auth_state = parts
            .extensions
            .get::<PortalAuthState>()
            .cloned()
            .unwrap_or_default();
        match (auth_state.contact, auth_state.sid) {
            (Some(contact), Some(sid)) if !sid.is_nil() => {
                Ok(RequirePortalSession { contact, sid })
            }
            _ => Err(AppError::Unauthorized),
        }
    }
}
