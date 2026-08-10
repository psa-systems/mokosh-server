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
