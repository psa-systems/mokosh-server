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
            Ok(claims) => PortalAuthState::authenticated(CurrentContact {
                id: claims.sub,
                tenant_id: claims.tid,
                company_id: claims.cid,
                email: claims.email,
                // Names are not minted into the JWT (PII minimisation);
                // handlers that need them call `PortalAuthService` or
                // re-read the contacts row. Defaults to empty here so
                // the handler can spot a stale token cheaply.
                first_name: String::new(),
                last_name: String::new(),
            }),
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
