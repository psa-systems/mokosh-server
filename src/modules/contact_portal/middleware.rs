//! mokosh-contact-login prompt 004: contact-plane auth middleware +
//! request extractors.
//!
//! Runs on the `/api/v1/contact/*` sub-router. Reads the Bearer token
//! (from `Authorization: Bearer ...`) OR the `mokosh:contact_token`
//! cookie (see routes.rs for the cookie-setting side), verifies it,
//! ensures the tenant is still active, and stashes a
//! `ContactAuthState` in request extensions for downstream extractors.
//!
//! Distinct from the retired `portal_auth_middleware` (prompt 001)
//! and from the staff-plane `auth_middleware`: the JWT `typ` claim
//! check ("contact") is what stops cross-plane replay.
//!
//! PMS-985: the `ContactSession` this attaches carries identity and
//! scope only, never capabilities. The token's `caps` claim is dropped
//! here on purpose, so a handler that needs to know what the caller may
//! do has to load it from `portal_roles` for the request it is serving.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;

use super::models::ContactSession;
use super::service::ContactAuthService;
use crate::utils::error::AppError;

/// Sibling of the retired `PortalAuthState` - carries the decoded
/// session (`None` on any failure) into request extensions so
/// `RequireContactAuth` can 401 without another DB read.
#[derive(Clone, Default)]
pub struct ContactAuthState {
    pub session: Option<ContactSession>,
}

impl ContactAuthState {
    pub fn authenticated(session: ContactSession) -> Self {
        Self {
            session: Some(session),
        }
    }
}

/// Injected into the `/api/v1/contact/*` sub-router via
/// `from_fn_with_state`. Holds the shared `ContactAuthService`
/// clone the middleware calls.
#[derive(Clone)]
pub struct ContactAuthMiddleware {
    pub service: Arc<ContactAuthService>,
}

impl ContactAuthMiddleware {
    pub fn new(service: ContactAuthService) -> Self {
        Self {
            service: Arc::new(service),
        }
    }
}

pub async fn portal_contact_middleware(
    State(state): State<ContactAuthMiddleware>,
    mut request: Request,
    next: Next,
) -> Response {
    let auth_state = match bearer(&request).or_else(|| cookie(&request)) {
        Some(token) => match state.service.decode_token(token) {
            Ok(claims) => {
                // mokosh-contact-login prompt 004: gate on tenant
                // status BEFORE trusting the JWT further. A suspended
                // tenant's live contact sessions must die on the next
                // request, not after the 15-min access token TTL.
                if state
                    .service
                    .ensure_tenant_active(claims.tid)
                    .await
                    .is_err()
                {
                    tracing::info!(
                        tenant_id = %claims.tid,
                        contact_id = %claims.sub,
                        "contact request rejected: owning tenant is not active",
                    );
                    ContactAuthState::default()
                } else {
                    ContactAuthState::authenticated(ContactSession {
                        id: claims.sub,
                        tenant_id: claims.tid,
                        company_id: claims.cid,
                        email: claims.email,
                        sid: claims.sid,
                    })
                }
            }
            Err(_) => ContactAuthState::default(),
        },
        None => ContactAuthState::default(),
    };
    request.extensions_mut().insert(auth_state);
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

/// mokosh-contact-login prompt 004: parse `mokosh:contact_token=<value>`
/// out of the Cookie header. Same shape the staff Google-OAuth path
/// uses; no cookie crate dep.
fn cookie(req: &Request) -> Option<&str> {
    let raw = req
        .headers()
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?;
    for pair in raw.split(';') {
        let pair = pair.trim();
        if let Some(value) = pair.strip_prefix("mokosh:contact_token=") {
            if !value.is_empty() {
                return Some(value);
            }
        }
    }
    None
}

/// mokosh-contact-login prompt 004: extractor that yields the
/// authenticated contact or 401. Every /api/v1/contact/* route that
/// touches contact-scoped data uses this.
#[derive(Clone)]
pub struct RequireContactAuth(pub ContactSession);

impl<S> axum::extract::FromRequestParts<S> for RequireContactAuth
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
            .get::<ContactAuthState>()
            .cloned()
            .unwrap_or_default();
        match auth_state.session {
            Some(s) => Ok(RequireContactAuth(s)),
            None => Err(AppError::Unauthorized),
        }
    }
}
