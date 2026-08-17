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
use crate::modules::auth::middleware::{AuthRejection, BearerOutcome};
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
    // PMS-769: record what happened to the presented credential so
    // `RequirePortalAuth` can answer with the RFC 6750 challenge that matches.
    // `decode_token` collapses every jsonwebtoken failure into
    // `AppError::Unauthorized`, so the portal surface cannot single out an
    // expired token; both cases are an `invalid_token` rejection here.
    let mut outcome = BearerOutcome::Absent;
    let auth_state = match bearer(&request) {
        Some(token) => match state.service.decode_token(token) {
            Ok(claims) => {
                outcome = BearerOutcome::Accepted;
                // Names are not minted into the JWT (PII minimisation), so
                // hydrate them from the contacts row (PMS-195). A missing
                // row or read error degrades to empty names rather than
                // failing the request. PMS-769: log the read error before
                // substituting, so a DB fault is not indistinguishable from a
                // contact who genuinely has no name on file.
                let names = match state.service.contact_names(claims.tid, claims.sub).await {
                    Ok(names) => names,
                    Err(e) => {
                        tracing::warn!(error = %e, contact = %claims.sub, "portal contact name lookup failed; falling back to empty names");
                        None
                    }
                };
                let (first_name, last_name) = names.unwrap_or_default();
                PortalAuthState::authenticated(CurrentContact {
                    id: claims.sub,
                    tenant_id: claims.tid,
                    company_id: claims.cid,
                    email: claims.email,
                    first_name,
                    last_name,
                })
            }
            // PMS-769: log the cause rather than discarding it, so a portal
            // 401 leaves server-side evidence. `debug`: an expired or
            // hand-crafted portal token is expected traffic, and the 401 is
            // the loud part.
            Err(e) => {
                outcome = BearerOutcome::Rejected;
                tracing::debug!(error = %e, "portal bearer rejected");
                PortalAuthState::default()
            }
        },
        None => PortalAuthState::default(),
    };

    request.extensions_mut().insert(auth_state);
    request.extensions_mut().insert(outcome);
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
    type Rejection = AuthRejection;

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
            // PMS-769: same envelope as before, now with the RFC 6750
            // challenge the portal is also a bearer resource server for.
            None => Err(AuthRejection::challenged(
                AppError::Unauthorized,
                crate::modules::auth::middleware::bearer_outcome(parts),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, routing::get, Router};
    use tower::ServiceExt;

    /// PMS-769: the portal is a bearer resource server too, so its 401 carries
    /// the RFC 6750 challenge. `decode_token` cannot distinguish an expired
    /// portal token from any other bad one, so the outcome recorded by
    /// `portal_auth_middleware` is only ever `Absent` or `Rejected`.
    async fn challenge_for(outcome: Option<BearerOutcome>) -> String {
        let app = Router::new()
            .route("/", get(|_: RequirePortalAuth| async { "ok" }))
            .layer(axum::middleware::from_fn(
                move |mut request: Request<Body>, next: axum::middleware::Next| async move {
                    if let Some(outcome) = outcome {
                        request.extensions_mut().insert(outcome);
                    }
                    next.run(request).await
                },
            ));
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), 401);
        let challenge = response
            .headers()
            .get("www-authenticate")
            .expect("portal 401 must carry a challenge")
            .to_str()
            .unwrap()
            .to_string();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let envelope: serde_json::Value = serde_json::from_slice(&body).unwrap();
        // The portal envelope itself is unchanged.
        assert_eq!(envelope["error"]["code"], "UNAUTHORIZED");
        challenge
    }

    #[tokio::test]
    async fn portal_401_without_a_credential_gets_the_bare_challenge() {
        assert_eq!(challenge_for(Some(BearerOutcome::Absent)).await, "Bearer");
        // No middleware ran at all: still the bare challenge, never a claim
        // that a credential was rejected.
        assert_eq!(challenge_for(None).await, "Bearer");
    }

    #[tokio::test]
    async fn portal_401_for_a_rejected_token_says_invalid_token() {
        assert_eq!(
            challenge_for(Some(BearerOutcome::Rejected)).await,
            r#"Bearer error="invalid_token""#
        );
    }
}
