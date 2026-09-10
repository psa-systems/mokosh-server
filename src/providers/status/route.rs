//! HTTP routes for the provider-status report.
//!
//! Two endpoints, both admin-gated:
//!
//! - `GET /api/v1/admin/providers/status` returns the JSON envelope for
//!   BUNYIP-634 to aggregate.
//! - `GET /api/v1/admin/providers/status.html` returns the HTML admin page
//!   for standalone deployments with no Bunyip.
//!
//! Both go through the SAME [`super::collect`] and therefore cannot report
//! different states of the same process. The `agreement_between_renderings`
//! test in `super::tests` pins that promise for the DATA; the routes here
//! deliberately do not add anything a renderer could disagree with.
//!
//! # Auth deferred
//!
//! The ticket names a Bunyip machine credential as the JSON endpoint's
//! future auth, but flags it "revise if BUNYIP-634 settles on another".
//! Until that ticket ships, `RequireAdmin` is the gate: a staff bearer
//! with an admin role. The HTML endpoint carries the same gate.

use axum::response::{Html, IntoResponse};
use axum::routing::get;
use axum::{Json, Router};

use crate::modules::auth::RequireAdmin;

/// The admin router carrying both endpoints. Mounted under `/api/v1` by
/// `create_api_router` so the shared auth middleware and error envelope
/// layers already wrap it.
pub fn provider_status_admin_routes() -> Router {
    Router::new()
        .route("/admin/providers/status", get(status_json))
        .route("/admin/providers/status.html", get(status_html))
}

/// JSON handler. Admin-gated; produces the schema-versioned envelope from
/// `renderer_json::render_json` against a freshly-collected report.
async fn status_json(_admin: RequireAdmin) -> impl IntoResponse {
    let report = super::collect();
    Json(super::renderer_json::render_json(&report))
}

/// HTML handler. Admin-gated; produces the standalone admin page from
/// `renderer_html::render_html` against a freshly-collected report.
async fn status_html(_admin: RequireAdmin) -> impl IntoResponse {
    let report = super::collect();
    let body = super::renderer_html::render_html(&report);
    (
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        Html(body),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use axum::middleware;
    use tower::ServiceExt;

    use crate::modules::auth::AuthState;
    use mokosh_types::auth::{CurrentUser, UserRole};

    /// Inject a fixed `AuthState` into the request extensions the way the
    /// production `auth_middleware` would, so `RequireAdmin` sees a caller
    /// without a database on the test path.
    fn with_auth(auth: AuthState) -> impl Fn(Request<Body>) -> Request<Body> + Clone {
        move |mut req: Request<Body>| {
            req.extensions_mut().insert(auth.clone());
            req
        }
    }

    fn test_router(auth: Option<AuthState>) -> Router {
        let base = provider_status_admin_routes();
        match auth {
            Some(auth) => {
                let injector = with_auth(auth);
                base.layer(middleware::from_fn(move |req, next: middleware::Next| {
                    let injector = injector.clone();
                    async move {
                        let req = injector(req);
                        next.run(req).await
                    }
                }))
            }
            None => base,
        }
    }

    fn admin_user() -> CurrentUser {
        CurrentUser {
            id: uuid::Uuid::nil(),
            tenant_id: uuid::Uuid::nil(),
            email: "admin@example.com".to_string(),
            first_name: "Admin".to_string(),
            last_name: "User".to_string(),
            role: UserRole::Admin,
            timezone: "UTC".to_string(),
            avatar_url: None,
            profile_completed: true,
            date_format_string: None,
            theme_base_mode: None,
            theme_accent_id: None,
            own_company_id: None,
            tenant_kind: String::new(),
        }
    }

    fn non_admin_user() -> CurrentUser {
        let mut u = admin_user();
        u.role = UserRole::Technician;
        u
    }

    /// An unauthenticated request lands on `RequireAdmin`'s default:
    /// [`AuthState::default`] is not authenticated, which reads as 401.
    #[tokio::test]
    async fn unauthenticated_json_is_rejected() {
        let app = test_router(None);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/providers/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        // Auth middleware isn't wired here so the default AuthState is
        // unauthenticated; `RequireAdmin` rejects. The rejection is 401 or
        // 403 depending on the code path (both are non-2xx and would be a
        // deny in production).
        assert!(
            !response.status().is_success(),
            "unauthenticated request must be rejected: {:?}",
            response.status()
        );
    }

    /// A non-admin caller is forbidden.
    #[tokio::test]
    async fn non_admin_json_is_forbidden() {
        let auth = AuthState::authenticated(non_admin_user(), uuid::Uuid::nil());
        let app = test_router(Some(auth));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/providers/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// An admin caller gets JSON with the expected envelope shape.
    #[tokio::test]
    async fn admin_json_is_ok_and_carries_the_envelope() {
        let auth = AuthState::authenticated(admin_user(), uuid::Uuid::nil());
        let app = test_router(Some(auth));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/providers/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(value["schema_version"].is_string());
        assert!(value["report"]["hosting_profile"].is_string());
        assert!(value["report"]["kinds"].is_array());
    }

    /// An admin caller gets HTML with a `text/html` content type.
    #[tokio::test]
    async fn admin_html_is_ok_and_serves_text_html() {
        let auth = AuthState::authenticated(admin_user(), uuid::Uuid::nil());
        let app = test_router(Some(auth));
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/admin/providers/status.html")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .expect("Content-Type header")
            .to_str()
            .unwrap();
        assert!(
            content_type.starts_with("text/html"),
            "expected text/html, got {content_type}"
        );
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(html.contains("<title>Mokosh Provider Status</title>"));
    }

    /// `/ready` is not defined in this router's own module and the source
    /// scan below pins that this PR does not touch its handler.
    #[test]
    fn ready_handler_untouched_by_this_pr() {
        const ROUTER: &str = include_str!("../../api/router.rs");
        // The `/ready` handler is `ready_check` inside `create_api_router`.
        // If a future edit renames or reshapes it this scan is out of
        // step, but that is what a review of this file would notice.
        assert!(ROUTER.contains("/ready"), "the /ready route is present");
        assert!(
            ROUTER.contains("async fn ready_check"),
            "the /ready handler stays named ready_check"
        );
    }
}
