//! HTTP routes for the provider-status report.
//!
//! Three endpoints, all admin-gated:
//!
//! - `GET /api/v1/admin/providers/status` returns the JSON envelope for
//!   BUNYIP-634 to aggregate.
//! - `GET /api/v1/admin/providers/status.html` returns the HTML admin page
//!   for standalone deployments with no Bunyip.
//! - `POST /api/v1/admin/providers/status/refresh` triggers a configuration
//!   generation swap through `config::try_refresh` and returns the
//!   freshly-collected report (PMS-984's "refresh control from the report").
//!
//! Both reads go through the SAME [`super::collect`] and therefore cannot
//! report different states of the same process. The `agreement_between_renderings`
//! test in `super::tests` pins that promise for the DATA; the routes here
//! deliberately do not add anything a renderer could disagree with.
//!
//! # Auth deferred
//!
//! The ticket names a Bunyip machine credential as the JSON endpoint's
//! future auth, but flags it "revise if BUNYIP-634 settles on another".
//! Until that ticket ships, `RequireAdmin` is the gate: a staff bearer
//! with an admin role. The HTML endpoint carries the same gate, and so
//! does the POST refresh handler, which additionally records the operator's
//! login as the actor on the resulting generation.

use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use crate::config::{try_refresh, RefreshOutcome, RefreshRequest};
use crate::modules::auth::{RequireAdmin, RequireAdminUser};

/// The admin router carrying all three endpoints. Mounted under `/api/v1` by
/// `create_api_router` so the shared auth middleware and error envelope
/// layers already wrap it.
pub fn provider_status_admin_routes() -> Router {
    Router::new()
        .route("/admin/providers/status", get(status_json))
        .route("/admin/providers/status.html", get(status_html))
        .route("/admin/providers/status/refresh", post(refresh_status))
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

/// POST refresh handler (PMS-984). Admin-gated; runs `config::try_refresh`
/// as the calling operator (their email is the `RefreshActor::Operator`
/// login), then returns the same JSON envelope the GET handler produces
/// plus a `refresh_outcome` field naming what happened.
///
/// `RefreshRequest::operator(...)` with no required keys is a best-effort
/// swap: it always applies, so the current shape is 200 + Applied. The
/// Rejected arm is written and returns 409 anyway, because [`try_refresh`]
/// grows required-key rejections in follow-up work (PMS-1012's per-key
/// refresh from the admin surface) and the shape must survive that.
async fn refresh_status(RequireAdminUser(user): RequireAdminUser) -> impl IntoResponse {
    let outcome = try_refresh(RefreshRequest::operator(user.email.clone()));
    let report = super::collect();
    let mut envelope = super::renderer_json::render_json(&report);
    let (status, outcome_json) = match outcome {
        RefreshOutcome::Applied { generation, .. } => (
            StatusCode::OK,
            json!({
                "status": "applied",
                "generation_number": generation.number(),
            }),
        ),
        RefreshOutcome::Rejected { reason, previous } => (
            StatusCode::CONFLICT,
            json!({
                "status": "rejected",
                "previous_generation_number": previous.number(),
                "reason": {
                    "required_keys_unresolved": reason
                        .required_keys_unresolved
                        .iter()
                        .map(|k| k.name())
                        .collect::<Vec<_>>(),
                    "bootstrap_keys_refused": reason
                        .bootstrap_keys_refused
                        .iter()
                        .map(|k| k.name())
                        .collect::<Vec<_>>(),
                    "providers_consulted": reason.providers_consulted,
                },
            }),
        ),
    };
    envelope["refresh_outcome"] = outcome_json;
    (status, Json(envelope))
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

    /// PMS-984: an unauthenticated POST to the refresh endpoint is rejected.
    /// `RequireAdminUser` delegates to `RequireAdmin`, and the default
    /// `AuthState` is unauthenticated, so the response is a non-2xx deny.
    #[tokio::test]
    async fn unauthenticated_refresh_is_rejected() {
        let app = test_router(None);
        let response = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/admin/providers/status/refresh")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            !response.status().is_success(),
            "unauthenticated refresh must be rejected: {:?}",
            response.status()
        );
    }

    /// PMS-984: a non-admin caller cannot trigger a refresh.
    #[tokio::test]
    async fn non_admin_refresh_is_forbidden() {
        let auth = AuthState::authenticated(non_admin_user(), uuid::Uuid::nil());
        let app = test_router(Some(auth));
        let response = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/admin/providers/status/refresh")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    /// PMS-984: an admin caller triggers a best-effort refresh, gets a 200
    /// with the envelope + `refresh_outcome.status == "applied"`, and the
    /// report's actor is now the caller's login.
    #[tokio::test]
    async fn admin_refresh_applies_and_names_the_operator() {
        let auth = AuthState::authenticated(admin_user(), uuid::Uuid::nil());
        let app = test_router(Some(auth));
        let response = app
            .oneshot(
                Request::builder()
                    .method(axum::http::Method::POST)
                    .uri("/admin/providers/status/refresh")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["refresh_outcome"]["status"], "applied");
        assert!(value["refresh_outcome"]["generation_number"].is_number());
        // The envelope carries the same report shape the GET produces, so a
        // client reading either learns the same shape.
        assert!(value["schema_version"].is_string());
        assert!(value["report"]["hosting_profile"].is_string());
        // The report's own actor names the operator that just refreshed:
        // `RequireAdminUser` handed us their email as the `Operator` login.
        // `ProviderStatusReport` renders the actor through `Debug`, so the
        // wire shape is `Operator(<login>)` for the operator variant.
        let actor = value["report"]["configuration_generation"]["actor"]
            .as_str()
            .expect("actor is a string");
        assert!(
            actor.contains("admin@example.com"),
            "the actor must name the operator login, got {actor}"
        );
        assert!(
            actor.starts_with("Operator"),
            "the actor must be the Operator variant, got {actor}"
        );
    }

    /// PMS-984: the HTML page carries the refresh form pointing at the POST
    /// endpoint, so an operator opening the page can trigger a swap without
    /// a second UI.
    #[tokio::test]
    async fn admin_html_carries_the_refresh_control() {
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
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let html = std::str::from_utf8(&body).unwrap();
        assert!(
            html.contains("action=\"/api/v1/admin/providers/status/refresh\""),
            "the HTML page must carry a POST form to the refresh endpoint"
        );
        assert!(html.contains("method=\"post\""));
        assert!(html.contains(">Refresh configuration<"));
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
