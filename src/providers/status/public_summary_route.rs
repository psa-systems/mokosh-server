//! PMS-1144: HTTP route for the outward provider-configuration summary.
//!
//! `GET /api/v1/providers` returns the [`super::public_summary::PublicProviderSummary`]
//! envelope. UNAUTHENTICATED by design: BUNYIP-634's aggregator reaches
//! Mokosh from the outside with no credential exchange, and every field in
//! the envelope is a `&'static str` naming a provider identity. Everything
//! that could leak (values, credentials, URLs, per-key provenance, the
//! generation actor) is excluded by construction in
//! [`super::public_summary::summarize`], and pinned by
//! [`super::public_summary::tests::public_summary_carries_no_secret_looking_strings`].
//!
//! The route is peer to `/version`, not to `/admin/providers/status`. The
//! admin route stays behind `RequireAdmin` and continues to serve the full
//! report shape for standalone operators and (later) BUNYIP-634's
//! machine-credential aggregator.

use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};

/// The router carrying the single public endpoint. Mounted under `/api/v1`
/// by `create_api_router` alongside `/version` and `/health` so it
/// inherits the shared middleware stack (error envelope, CORS) without
/// picking up the request-authentication middleware every authenticated
/// endpoint needs.
pub fn provider_public_summary_routes() -> Router {
    Router::new().route("/providers", get(public_summary))
}

/// Handler: collect the full report, reduce it to the outward summary, and
/// return it. The reduction is a pure function of the report so the
/// serialised bytes are testable in isolation (see the sibling
/// `public_summary::tests`); this route deliberately does nothing a
/// renderer could disagree with.
async fn public_summary() -> impl IntoResponse {
    let report = super::collect();
    let summary = super::public_summary::summarize(&report);
    Json(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    /// The endpoint is reachable WITHOUT any auth injection. The router
    /// under test carries no auth middleware, matching the mount site in
    /// `create_api_router` which places this route peer to `/version` and
    /// `/health` rather than behind the auth stack.
    #[tokio::test]
    async fn unauthenticated_get_is_ok() {
        let app = provider_public_summary_routes();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/providers")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// The body is the summary envelope: schema_version, hosting_profile,
    /// and a `providers` object with the five deployment-scoped kinds as
    /// arrays. The kinds are the CONTRACT for BUNYIP-634's aggregator.
    #[tokio::test]
    async fn body_shape_is_the_public_summary_envelope() {
        let app = provider_public_summary_routes();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/providers")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["schema_version"], "1");
        assert!(value["hosting_profile"].is_string());
        for kind in [
            "configuration",
            "secrets_application",
            "storage",
            "authentication",
            "email",
        ] {
            assert!(
                value["providers"][kind].is_array(),
                "providers.{kind} must be present as an array"
            );
        }
        // The tenant-tier kind is deliberately absent from the summary.
        assert!(value["providers"]["secrets_tenant"].is_null());
    }
}
