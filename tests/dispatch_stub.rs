//! Integration test for the placeholder-module stub body (F12 / PMS-125).
//!
//! `/api/v1/dispatch` is still a placeholder behind PMS-58. The router
//! used to respond with a generic `Not implemented yet` envelope; this
//! test pins the new per-module body so the contract does not silently
//! regress to the old shape, and so an integrator can rely on the JSON
//! fields (`module`, `tracking_issue`, `planned_endpoints`, ...) to
//! find their way to the tracking issue.

mod common;

use common::boot;
use sqlx::PgPool;

#[sqlx::test]
async fn dispatch_stub_returns_self_documenting_501(pool: PgPool) {
    let app = boot(pool).await;

    let resp = app
        .client
        .get(app.url("/api/v1/dispatch"))
        .send()
        .await
        .expect("send GET /api/v1/dispatch");
    assert_eq!(
        resp.status().as_u16(),
        501,
        "dispatch stub must return 501"
    );
    let body: serde_json::Value = resp.json().await.expect("dispatch stub JSON body");

    assert_eq!(body["error"], "not_implemented");
    assert_eq!(body["module"], "dispatch");
    assert_eq!(body["tracking_issue"], "PMS-58");
    assert_eq!(body["path"], "/api/v1/dispatch");
    assert!(
        body["tracking_url"]
            .as_str()
            .map(|s| s.contains("PMS-58"))
            .unwrap_or(false),
        "tracking_url must reference the YouTrack key: {body}"
    );
    let endpoints = body["planned_endpoints"]
        .as_array()
        .expect("planned_endpoints must be an array");
    assert!(
        !endpoints.is_empty(),
        "planned_endpoints must list at least one entry"
    );
    for ep in endpoints {
        assert!(ep["method"].is_string(), "endpoint missing method: {ep}");
        assert!(ep["path"].is_string(), "endpoint missing path: {ep}");
        assert!(
            ep["summary"].is_string(),
            "endpoint missing summary: {ep}"
        );
    }
}

#[sqlx::test]
async fn dispatch_stub_wildcard_subpath_returns_same_payload(pool: PgPool) {
    let app = boot(pool).await;

    let resp = app
        .client
        .get(app.url("/api/v1/dispatch/board"))
        .send()
        .await
        .expect("send GET /api/v1/dispatch/board");
    assert_eq!(
        resp.status().as_u16(),
        501,
        "dispatch sub-path must also return 501 instead of 404"
    );
    let body: serde_json::Value = resp.json().await.expect("subpath JSON body");
    assert_eq!(body["module"], "dispatch");
    assert_eq!(body["path"], "/api/v1/dispatch/board");
}
