//! Integration test for the dispatch board (PMS-58).
//!
//! `/api/v1/dispatch` used to be a self-documenting 501 placeholder
//! behind PMS-58. It is now a real aggregating endpoint that combines
//! appointments (recurring series expanded), weekly availability,
//! approved time off, and current on-call coverage for a date range.
//! This test pins the new contract: the four top-level sections must be
//! present, and the endpoint must no longer return 501.

mod common;

use common::{boot, login, seed_admin};
use sqlx::PgPool;

#[sqlx::test]
async fn dispatch_returns_aggregated_sections(pool: PgPool) {
    let (_admin_id, email, password) = seed_admin(&pool).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    // Bounded window is mandatory: recurring appointments have no
    // natural upper bound, so the handler requires both `from` and `to`.
    let from = "2026-01-01T00:00:00Z";
    let to = "2026-01-31T23:59:59Z";

    let resp = app
        .client
        .get(app.url(&format!("/api/v1/dispatch?from={from}&to={to}")))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send GET /api/v1/dispatch");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "dispatch must return 200, not the old 501 stub"
    );
    let body: serde_json::Value = resp.json().await.expect("dispatch JSON body");

    // The four aggregated sections must all be present and array-typed,
    // even when empty (a freshly seeded tenant has no scheduling data).
    for section in ["appointments", "availability", "time_off", "on_call"] {
        assert!(
            body[section].is_array(),
            "dispatch response must carry an array `{section}`, got {body}"
        );
    }
}

#[sqlx::test]
async fn dispatch_requires_a_bounded_range(pool: PgPool) {
    let (_admin_id, email, password) = seed_admin(&pool).await;
    let app = boot(pool).await;
    let token = login(&app, &email, &password).await;

    // Missing `to` => 400. Recurrence expansion needs an upper bound.
    let resp = app
        .client
        .get(app.url("/api/v1/dispatch?from=2026-01-01T00:00:00Z"))
        .bearer_auth(&token)
        .send()
        .await
        .expect("send GET /api/v1/dispatch without `to`");
    assert_eq!(
        resp.status().as_u16(),
        400,
        "dispatch without a bounded range must 400"
    );
}
