//! Integration test for the readiness probe (PMS-130).
//!
//! `/api/v1/ready` runs a live DB ping plus a best-effort Infisical
//! probe gated on `INFISICAL_BASE_URL`. The integration harness
//! provisions a fresh per-test database via `#[sqlx::test]` and does
//! not configure Infisical, so the expected payload is:
//!   `{"status":"ready","checks":{"db":"ok","infisical":"skipped"}}`

mod common;

use common::boot;
use sqlx::PgPool;

#[sqlx::test]
async fn ready_returns_ok_when_db_reachable_and_infisical_unconfigured(pool: PgPool) {
    let app = boot(pool).await;

    let resp = app
        .client
        .get(app.url("/api/v1/ready"))
        .send()
        .await
        .expect("send GET /api/v1/ready");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "ready should 200 on healthy DB"
    );
    let body: serde_json::Value = resp.json().await.expect("ready JSON body");

    assert_eq!(body["status"], "ready");
    assert_eq!(body["checks"]["db"], "ok");
    // Infisical not configured in the test harness; probe is skipped.
    assert_eq!(body["checks"]["infisical"], "skipped");
}

#[sqlx::test]
async fn health_remains_plain_text_ok(pool: PgPool) {
    let app = boot(pool).await;

    let resp = app
        .client
        .get(app.url("/api/v1/health"))
        .send()
        .await
        .expect("send GET /api/v1/health");
    assert_eq!(resp.status().as_u16(), 200);
    let body = resp.text().await.expect("health text body");
    assert_eq!(body, "OK", "health stays the cheap liveness probe");
}
