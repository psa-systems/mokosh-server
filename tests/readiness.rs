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

#[sqlx::test]
async fn ready_sets_cache_control_no_store(pool: PgPool) {
    let app = boot(pool).await;

    let resp = app
        .client
        .get(app.url("/api/v1/ready"))
        .send()
        .await
        .expect("send GET /api/v1/ready");
    let cache_control = resp
        .headers()
        .get(reqwest::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    assert_eq!(
        cache_control.as_deref(),
        Some("no-store"),
        "intermediate caches must not pin the probe response"
    );
}

#[sqlx::test]
async fn ready_returns_503_when_db_pool_closed(pool: PgPool) {
    // Close the pool before booting the app so the SELECT 1 inside
    // /ready fails. boot() stores a clone on TestApp so the listener
    // task keeps the closed pool; the handler gets a real failure
    // from sqlx rather than a connect-time error.
    pool.close().await;
    let app = boot(pool).await;

    let resp = app
        .client
        .get(app.url("/api/v1/ready"))
        .send()
        .await
        .expect("send GET /api/v1/ready");
    assert_eq!(
        resp.status().as_u16(),
        503,
        "ready must 503 when the DB is unreachable"
    );
    let body: serde_json::Value = resp.json().await.expect("ready JSON body");
    assert_eq!(body["status"], "not_ready");
    assert!(
        body["checks"]["db"]
            .as_str()
            .map(|s| s.starts_with("error:"))
            .unwrap_or(false),
        "db check should surface the underlying error: {body}"
    );
}
