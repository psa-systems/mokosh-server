//! Integration test for the readiness probe (PMS-130).
//!
//! `/api/v1/ready` runs a live DB ping plus a best-effort Infisical
//! probe gated on `INFISICAL_BASE_URL`. The integration harness
//! provisions a fresh per-test database via `#[sqlx::test]` and does
//! not configure Infisical, so the expected payload is:
//!   `{"status":"ready","checks":{"db":"ok","infisical":"skipped"}}`
//!
//! Every /ready case calls `unconfigure_infisical()` first so that
//! premise holds no matter what the surrounding shell exports.

mod common;

use common::boot;
use sqlx::PgPool;

/// Pin the harness premise: Infisical is unconfigured. `just
/// test-integration` runs inside the dev compose `server` container,
/// which always exports `INFISICAL_BASE_URL` (compose.dev.yml) while
/// the `infisical` service itself is an opt-in profile, so the probe
/// hit an absent host and 503'd after its 1s timeout (PMS-685). The
/// handler caches the env read in a `OnceLock` on the first /ready
/// request, so clearing it before the first boot is enough; `Once`
/// keeps the mutation to a single call for the whole binary.
fn unconfigure_infisical() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| std::env::remove_var("INFISICAL_BASE_URL"));
}

#[sqlx::test]
async fn ready_returns_ok_when_db_reachable_and_infisical_unconfigured(pool: PgPool) {
    unconfigure_infisical();
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
    unconfigure_infisical();
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
    unconfigure_infisical();
    // Close the pool before booting the app so the SELECT 1 inside
    // /ready fails. boot() stores a clone on TestApp so the listener
    // task keeps the closed pool; the handler gets a real failure
    // from sqlx rather than a connect-time error.
    pool.close().await;
    let app = boot(pool).await;

    // `pool.close()` resolves once the close is requested, but on a
    // loaded CI runner the pooled connections may not have fully torn
    // down by the time `boot()` returns. Yield once so the runtime can
    // run the close-out tasks before we probe, making the subsequent
    // `SELECT 1` deterministically hit a closed pool.
    tokio::task::yield_now().await;

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
