//! PMS-471 / PMS-453 phase 2b: integration test for scheduled
//! dashboard delivery.
//!
//! Pins three guarantees:
//!   - Creating a schedule via POST returns a row with
//!     `next_run_at` computed from the cron expression.
//!   - One worker tick on a schedule that is due materialises the
//!     dashboard, enqueues an `email` row into `notifications`, and
//!     advances `last_run_at` / `next_run_at`.
//!   - A schedule with `is_active = false` is NOT picked up by the
//!     tick (no notification, no advance).

mod common;

use mokosh_server::modules::dashboards::{DashboardsService, ScheduledDashboardsWorker};
use mokosh_server::Database;
use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

async fn create_dashboard(app: &common::TestApp, token: &str) -> Uuid {
    let resp: Value = app
        .client
        .post(app.url("/api/v1/dashboards"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "name": "Test Dashboard",
            "layout": {
                "widgets": [
                    {"key": "open_tickets"},
                    {"key": "weekly_hours"},
                ],
            },
        }))
        .send()
        .await
        .expect("create dashboard")
        .json()
        .await
        .expect("dashboard body");
    Uuid::parse_str(resp["id"].as_str().expect("id")).expect("uuid")
}

fn build_worker(pool: PgPool) -> ScheduledDashboardsWorker {
    let db = Database::from_pool(pool);
    let dashboards = Arc::new(DashboardsService::new(db.pool().clone()));
    ScheduledDashboardsWorker::new(db, dashboards)
}

#[sqlx::test]
async fn schedule_create_returns_next_run_at(pool: PgPool) {
    let (_aid, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let dashboard_id = create_dashboard(&app, &token).await;

    let resp: Value = app
        .client
        .post(app.url(&format!("/api/v1/dashboards/{dashboard_id}/schedules")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "cron_expr": "0 0 0 * * * *",
        }))
        .send()
        .await
        .expect("schedule POST")
        .json()
        .await
        .expect("schedule body");
    assert_eq!(resp["is_active"], true);
    assert!(
        resp["next_run_at"].as_str().is_some(),
        "next_run_at must be populated; body={resp:?}"
    );
    assert_eq!(
        resp["dashboard_id"].as_str().map(str::to_string),
        Some(dashboard_id.to_string())
    );
}

#[sqlx::test]
async fn worker_tick_materialises_due_schedule(pool: PgPool) {
    let (_aid, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let dashboard_id = create_dashboard(&app, &token).await;

    let resp: Value = app
        .client
        .post(app.url(&format!("/api/v1/dashboards/{dashboard_id}/schedules")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "cron_expr": "0 0 0 * * * *",
        }))
        .send()
        .await
        .expect("schedule POST")
        .json()
        .await
        .expect("schedule body");
    let schedule_id = Uuid::parse_str(resp["id"].as_str().unwrap()).unwrap();
    sqlx::query(
        "UPDATE scheduled_dashboards SET next_run_at = NOW() - INTERVAL '1 hour' WHERE id = $1",
    )
    .bind(schedule_id)
    .execute(&pool)
    .await
    .expect("back-date");

    let worker = build_worker(pool.clone());
    let stats = worker.run_tick(10).await.expect("tick");
    assert_eq!(stats.examined, 1, "one due schedule");
    assert_eq!(stats.delivered, 1, "delivery succeeded");

    // The worker should have INSERTed an email notification carrying
    // the dashboard's widget keys in the body.
    let body: (String,) = sqlx::query_as(
        "SELECT body FROM notifications \
         WHERE tenant_id = $1 AND channel_type = 'email' AND status = 'pending' \
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("body");
    assert!(
        body.0.contains("open_tickets") && body.0.contains("weekly_hours"),
        "snapshot must surface widget keys; body={:?}",
        body.0
    );

    // last_run_at + next_run_at advanced; no last_error.
    let row: (
        Option<chrono::DateTime<chrono::Utc>>,
        chrono::DateTime<chrono::Utc>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT last_run_at, next_run_at, last_error FROM scheduled_dashboards WHERE id = $1",
    )
    .bind(schedule_id)
    .fetch_one(&pool)
    .await
    .expect("row");
    assert!(row.0.is_some(), "last_run_at populated");
    assert!(
        row.1 > chrono::Utc::now(),
        "next_run_at advanced; got {:?}",
        row.1
    );
    assert!(row.2.is_none(), "no last_error on a successful delivery");
}

#[sqlx::test]
async fn worker_tick_skips_disabled_schedule(pool: PgPool) {
    let (_aid, email, password) = common::seed_admin(&pool).await;
    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let dashboard_id = create_dashboard(&app, &token).await;

    let resp: Value = app
        .client
        .post(app.url(&format!("/api/v1/dashboards/{dashboard_id}/schedules")))
        .bearer_auth(&token)
        .json(&serde_json::json!({
            "cron_expr": "0 0 0 * * * *",
            "is_active": false,
        }))
        .send()
        .await
        .expect("schedule POST")
        .json()
        .await
        .expect("schedule body");
    let schedule_id = Uuid::parse_str(resp["id"].as_str().unwrap()).unwrap();
    sqlx::query(
        "UPDATE scheduled_dashboards SET next_run_at = NOW() - INTERVAL '1 hour' WHERE id = $1",
    )
    .bind(schedule_id)
    .execute(&pool)
    .await
    .expect("back-date");

    let worker = build_worker(pool.clone());
    let stats = worker.run_tick(10).await.expect("tick");
    assert_eq!(
        stats.examined, 0,
        "disabled schedule must NOT be picked up; got {stats:?}"
    );

    let pending: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM notifications \
         WHERE tenant_id = $1 AND channel_type = 'email'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(pending.0, 0, "disabled schedule produces no notification");
}
