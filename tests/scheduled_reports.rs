//! PMS-478: integration test for scheduled report delivery.
//!
//! Pins three guarantees:
//!   - Creating a schedule via POST returns a row with next_run_at
//!     computed from the cron expression.
//!   - One worker tick on a schedule that is due materialises the
//!     report, enqueues an `email` row into `notifications`, and
//!     advances `last_run_at` / `next_run_at`.
//!   - A schedule with `is_active = false` is NOT picked up by the
//!     tick (no notification, no advance).

mod common;

use mokosh_server::modules::saved_reports::{SavedReportsService, ScheduledReportsWorker};
use mokosh_server::Database;
use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

async fn seed_ticket(pool: &PgPool, company_id: Uuid, admin_id: Uuid, title: &str) -> Uuid {
    let status_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_statuses WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(pool)
            .await
            .expect("status");
    let priority_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_priorities WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(pool)
            .await
            .expect("priority");
    let queue_id: Uuid =
        sqlx::query_scalar("SELECT id FROM ticket_queues WHERE tenant_id = $1 LIMIT 1")
            .bind(common::DEFAULT_TENANT_ID)
            .fetch_one(pool)
            .await
            .expect("queue");
    let id = Uuid::new_v4();
    sqlx::query(
        r#"INSERT INTO tickets
           (id, tenant_id, ticket_number, title, status_id, priority_id,
            queue_id, company_id, created_by_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)"#,
    )
    .bind(id)
    .bind(common::DEFAULT_TENANT_ID)
    .bind(format!("T-{}", &id.to_string()[..8]))
    .bind(title)
    .bind(status_id)
    .bind(priority_id)
    .bind(queue_id)
    .bind(company_id)
    .bind(admin_id)
    .execute(pool)
    .await
    .expect("seed ticket");
    id
}

async fn create_shared_report(app: &common::TestApp, token: &str) -> Uuid {
    let report: Value = app
        .client
        .post(app.url("/api/v1/reports/saved"))
        .bearer_auth(token)
        .json(&serde_json::json!({
            "name": "Weekly tickets",
            "entity_type": "tickets",
            "columns": [
                {"field": "ticket_number"},
                {"field": "title", "header": "Subject"},
            ],
            "is_shared": true,
        }))
        .send()
        .await
        .expect("create report")
        .json()
        .await
        .expect("report body");
    Uuid::parse_str(report["id"].as_str().expect("report id")).expect("uuid parse")
}

fn build_worker(pool: PgPool) -> ScheduledReportsWorker {
    // The integration tests boot a single-pool Database via
    // common::boot; for direct worker driving we wrap the same pool
    // both as app + migrator so the tick can read scheduled_reports
    // and INSERT notifications without RLS friction.
    let db = Database::from_pool(pool);
    let reports = Arc::new(SavedReportsService::new(db.clone()));
    ScheduledReportsWorker::new(db, reports)
}

#[sqlx::test]
async fn schedule_create_returns_next_run_at(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let _ = seed_ticket(&pool, company_id, admin_id, "Alpha").await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let report_id = create_shared_report(&app, &token).await;

    let resp: Value = app
        .client
        .post(app.url(&format!("/api/v1/reports/saved/{report_id}/schedules")))
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
}

#[sqlx::test]
async fn worker_tick_materialises_due_schedule(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let _ = seed_ticket(&pool, company_id, admin_id, "Alpha").await;
    let _ = seed_ticket(&pool, company_id, admin_id, "Bravo").await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let report_id = create_shared_report(&app, &token).await;

    // Create the schedule with a far-future cron, then back-date its
    // next_run_at into the past so the worker picks it up on the
    // next tick. Lets the test drive a deterministic single run
    // without waiting on real wall-clock cron firings.
    let resp: Value = app
        .client
        .post(app.url(&format!("/api/v1/reports/saved/{report_id}/schedules")))
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
        "UPDATE scheduled_reports SET next_run_at = NOW() - INTERVAL '1 hour' WHERE id = $1",
    )
    .bind(schedule_id)
    .execute(&pool)
    .await
    .expect("back-date next_run_at");

    let worker = build_worker(pool.clone());
    let stats = worker.run_tick(10).await.expect("tick");
    assert_eq!(stats.examined, 1, "exactly one due schedule");
    assert_eq!(stats.delivered, 1, "delivery succeeded");

    // The worker should have INSERTed an email notification.
    let pending: (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM notifications \
         WHERE tenant_id = $1 AND channel_type = 'email' AND status = 'pending'",
    )
    .bind(common::DEFAULT_TENANT_ID)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(pending.0, 1, "one email notification enqueued");

    // last_run_at + next_run_at must be advanced; last_error null.
    let row: (
        Option<chrono::DateTime<chrono::Utc>>,
        chrono::DateTime<chrono::Utc>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT last_run_at, next_run_at, last_error FROM scheduled_reports WHERE id = $1",
    )
    .bind(schedule_id)
    .fetch_one(&pool)
    .await
    .expect("row");
    assert!(row.0.is_some(), "last_run_at populated");
    assert!(
        row.1 > chrono::Utc::now(),
        "next_run_at advanced into the future; got {:?}",
        row.1
    );
    assert!(row.2.is_none(), "no last_error on a successful delivery");
}

#[sqlx::test]
async fn worker_tick_skips_disabled_schedule(pool: PgPool) {
    let (admin_id, email, password) = common::seed_admin(&pool).await;
    let company_id = common::seed_company(&pool).await;
    let _ = seed_ticket(&pool, company_id, admin_id, "Alpha").await;

    let app = common::boot(pool.clone()).await;
    let token = common::login(&app, &email, &password).await;
    let report_id = create_shared_report(&app, &token).await;

    let resp: Value = app
        .client
        .post(app.url(&format!("/api/v1/reports/saved/{report_id}/schedules")))
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
        "UPDATE scheduled_reports SET next_run_at = NOW() - INTERVAL '1 hour' WHERE id = $1",
    )
    .bind(schedule_id)
    .execute(&pool)
    .await
    .expect("back-date");

    let worker = build_worker(pool.clone());
    let stats = worker.run_tick(10).await.expect("tick");
    assert_eq!(
        stats.examined, 0,
        "disabled schedule must NOT be picked up by the tick; got {stats:?}"
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
